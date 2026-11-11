# Runbook — Queue Depth High

**Alert:** any Celery queue depth > 50 for 10 minutes, or any new dead-letter queue
(`dlq:scan:{id}`) entry.
**Severity:** SEV2 (SEV1 if scans are failing platform-wide). **Owner:** Siddharth Peeyush.

## Meaning

Queue depth is the number of tasks waiting in Redis for a worker. A rising depth means
tasks are arriving faster than workers finish them. Per queue:

| Queue | Normal depth | What a high depth means |
|---|---|---|
| `recon` | Near 0 (fast, 2 s/host, 10 workers) | DNS/subdomain/probe stage stuck or flooded |
| `crawl` | Low (3 workers, 10 min/scan) | Katana crawling slowly or a target hanging the crawler |
| `vuln` | Low but bursty (2 workers, 30 min/scan) | Nuclei runs are the slowest stage — this queue grows first under load |

A high depth alone is not an outage — scans still complete, just slowly. It becomes an
outage when tasks start timing out, retrying, and landing in the DLQ.

## Impact check (do first, ~2 minutes)

1. Which queue is deep? Check each: `recon`, `crawl`, `vuln`. (Redis `LLEN` per queue
   or the Celery Flower/inspect output.)
2. Are scans completing at all? Check the newest `scans` rows: any `done` in the last
   10 minutes? Any `failed`?
3. Check the DLQ: any `dlq:scan:{id}` entries? Each one is a scan that failed 3×.
4. Check worker logs: are workers alive and picking up tasks, or crashed / OOMed /
   sleeping (Render free tier)?

## Likely causes

| Cause | Signal |
|---|---|
| Worker service asleep or crashed (Render free sleeps after 15 min idle) | Depth rises on all queues at once; worker logs stop; `/health` shows `celery: down` |
| One slow target blocking a queue | Depth rises on one queue only; `scan_jobs` shows one scan stuck in one stage for a long time |
| Nuclei OOM (512 MB worker) | Worker restarts in logs; `vuln` depth rises; tasks retry and fail again |
| Traffic spike (launch / newsletter / abuse) | Depth rises on all queues; scan creation rate spiked in `audit_logs` |
| Upstream slowness (target rate-limiting us, LLM 429) | Stage durations spike in `scan_jobs`; triage stage stuck waiting on Gemini/Groq |
| Poison task (a task that crashes the worker every time) | Same `scan_id:stage` retrying, DLQ growing, worker restarts correlate with that task |

## Step-by-step fixes

1. **Worker down/asleep:** Render dashboard → worker service → restart / wake it.
   Confirm the UptimeRobot 14-min keep-alive is configured for the *worker* too, or
   that the API keep-alive is enough to keep the shared host awake (it is not — the
   worker is a separate service; it needs its own wake path or it sleeps mid-scan).
   Idempotent tasks resume from the last completed stage — do not purge queues.
2. **One slow target:** find the stuck `scan_id` in `scan_jobs` (stage started long ago,
   no finish). Cancel that scan (`POST /scans/{id}/cancel`) — cancelling one stuck scan
   unblocks the queue for everyone else. Check the target: is it rate-limiting us
   (429s in logs)? If so, the politeness backoff (60 s, halve concurrency) should have
   engaged — if it did not, that is a bug to file.
3. **Nuclei OOM:** reduce the template set for the affected scan (curated 200 is the
   cap — confirm no run is using the full 8,000), confirm JSONL streaming (never load
   all findings into memory). If OOM persists on the curated set, the fix is a paid
   Render worker ($7/mo), not a code change.
4. **Traffic spike:** check whether it is legitimate (launch) or abuse (one user / one
   IP creating many scans). Abuse → suspend the account per the abuse workflow and
   preserve audit logs. Legitimate → let the queues drain; do not raise concurrency
   past the per-target politeness caps (5 req/s, 2 concurrent) to "catch up" — that
   hammers targets and gets the scanner blocked.
5. **Upstream slowness (LLM 429):** triage falls back to heuristic-only (by design).
   Confirm the fallback engaged (findings have verdicts from heuristics, not errors).
   Do not retry LLM calls aggressively — that worsens the rate limit.
6. **Poison task:** identify the `scan_id:stage:target_hash` from the DLQ, mark that
   scan `failed` with a human-readable error, and file a bug with the task id and the
   worker log lines. Do **not** requeue a poison task — it will crash the worker again.
7. **Never purge a queue to "fix" depth.** Purging deletes users' scans. Drain, cancel
   the stuck ones, fix the worker — in that order.

## Escalation

- Depth still rising after 30 minutes, or scans failing platform-wide (> 20% failed in
  1 h): SEV2 → SEV1. Pause new scan creation, post a status note, investigate.
- If the cause is abuse (unauthorized scanning attempts, quota evasion): follow the
  incident plan — acknowledge 24 h, investigate 72 h, suspend same day if credible.
- Post-incident: postmortem within 7 days. If the fix is "paid Redis" or "paid Render
  worker", that is a capacity decision — record it in `docs/decisions/` and tell the
  owner the cost before spending it.
