# ADR-0004: Celery + Upstash Redis queues (three routed queues)

**Status:** Accepted (11 Nov 2026, Phase 0)
**Deciders:** Owner + build agent. Locked in `ENGINEERING-PLAN.md` §0.

## Context

A scan is a 13-stage pipeline (verify → DNS → subdomains → ports → probe → fingerprint
→ crawl → JS secrets → Nuclei → triage → enrichment → report → notify) that takes up to
30 minutes for a deep scan. None of it can run inside an HTTP request: Render free
services sleep, requests time out, and a Nuclei run would block the API for every other
user. The work must be asynchronous, resumable after a worker restart, retryable with
backoff, and rate-limited per stage — and the rate-limit store must survive redeploys
(so it must be shared, not in-process memory).

## Decision

- **Broker + result backend + rate-limit store:** Upstash Redis (free tier, 10k
  commands/day). One shared store for queues, locks, and rate limits.
- **Task framework:** Celery (Python-native), with **three routed queues — never one big
  queue**:

| Queue | Work | Concurrency | Timeout | Rate limit |
|---|---|---|---|---|
| `recon` | DNS, subdomains, httpx probe, TLS | 10 workers | 2 s/host | 50 tasks/min |
| `crawl` | Katana crawl, JS download, secret scan | 3 workers | 10 min/scan | 5 tasks/min per domain |
| `vuln` | Nuclei, dalfox, nikto | 2 workers | 30 min/scan | 10 tasks/min global, 1 per target |

- **Idempotency:** `task_id = scan_id:stage:target_hash`. Re-running a stage returns the
  stored result; findings are never duplicated.
- **Retries:** exponential backoff (60s / 300s / 900s), max 3 attempts, then dead-letter
  queue `dlq:scan:{id}` and the scan is marked `failed` with a human-readable error.
- **Workers run on a separate Render free service from the API**, so a sleeping API does
  not kill a running scan.
- **Nightly jobs** (Celery beat / cron): KEV JSON + EPSS CSV download, Nuclei template
  update, 90-day evidence auto-delete.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| One big queue for all stages | A slow Nuclei job would starve recon; a burst of recon tasks would delay vuln scans. Separate queues with separate concurrency isolate the stages — this is the blueprint's explicit rule (§1.5) |
| In-process background tasks (FastAPI `BackgroundTasks`) | Dies with the process; Render free sleeps after 15 min idle, killing mid-scan work; no retries, no routing, no rate limits, no dead-letter queue |
| AWS SQS / Google Cloud Tasks | Paid, and Celery + Redis is $0 on the free tier; SQS adds a vendor + IAM surface for no MVP benefit. Revisit only if Redis becomes the bottleneck at scale (it is the expected first bottleneck — see system-design §9) |
| Temporal / Prefect / Airflow | Heavyweight orchestration for a 13-stage linear chain; Celery chains + chords already express it, and the team knows Celery. Airflow's scheduler + UI is overkill for a solo founder |
| BullMQ / Node-based queue | Splits the queue into the Node world while the workers are Python; Celery is Python-native and the workers are Python |

## Consequences

- **Positive:** resumable scans (each stage is idempotent, so a scan resumes from the
  last completed stage after a worker sleep/restart); per-stage rate limits protect both
  targets (politeness) and the platform (abuse); dead-letter queue makes failures visible
  instead of silent.
- **Negative:** Upstash free tier (10k commands/day) is the **first bottleneck at 10×**
  — at ~53 scans/day the estimate is ~10,600 commands/day, already marginal. The first
  paid cost is Redis at $10/mo (~100 scans/day), planned and budgeted.
- **Neutral / to watch:** Render free worker memory is 512 MB — Nuclei with the curated
  200 templates fits; the full 8,000-template set does not. Stream JSONL output; never
  load all findings into memory. If Nuclei OOMs, the fix is a paid Render worker
  ($7/mo), not a queue re-architecture.
