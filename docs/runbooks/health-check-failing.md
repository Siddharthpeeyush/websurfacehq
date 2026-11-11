# Runbook — Health Check Failing

> **Phase 0 banner (review fix):** `/health` is currently LIVENESS-ONLY — it
> returns `200 {"status": "ok"}` and checks no component. The per-component
> body (`database` / `redis` / `celery` fields) lands in Week 1 when Supabase
> and Upstash are wired in. Until then: if `/health` returns non-200, the API
> process itself is down (see "Impact check" below); if `/health` is 200 but
> you suspect a dependency, check the process logs — there is no component
> field to read yet. The steps below that read component fields apply only
> after the Week 1 health shape lands.

**Alert:** `/health` returns non-200, or returns 200 with any component `down`, for
2 consecutive UptimeRobot checks.
**Severity:** SEV1. **Owner:** Siddharth Peeyush.

## Meaning

`/health` checks three components with timeouts and reports each one: Postgres
(Supabase), Redis (Upstash), and Celery (worker connectivity). A failing check means
one of those is unreachable, or the API process itself is down. `/live` is the
lightweight endpoint (process alive, no dependency checks) — if `/live` is up but
`/health` is down, the API process is fine and a dependency is the problem.

## Impact check (do first, ~2 minutes)

1. Open `/live`: up or down?
   - `/live` down → the API service itself is down (Render). Skip to "API down".
   - `/live` up, `/health` down → read the `/health` body: which component is `down`?
2. Check UptimeRobot history: did all checks fail at once (deploy? provider outage?)
   or one at a time (single dependency degrading)?
3. Check Sentry for new errors in the same window — a deploy that broke DB access
   shows up as both.

## Likely causes

| Symptom | Likely cause |
|---|---|
| `/live` down | Render service crashed / sleeping and keep-alive missed / bad deploy / out of memory |
| `database: down` | Supabase outage, wrong `SUPABASE_URL` / key, DB connection exhaustion, network block |
| `redis: down` | Upstash outage, wrong `UPSTASH_REDIS_REST_URL` / token, free-tier command cap hit |
| `celery: down` | Worker service down / sleeping, broker URL wrong, worker crashed (OOM on Nuclei) |
| All components down at once | Bad deploy (env vars), Render region issue, or a network change |

## Step-by-step fixes

### API down (`/live` down)
1. Render dashboard → API service → check status and recent logs. Look for a crash loop
   (repeated restarts) vs a sleeping service (no logs, "service suspended").
2. Sleeping service: hit the service URL manually once; confirm the UptimeRobot 14-min
   keep-alive ping is still configured and has not been paused.
3. Crash loop: read the last log lines — a missing required env var makes the app
   refuse to start with a clear message (by design). Fix the env var in Render, redeploy.
4. Out of memory: check Render metrics; if the API (not the worker) is OOMing, look for
   a request loading a huge payload into memory (report generation streaming a full
   scan into RAM is the usual suspect).
5. If the last deploy caused it: roll back per `docs/runbooks/rollback.md`.

### `database: down`
1. Supabase dashboard → project health: is Supabase itself up? Check Supabase status.
2. Verify env vars in Render (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`,
   `SUPABASE_ANON_KEY`) — a rotated key that was not updated in Render is the most
   common cause. Never paste a key into chat; update it in the Render dashboard.
3. Check connection count in Supabase: free-tier exhaustion looks like intermittent
   `down` (some checks pass, some fail). If exhausted, restart the API service to drop
   idle connections and reduce pool size in config.
4. If Supabase is down platform-wide: wait for their status page; do not redeploy
   (redeploying will not fix a provider outage and may lose the last good deploy).

### `redis: down`
1. Upstash dashboard → database status + command usage. If usage is at/over 10k
   commands/day, the free tier is capped — that is the expected first bottleneck
   (see `docs/system-design.md` §9). Upgrade to paid Redis ($10/mo) — do not try to
   "fix" it by dropping rate limits.
2. Verify `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` in Render.
3. If Upstash is up and credentials are right, restart the API service once (stale
   connection pool) and re-check.

### `celery: down`
1. Render dashboard → worker service → status + logs. A worker that OOMed on Nuclei
   (512 MB free tier) restarts and shows `celery: down` until it is back.
2. Check the DLQ (`dlq:scan:{id}` in Redis): tasks that failed 3× sit here. Do not
   purge the DLQ — each entry is a failed scan to investigate.
3. If the worker is up but Celery reports down, verify `CELERY_BROKER_URL` matches the
   Upstash URL the API uses (a mismatch means the API is pinging a queue the worker
   never reads).
4. See also `docs/runbooks/queue-depth-high.md`.

## Escalation

- If a provider (Supabase / Upstash / Render) is down platform-wide: post a status note,
  do not redeploy, and wait for the provider. Check their status pages, not just ours.
- If health is still failing after 15 minutes of fixes: SEV1 — pause new scan creation
  (maintenance message on the dashboard), preserve logs, and investigate before
  re-deploying.
- Post-incident: postmortem within 7 days with one preventive fix.
