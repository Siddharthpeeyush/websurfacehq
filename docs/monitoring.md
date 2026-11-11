# WebSurfaceHQ — Monitoring

**Status:** Phase 0 (scaffold / docs only). No service exists to monitor yet. This plan
is implemented as services land: UptimeRobot + Sentry in Week 1, alert rules wired
before the first live scan in Week 2, all runbooks written before launch in Week 4.

## 1. Uptime checks (UptimeRobot, free tier)

| Check | URL / target | Interval | Notes |
|---|---|---|---|
| Homepage | `https://websurfacehq.com/` (once registered) | 5 min | Also the public "is it up" signal |
| Login page | `https://websurfacehq.com/login` | 5 min | Catches frontend deploy breakage that leaves the homepage fine |
| API health | `https://api.websurfacehq.com/health` (or Render URL until the domain lands) | 5 min | Full component check (DB + Redis + Celery) from Week 1; Phase 0 `/health` is liveness-only — see runbook |
| API live | `https://api.websurfacehq.com/live` | 1 min | Lightweight, for load balancers |
| Core scan flow | Synthetic: create a scan on the owner's own domain (staging, weekly) | Weekly | Not an UptimeRobot HTTP check — a scheduled staging run; see §4 |
| Render keep-alive | `GET /health` every 14 min | 14 min | Render free sleeps after 15 min idle; this ping is load-bearing, not cosmetic |

## 2. Technical metrics

| Metric | Source | Why it matters |
|---|---|---|
| Error rate (5xx / total requests) | API logs → Sentry / Render metrics | Alert > 5% (§3) |
| p50 / p95 / p99 API latency | API middleware (request timing logs) | Alert p95 > 2 s (§3) |
| DB connections in use | Supabase dashboard / Postgres `pg_stat_activity` | Free-tier connection exhaustion kills the API before CPU does |
| Queue depth per queue (`recon` / `crawl` / `vuln`) | Celery / Redis `LLEN` | Alert > 50 (§3); see `docs/runbooks/queue-depth-high.md` |
| Dead-letter queue depth (`dlq:scan:{id}`) | Redis | Any DLQ entry is a failed scan — investigate, do not ignore |
| Worker memory (Nuclei stage) | Render metrics | 512 MB free tier; Nuclei OOM is the known failure mode |
| Scan stage durations (p50/p95/p99 per stage) | `scan_jobs` rows | Finds the slow stage before users complain |
| LLM calls per scan / per day | Triage service logs | Free-tier rate limits; max 50/scan cap enforcement |
| Redis commands per day | Upstash dashboard | First bottleneck at 10× (10k/day free tier) |
| Storage used (DB + buckets) | Supabase dashboard | 500 MB DB / 1 GB storage free caps; see system-design §9 |

## 3. Business metrics

| Metric | Source | Why it matters |
|---|---|---|
| Signups / day | Supabase Auth / `audit_logs` | Launch traction |
| Targets verified / day | `targets` table | Activation: signup → verified domain is the funnel's narrowest step |
| Scans started / completed / failed per day | `scans` table | Failed-scan rate is a product-health metric, not just an ops one |
| Median scan time (quick / standard / deep) | `scans.started_at` → `finished_at` | Promise is quick < 5 min, standard < 20 min |
| False-positive rate after triage | Finding feedback (`false_positive` marks) | Target < 10%; the #1 trust metric — if it rises, triage is regressing |
| Reports downloaded | `audit_logs` / Storage signed-URL issuance | The deliverable actually being used |
| Paying users / MRR (when billing lands) | `subscriptions` + gateway | Break-even is ~10 Pro users at Rs 1,499 |

## 4. Alert rules

Every alert has a runbook (see `docs/runbooks/`). An alert without a runbook is not
shipped. Alerts go to the owner (Siddharth Peeyush) — single owner for all alerts in MVP.

| Alert | Threshold | Duration | Severity | Owner | Runbook |
|---|---|---|---|---|---|
| API error rate high | 5xx > 5% of requests | 5 min | SEV2 | Siddharth | `docs/runbooks/health-check-failing.md` (extend: check Sentry) |
| API p95 latency high | p95 > 2 s | 10 min | SEV2 | Siddharth | Health-check runbook + slow-query check |
| Health check failing | `/health` non-200 or any component `down` | 2 consecutive checks | SEV1 | Siddharth | `docs/runbooks/health-check-failing.md` |
| Queue depth high | Any queue depth > 50 | 10 min | SEV2 | Siddharth | `docs/runbooks/queue-depth-high.md` |
| Dead-letter entries | Any new DLQ entry | Immediate | SEV2 | Siddharth | Queue runbook (DLQ section) |
| Scan failure rate high | > 20% of scans failed in 1 h | 1 h | SEV2 | Siddharth | Queue runbook + Sentry scan errors |
| Uptime: homepage / login down | Any UptimeRobot check down | 2 consecutive checks | SEV1 | Siddharth | Health-check runbook |
| Redis commands near limit | > 8,000 commands/day (80% of free tier) | Daily | SEV3 | Siddharth | Plan the $10/mo Redis upgrade; do not wait for the hard cap |
| Supabase DB near limit | > 400 MB (80% of 500 MB) | Daily | SEV3 | Siddharth | Storage pruning / Supabase Pro ($25/mo) |
| LLM rate limit hit | Any 429 from Gemini/Groq | Immediate | SEV3 | Siddharth | Heuristic-only fallback engages; check triage accuracy |
| Abuse report received | Any | Immediate | SEV1 | Siddharth | Incident plan: acknowledge 24 h, investigate 72 h, suspend same day if credible |

**Severity definitions:** SEV1 — tenant data exposed, unauthorized scans, or the product
is down; SEV2 — scans failing platform-wide or a core flow degraded; SEV3 — single-user
or cosmetic issue, or a capacity warning.

## 5. Sentry + UptimeRobot plan

- **Sentry (free tier, 5k events/month):** frontend (Next.js) + backend (FastAPI).
  Every event carries `user_id`, `tenant_id` (= `user_id`), and `request_id`. Source maps
  uploaded on deploy but **never served publicly**. Separate staging and production
  projects (separate DSNs). A staging-only test route that throws an error verifies
  delivery end to end before launch.
- **UptimeRobot (free):** the checks in §1. Status page: a simple public status page
  in Week 4 (Month 2: full status page).
- **Logs:** structured JSON, levels, `request_id` on every line and in the
  `X-Request-Id` response header, `user_id` where available, automatic redaction of
  password/token/secret fields. Empty catch blocks, ignored promise rejections, and
  errors caught but not logged or re-thrown are bugs — users see a friendly message,
  full detail goes to Sentry.
- **Billing alerts:** set on every provider (Vercel, Render, Supabase, Upstash, Sentry)
  before launch — a surprise bill is an ops failure, not bad luck.
