# WebSurfaceHQ — Architecture

**Status:** Phase 0 (scaffold / docs only). This describes the target architecture for
Weeks 1–4. Nothing below is deployed yet; there is no Supabase project, no Render
service, and no code outside the scaffold owned by other agents.

## 1. Component diagram (ASCII)

```
                    ┌─────────────────────────────────────────────────┐
                    │  User (browser, 375px mobile + desktop)        │
                    └──────────────────────┬──────────────────────────┘
                                           │ HTTPS
                                           ▼
                    ┌─────────────────────────────────────────────────┐
                    │  Vercel — apps/web                               │
                    │  Next.js 14 (App Router) + TypeScript + Tailwind│
                    │  Dashboard · Scan wizard · Findings · Reports    │
                    │  Polls GET /scans/{id} every 5s (MVP)           │
                    └──────────────────────┬──────────────────────────┘
                                           │ HTTPS, Supabase JWT
                                           ▼
                    ┌─────────────────────────────────────────────────┐
                    │  Render — apps/api (FastAPI, Python)             │
                    │  main.py · core/ (config, security, rate_limit, │
                    │  logging) · auth/ (JWT verify, can())            │
                    │  targets/ · scans/ · findings/ · reports/        │
                    │  services/ (orchestrator, triage, enrichment)    │
                    │  Business logic in /services, NEVER in handlers │
                    └──────┬──────────────────────┬───────────────────┘
                           │ SQL (RLS)            │ enqueue / locks /
                           ▼                      │ rate limits
              ┌────────────────────────┐          ▼
              │ Supabase Postgres      │   ┌────────────────────────┐
              │ targets · scans ·      │   │ Upstash Redis          │
              │ assets · findings ·    │   │ broker + result backend│
              │ scan_jobs · audit_logs │   │ + rate-limit store     │
              │ subscriptions · teams  │   └──────────┬─────────────┘
              │ api_keys · notific.    │              │ Celery
              │ + Supabase Auth        │              ▼
              │ + Supabase Storage     │   ┌────────────────────────┐
              │   (private buckets,    │   │ Render — Celery workers│
              │   tenant-scoped paths) │   │ recon / crawl / vuln   │
              └────────────────────────┘   │ queues (3, routed)     │
                           ▲               │  └─► Go scanner-agent  │
                           │ signed URLs   │       binary (exec:     │
                           │ (short-lived) │       naabu, httpx,     │
                           └───────────────┤       katana, nuclei)   │
                                           └──────┬─────────────────┘
                                                  │ outbound, ≤5 req/s
                                                  │ per target, SSRF
                                                  │ blocklist enforced
                                                  ▼
                                      ┌─────────────────────────────┐
                                      │ Target domain (verified     │
                                      │ owner only) + public feeds: │
                                      │ NVD · CISA KEV · EPSS ·     │
                                      │ crt.sh · Gemini/Groq (LLM)  │
                                      └─────────────────────────────┘
```

Data flow for one scan: browser → API (auth + `can()` + quota check) → scan row created
→ Celery chain enqueued → workers run stages via the Go scanner-agent → results written
to Postgres + evidence to Storage → triage + enrichment → report generated → user notified.
The API never runs a scan itself; the worker never serves HTTP.

## 2. Stack choice per layer (with one rejected alternative each)

| Layer | Chosen | Why | Rejected alternative + why |
|---|---|---|---|
| Frontend | Next.js 14 (App Router) + TypeScript + Tailwind on Vercel Hobby ($0) | App Router + RSC, Vercel free tier, TS strictness for a security product, Tailwind design tokens | **Plain React SPA (Vite)**: no SSR/SEO for marketing + sample-report pages, no built-in routing conventions; Next.js is the playbook-friendly default and Vercel hosting is free |
| API | FastAPI (Python) on Render Free | Best Python ecosystem for security tooling, Pydantic validation at the boundary, async, OpenAPI docs free | **Express/Node**: weaker security-tooling ecosystem (no Nuclei/sqlmap-adjacent libraries, no Celery equivalent as mature); Python owns the orchestration layer |
| Hot path / scanning | Go `scanner-agent` binary (wraps naabu/httpx/katana/nuclei via exec) | Go concurrency for port scanning/crawling; ProjectDiscovery tools are Go-native and pipe JSONL to each other | **Python-only scanning**: Python concurrency + subprocess orchestration is slower and more fragile for 10k-host probes; Go is the right tool for the hot path. (NOT faked in Python — see packages/scanner-agent/README.md) |
| Database / Auth / Storage | Supabase (Postgres + Auth + Storage), RLS on all tables | One free tier covers DB + proven auth + private storage; RLS enforces tenancy in the database, not just app code | **Hand-rolled Postgres + custom JWT auth**: hand-rolled auth is explicitly forbidden by the playbook and the plan; Supabase Auth is the proven provider |
| Queue | Celery + Upstash Redis, 3 routed queues (recon / crawl / vuln) | Python-native, retries, routing, rate limits, dead-letter handling; Redis survives redeploys as the rate-limit store | **One big queue / in-process background tasks**: one slow Nuclei job would starve recon; separate queues with separate concurrency (10 / 3 / 2 workers) isolate the stages. Also rejected: **SQS** — paid, and Celery+Redis is $0 |
| AI triage | Gemini 2.5 Flash (primary) / Groq Llama-3.1 (fallback), free tier | $0, JSON-only verdicts, cached by finding hash, Medium+ only, max 50 calls/scan | **Self-hosted LLM**: no free GPU on Render free; cost and ops burden kill the $0 MVP. **LLM for every finding**: Low/Info findings skip the LLM entirely — cost control |
| Enrichment | NVD API 2.0 + CISA KEV JSON + FIRST EPSS CSV (nightly download, free) | Public data, no per-finding API call at scan time; KEV-first sorting is the product's ranking edge | **Per-finding live NVD lookup at scan time**: rate-limited (5 req/30s without key) and slow; nightly bulk download is free and fast |
| Reports | HTML + PDF via Playwright PDF (or WeasyPrint) | Reuses the frontend's rendering; PDF is the deliverable agencies attach to client work | **Hand-built PDF library (ReportLab)**: double maintenance (HTML report + PDF layout diverge); render HTML once, print to PDF |
| Error tracking | Sentry free tier (frontend + backend) | 5k events/month free, user/tenant/request ids attached | **Logging-only errors**: no alerting, no grouping, no source context; Sentry is the playbook default |
| Uptime | UptimeRobot (free) pinging `/health` every 14 min | Also doubles as the Render free-tier keep-alive (service sleeps after 15 min idle) | **No keep-alive / cron-only**: a sleeping API kills the first user request of the day; the 14-min ping is load-bearing, not cosmetic |

## 3. Folder structure (monorepo)

```
websurfacehq/
├── README.md                    # product, stack, setup, Phase 0 exit gate
├── AGENTS.md                    # repo memory: product, stack, rules, decisions, blockers
├── ENGINEERING-PLAN.md          # master plan (phases, gates, security rules)
├── .env.example                 # every variable, documented, placeholder values only
├── .gitignore
├── docs/
│   ├── system-design.md         # this design's companion: problem, roles, flows, load math
│   ├── architecture.md          # this file
│   ├── decisions/adr-0001…0004  # architecture decision records
│   ├── permissions.md           # roles + matrix + can() contract (Phase 0: contract only)
│   ├── threat-model.md          # STRIDE + OWASP Top 10 per entry point
│   ├── api-conventions.md       # naming, errors, pagination, money, status codes
│   ├── testing.md               # test strategy
│   ├── monitoring.md            # uptime, metrics, alerts
│   ├── caching.md               # cache candidates; never tenant data at a shared layer
│   └── runbooks/                # rollback, health-check-failing, queue-depth-high
├── apps/
│   ├── web/                     # Next.js 14 + TS + Tailwind  (exists in Phase 0)
│   └── api/                     # FastAPI + Celery            (scaffold exists in Phase 0)
│       ├── app/
│       │   ├── main.py          # health, middleware
│       │   ├── core/            # config, security, rate_limit, logging
│       │   ├── auth/            # Supabase JWT verify, can()              (Week 1)
│       │   ├── targets/ scans/ findings/ reports/                      (Week 1)
│       │   ├── workers/         # Celery app, task routing               (Week 1)
│       │   └── services/        # orchestrator, triage, enrichment (logic lives here) (Week 1)
│       └── tests/               # pytest: unit + integration vs real DB  (unit exists in Phase 0; integration Week 1)
├── packages/
│   └── scanner-agent/           # Go binary (README placeholder only in Phase 0)
├── supabase/
│   └── migrations/              # version-controlled migrations ONLY (none yet in Phase 0)
└── .github/                     # CI (install → lint → typecheck → test → build)
                                 # (OWNED BY ANOTHER AGENT — do not touch)
```

Rules: business logic in `apps/api/app/services/` or `packages/` domain code, never in
route handlers and never in UI components. No `apps/web` or `apps/api` code is written by
the docs agent; the scaffold for those directories is owned by other agents.

## 4. Where background jobs run

- **Celery workers on a separate Render free service from the API**, so a sleeping API
  does not kill a running scan (and vice versa). Two services, one codebase, different
  entrypoints (`uvicorn` vs `celery worker`).
- **Three routed queues** (never one big queue):

| Queue | Work | Concurrency | Timeout | Rate limit |
|---|---|---|---|---|
| `recon` | DNS, subdomains, httpx probe, TLS | 10 workers | 2 s/host | 50 tasks/min |
| `crawl` | Katana crawl, JS download, secret scan | 3 workers | 10 min/scan | 5 tasks/min per domain |
| `vuln` | Nuclei, dalfox, nikto | 2 workers | 30 min/scan | 10 tasks/min global, 1 per target |

- **Task chain per scan** (Celery chain + chord): `verify_target → dns_enum →
  subdomain_enum → port_scan → http_probe → tech_fingerprint → crawl → js_secret_scan →
  nuclei_scan → ai_triage → enrichment → generate_report → notify_user`.
- **Idempotency:** `task_id = scan_id:stage:target_hash`; re-running a stage returns the
  stored result, never duplicates findings. Retries: exponential backoff 60s / 300s /
  900s, max 3 attempts, then dead-letter queue `dlq:scan:{id}` + scan marked `failed`.
- **Nightly jobs (Celery beat / cron):** KEV JSON + EPSS CSV download, Nuclei template
  update, 90-day evidence auto-delete, billing reconciliation (when billing lands).
- **Render free-tier reality:** 512 MB worker memory — Nuclei with the curated 200
  templates fits; the full 8,000-template set does not. Stream JSONL; never load all
  findings into memory.

## 5. Third-party costs

| Service | Launch ($0 MVP) | At 10× users (~500 scans/day) | Notes |
|---|---|---|---|
| Vercel (frontend) | $0 Hobby | $20/mo Pro | 100 GB bandwidth free; breaks on bandwidth first |
| Render API + worker | $0 Free (×2 services) | $7/mo per service = $14/mo | Sleeps after 15 min idle; UptimeRobot ping every 14 min |
| Supabase | $0 Free | $25/mo Pro | 500 MB DB / 1 GB storage free; storage pruning needed before this (see system-design §9) |
| Upstash Redis | $0 Free | $10/mo | 10k cmds/day free — **first thing to break** (see below) |
| Gemini / Groq | $0 Free tier | Pay-as-you-go | Max 50 LLM calls/scan, cached by finding hash |
| Sentry | $0 Free | $26/mo | 5k events/month free |
| NVD / KEV / EPSS / crt.sh | $0 | $0 | Public data; NVD free key raises rate limit |
| **Total** | **$0/mo** | **~$95/mo** | Blueprint's "~$42/mo at 100 scans/day" covers Redis + Render only; Supabase Pro + Vercel Pro + Sentry push it higher at 10× |

At 10×, the most expensive component is Supabase Pro ($25/mo), then Vercel Pro ($20/mo).
The first paid cost is still Redis ($10/mo) at ~100 scans/day, then Render ($7/mo).

## 6. Three riskiest decisions

1. **Modular monolith + Render free tier for a scanner workload.** A scanner is
   bursty and memory-hungry (Nuclei) while Render free gives 512 MB and sleeps after
   15 minutes idle. Mitigation: separate worker service, UptimeRobot keep-alive,
   idempotent resumable stages, curated 200 templates, JSONL streaming. If scans
   routinely OOM or time out, the fix is a paid Render worker ($7/mo) — the cheapest
   paid step — not a re-architecture.
2. **AI triage as the headline differentiator.** If triage is wrong, the product cries
   wolf and trust dies (false positives are the #1 churn risk in the blueprint).
   Mitigation: heuristic filter first (drops ~60% noise free), LLM only on Medium+,
   reachability probe before the LLM, raw evidence always shown, user feedback loop
   auto-suppresses confirmed false positives, max 50 LLM calls/scan with a
   heuristic-only fallback if the LLM fails.
3. **Authorized scanning as a legal moat that is also a legal liability.** The product
   exists to scan other people's websites; one unauthorized scan is a reputation-ending
   event. Mitigation in depth: ownership proof before any intrusive stage, worker-side
   SSRF blocklist + DNS-rebinding check, audit log on every scan, abuse workflow
   (acknowledge 24h / investigate 72h / suspend same day if credible), Terms + Privacy
   before launch, no government/military/critical-infrastructure scanning without a
   written contract. This is the risk that cannot be fixed after the fact — it is
   designed in from Phase 0, not bolted on in Week 4.
