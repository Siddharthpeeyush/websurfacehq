# WebSurfaceHQ

**"Your attack surface, under control."**

WebSurfaceHQ is an international vulnerability-scanner SaaS for small-business website
owners, indie developers, and small agencies who have a website but no security team.
Paste a domain, prove you own it, and get a prioritized, evidence-backed security report
a developer can act on in 10 minutes — with AI triage of false positives, safe
proof-of-concept evidence, JS secret detection, and an attack-surface diff that shows
what changed since the last scan. Authorized scanning only: no scan runs without proof
of ownership, and the scanner never auto-exploits, never dumps data, and never uses a
secret it finds.

**Status: Phase 0 — scaffold and docs only.** There is no deployed product yet, no
Supabase project, no live scan. This repo holds the engineering plan, the design docs,
and the working scaffold: `apps/web` (Next.js, builds and serves locally) and
`apps/api` (FastAPI, real `GET /health` → 200), plus CI, pre-commit and gitleaks
configs. See "Phase 0 exit gate" below.

## Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14 (App Router) + TypeScript + Tailwind — Vercel Hobby |
| API | FastAPI (Python) + Pydantic — Render Free |
| Hot path | Go `scanner-agent` binary wrapping naabu / httpx / katana / nuclei (via exec) |
| Database / Auth / Storage | Supabase (Postgres + Auth + Storage), RLS on all tables |
| Queue | Celery + Upstash Redis — 3 routed queues (recon / crawl / vuln) |
| AI triage | Gemini 2.5 Flash (primary) / Groq Llama-3.1 (fallback), free tier |
| Enrichment | NVD API 2.0, CISA KEV, FIRST EPSS (nightly, free) |
| Observability | Sentry (free) + UptimeRobot (free) |

Cost at MVP: **$0/month** on free tiers. First paid at ~100 scans/day: Redis ~$10/mo,
then Render ~$7/mo. Full cost tables: `docs/architecture.md` §5,
`docs/system-design.md` §9.

## Monorepo layout

```
websurfacehq/
├── README.md                    # this file
├── AGENTS.md                    # repo memory: product, stack, rules, decisions, blockers
├── ENGINEERING-PLAN.md          # master plan (phases, gates, security rules)
├── .env.example                 # every variable, documented, placeholders only
├── docs/                        # system-design, architecture, decisions, permissions,
│                                # threat-model, api-conventions, testing, monitoring,
│                                # caching, runbooks/
├── apps/
│   ├── web/                     # Next.js frontend (scaffold exists; no test suite yet — Week 1)
│   └── api/                     # FastAPI (Celery + services/ land in Week 1)
├── packages/
│   └── scanner-agent/           # Go binary (README placeholder in Phase 0 — Go 1.27.4 installed, no code yet)
├── supabase/
│   └── migrations/              # version-controlled migrations only (none yet in Phase 0)
└── .github/                     # CI: install → lint → typecheck → test → build
```

## Setup

### Prerequisites

- Node.js 20+ and npm (frontend)
- Python 3.12+ (API)
- Go 1.27.4 (scanner-agent) — installed user-local at `~/go` on this VM (Phase 0)
- Supabase project (owner creates it in the dashboard when asked — Week 1)
- Upstash Redis database (free tier)

### 1. Clone and configure

```bash
git clone https://github.com/Siddharthpeeyush/websurfacehq.git
cd websurfacehq
cp .env.example apps/api/.env        # API env file (see .env.example header)
cp .env.example apps/web/.env.local  # frontend env file
# then fill in REAL values in each; never commit .env / .env.local
# (do NOT create a .env at the repo root — neither app reads one there)
```

### 2. Frontend (apps/web)

```bash
cd apps/web
npm install
npm run dev                 # http://localhost:3000
```

### 3. API + workers (apps/api)

```bash
cd apps/api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload            # API on http://localhost:8000
# worker (Week 1 — app.workers does not exist yet in Phase 0):
# celery -A app.workers.celery_app worker --loglevel=info
```

### 4. Verify

```bash
curl http://localhost:8000/health   # expect 200 {"status": "ok"} — liveness-only in Phase 0
                                    # (component checks for DB/Redis/Celery land in Week 1)
curl http://localhost:8000/live     # expect 200 (lightweight, for load balancers)
```

## Commands

| Command | Where | Purpose |
|---|---|
| `npm run dev` / `npm run build` / `npm run lint` | `apps/web` | Dev server / production build / lint |
| `uvicorn app.main:app --reload` | `apps/api` | API dev server |
| `celery -A app.workers.celery_app worker --loglevel=info` | `apps/api` | Celery worker (Week 1 — does not exist yet) |
| `pytest` | `apps/api` | Unit tests — 11 passing in Phase 0 (integration vs real DB lands Week 1) |
| `supabase db push` | repo root | Apply migrations (staging first, then prod) — Week 1, no migrations exist yet |

Exact scripts are defined in each app's `package.json` / `pyproject.toml`; this table
is the contract they must match. There is no web test script in Phase 0 (no web test
suite yet — see `.github/workflows/ci.yml` header note).

## Docs

- Product design: [docs/system-design.md](docs/system-design.md)
- Architecture: [docs/architecture.md](docs/architecture.md)
- Decisions: [docs/decisions/](docs/decisions/) (ADRs 0001–0004)
- Permissions + `can()` contract: [docs/permissions.md](docs/permissions.md)
- Threat model: [docs/threat-model.md](docs/threat-model.md)
- API conventions: [docs/api-conventions.md](docs/api-conventions.md)
- Testing: [docs/testing.md](docs/testing.md)
- Monitoring: [docs/monitoring.md](docs/monitoring.md)
- Caching: [docs/caching.md](docs/caching.md)
- Runbooks: [docs/runbooks/](docs/runbooks/) (rollback, health-check-failing, queue-depth-high)
- Migrations: [supabase/migrations/README.md](supabase/migrations/README.md)
- Scanner agent: [packages/scanner-agent/README.md](packages/scanner-agent/README.md)
- Master plan: [ENGINEERING-PLAN.md](ENGINEERING-PLAN.md)
- Build method: the 15-layer Real SaaS Playbook
  (`~/workspace/custom-skills/real-saas-playbook/SKILL.md`)
- Product spec: blueprint v4 (`~/workspace/vuln-scanner-platform/PDF-SOURCE.md`)

## Phase 0 exit gate

Phase 0 is done when: dev servers run, `GET /health` returns 200, CI is green on the
empty skeleton, and an independent reviewer has security-reviewed the phase.
Evidence: CI log + health-check output. No phase is reported as done without its evidence.
