# ADR-0001: Modular monolith (not microservices)

**Status:** Accepted (11 Nov 2026, Phase 0)
**Deciders:** Owner (Siddharth Peeyush) + build agent, per the Real SaaS Playbook Layer 2.

## Context

WebSurfaceHQ is a solo-founder SaaS: one developer (plus AI agents), a $0 MVP budget, and
a 4-week build window. The system has clear pieces — a Next.js frontend, a FastAPI API,
Celery workers, and a Go scanner-agent — but at MVP volume (~30–50 scans/day) none of
them is under enough load to justify independent deployables. The blueprint (§1.1) and
the playbook both default to a modular monolith for a solo/small team. The failure mode
we are avoiding is the one the playbook warns about: microservices that are harder to
debug, more expensive to run (each service is a paid Render instance once free tier ends),
and slower to change — for load that does not exist yet.

## Decision

Build one monorepo with one deployable API service plus separate Celery worker processes
from the same codebase, with strict module boundaries:

- `apps/web` (Next.js frontend) and `apps/api` (FastAPI) are separate deployables but
  live in one repo with one CI pipeline.
- Inside `apps/api`, business logic lives in `app/services/`; route handlers are thin;
  modules (`targets/`, `scans/`, `findings/`, `reports/`, `auth/`, `workers/`) may only
  talk to each other through their service layer, never by importing another module's
  internals.
- The Go `scanner-agent` is a separate binary (in `packages/scanner-agent/`) invoked by
  workers via exec — it is a process boundary, not a network service.
- Split a module into its own service only when a single queue becomes the bottleneck
  (blueprint §1.1: "Split only when a single queue becomes the bottleneck").

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Full microservices (auth service, scan service, report service, triage service) | 4–5 deployables × Render free-tier sleep behaviour = scans dying mid-pipeline; 4–5× the CI/deploy/observability surface for a solo founder; $0 budget cannot absorb per-service paid tiers at 100 scans/day |
| Single-process everything (API + workers in one Render service) | A sleeping API would kill a running scan (Render free sleeps after 15 min idle); a Nuclei OOM would take the API down with it. Rejected on reliability, not on principle — the worker is a separate *process*, not a separate *service architecture* |
| Serverless functions for the API | Scan orchestration is long-lived and stateful (30-min Nuclei runs, Celery chains); function timeouts and cold starts fight the workload. Vercel/Render free services fit better |

## Consequences

- **Positive:** one repo, one CI pipeline, one deploy story; debugging is `grep` + one
  log stream per service; $0 at MVP; a module can be extracted later without rewriting
  callers (the service-layer boundary is the seam).
- **Negative:** a bad deploy can take API + workers down together (mitigated: separate
  Render services, separate deploys, rollback runbook in `docs/runbooks/rollback.md`);
  the API and workers share a codebase, so a breaking change in shared code affects both
  (mitigated: CI runs the full suite before either deploys).
- **Neutral / to watch:** if the `vuln` queue becomes the bottleneck first (likely —
  Nuclei is the slowest stage), the first split is to scale worker *concurrency*, not to
  extract a service. A service split is a Month 3+ decision, taken on measured queue
  data, not on speculation.
