# ADR-0002: Next.js (frontend) + FastAPI (API) + Go (scanner-agent) stack

**Status:** Accepted (11 Nov 2026, Phase 0)
**Deciders:** Owner + build agent. Locked in `ENGINEERING-PLAN.md` §0.

## Context

Three different jobs need three different strengths: (1) a dashboard that is fast,
accessible, and SEO-friendly for marketing/sample-report pages; (2) an API that
orchestrates a security pipeline with strict input validation and a mature security-tooling
ecosystem; (3) a hot path that port-scans and crawls thousands of hosts concurrently.
No single language is best at all three. The blueprint (§1.2–1.6, §3) prescribes this
exact split, and the owner's standing rule is "use the best tech stack" for the job.

## Decision

- **Frontend:** Next.js 14 (App Router) + TypeScript + Tailwind, hosted on Vercel Hobby.
- **API:** FastAPI (Python) on Render, with Pydantic validation at the boundary and
  Celery for background work.
- **Hot path:** Go `scanner-agent` binary in `packages/scanner-agent/`, wrapping
  ProjectDiscovery tools (naabu, httpx, katana, nuclei) via exec and parsing their JSONL.
- **Database/Auth/Storage:** Supabase (see ADR-0003). **Queue:** Celery + Upstash Redis
  (see ADR-0004).

## Alternatives considered

| Layer | Alternative | Why rejected |
|---|---|---|
| Frontend | React SPA (Vite) + separate marketing site | No SSR/SEO for landing + sample-report pages; two sites to maintain; Next.js on Vercel is free and is the playbook-friendly default |
| Frontend | SvelteKit / Remix | Smaller hiring/community surface for a solo founder; no advantage over Next.js for a dashboard product |
| API | Express / Node.js | Weaker security-tooling ecosystem (no Celery-class task queue as mature, fewer scanner-adjacent libraries); Python owns orchestration of Nuclei/sqlmap-style tooling |
| API | Django | Heavier than needed; FastAPI's async + Pydantic + auto OpenAPI docs fit an API-first service better, and the blueprint prescribes FastAPI |
| API | Go for the whole backend | Go's HTTP ecosystem is fine, but Python's security-tooling libraries, Celery, and the team's existing Python fluency win for orchestration; Go is used where it is actually better (the hot path) |
| Hot path | Python-only scanning (asyncio + subprocess) | Slower and more fragile at 10k-host probe scale; ProjectDiscovery tools are Go-native and designed to pipe JSONL to each other — wrapping them from Go is the natural fit |
| Hot path | Writing our own port scanner / crawler / Nuclei replacement | Explicitly forbidden by the blueprint (§3.8): "Do not write your own port scanner or crawler. Wrap the best open-source tools and orchestrate them." |

## Consequences

- **Positive:** each layer uses the best tool for its job; $0 at MVP across all three
  hosts; ProjectDiscovery tools are wrapped, not rebuilt; TypeScript + Pydantic give
  strict typing at both boundaries.
- **Negative:** three languages in one repo (TypeScript, Python, Go) — more toolchain to
  maintain. Mitigated: each layer has its own lint/typecheck/test in CI, and the Go
  surface is deliberately tiny (one binary, exec + JSONL parsing).
- **Toolchain note (resolved 11 Nov 2026, Phase 0):** Go 1.27.4 is installed on this
  VM (official go.dev tarball, SHA256-verified, user-local `~/go`). The Go
  scanner-agent phase is unblocked. Do not fake the agent in Python and call it
  done — see `packages/scanner-agent/README.md`.
