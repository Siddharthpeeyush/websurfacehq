# AGENTS.md — WebSurfaceHQ repo memory

> Update this file every time a decision is made. A decision not recorded here is a
> decision not made. This file is the repo's memory; the docs in `docs/` are the
> reasoning behind it.

## Product (2–3 sentences)

WebSurfaceHQ ("Your attack surface, under control.") is an international
vulnerability-scanner SaaS for small-business website owners, indie developers, and
small agencies with no security team. Paste a domain, prove you own it (DNS TXT or
`/.well-known/scan-verify.txt`), get a prioritized, evidence-backed report a developer
can act on in 10 minutes — AI-triaged false positives, safe PoCs, JS secret detection,
KEV/EPSS-ranked fixes, and an attack-surface diff. Authorized scanning only; the
scanner never auto-exploits, never dumps data, and never uses a secret it finds.
Spec: blueprint v4 (`~/workspace/vuln-scanner-platform/PDF-SOURCE.md`).

## Stack

- **Frontend:** Next.js 16 (App Router) + TypeScript + Tailwind — Vercel Hobby ($0)
- **API:** FastAPI (Python) + Pydantic — Render Free
- **Hot path:** Go `scanner-agent` binary wrapping naabu / httpx / katana / nuclei via exec
- **DB / Auth / Storage:** Supabase (Postgres + Auth + Storage), RLS on all tables
- **Queue:** Celery + Upstash Redis — 3 routed queues (recon / crawl / vuln)
- **AI triage:** Gemini 2.5 Flash (primary) / Groq Llama-3.1 (fallback), free tier
- **Enrichment:** NVD API 2.0, CISA KEV, FIRST EPSS (nightly, free)
- **Observability:** Sentry (free) + UptimeRobot (free, 14-min `/health` ping = Render keep-alive)

## Toolchain

- **Go 1.27.4 installed on this VM** (11 Nov 2026, Phase 0): official tarball from
  go.dev, SHA256-verified, user-local at `~/go` (no sudo), `go version go1.27.4
  linux/amd64` verified. GOPATH set to `~/gopath` (Go's default GOPATH collided
  with GOROOT at `~/go`). The Go scanner-agent phase is **unblocked** — the
  toolchain gap from the plan is closed. Do NOT fake the agent in Python and call
  it done — see `packages/scanner-agent/README.md`.
- Node.js 20+, Python 3.12+ assumed for the scaffold agents; versions to be confirmed
  by them in their own setup notes.

## Rules (non-negotiable)

1. Follow the 15-layer Real SaaS Playbook in order (`~/workspace/custom-skills/real-saas-playbook/SKILL.md`).
   Do not skip a layer because the happy path works.
2. Working loop per task: plan first → review the plan → implement in small steps on a
   branch → verify with lint + typecheck + tests → review the diff → record the decision
   here and in `docs/decisions/`.
3. **Do-not-fool-me check before calling any task done:** show lint + typecheck + test
   output; list every file changed and why; list anything skipped / stubbed / mocked /
   hard-coded; list assumptions the user should confirm. Never describe work as complete
   if any test is failing or skipped. Never edit a test to make it pass.
4. **Independent review:** a separate reviewer agent security-reviews each phase before
   it is reported as done. A phase is not done until the reviewer signs off.
5. Ask before adding a dependency; record the reason for every dependency added.

## The 8 security procedures (from the blueprint + plan — condensed)

1. **Threat model first:** STRIDE + OWASP Top 10 per entry point, in
   `docs/threat-model.md`, before the code for that entry point.
2. **Auth never hand-rolled:** Supabase Auth only. RLS on all tables. One central
   `can(user, action, resource)` used by every endpoint; frontend only hides actions,
   server is the source of truth.
3. **Scanner safety:** ownership proof BEFORE any scan (DNS TXT or
   `/.well-known/scan-verify.txt`). Worker-side SSRF blocklist: `10/8, 172.16/12,
   192.168/16, 127/8, 169.254.169.254`, localhost, plus DNS-rebinding check. Safe
   payloads only. 5 req/s per domain. Found secrets flagged redacted and NEVER used.
4. **Data protection:** encryption at rest for sensitive fields; 90-day evidence
   auto-delete; instant user deletion; structured JSON logs with redaction; private
   storage with short-lived signed URLs; never cache one tenant's data for another.
5. **Secrets & code hygiene:** no secrets in code / committed .env / frontend bundle.
   CI secret scanner blocks merges. Dependency audit in CI.
6. **Testing test-first:** unit + integration against a real DB; 401/403/404 matrix on
   every endpoint; SSRF / injection / XSS tests; run the scanner on itself before
   launch; live screen-by-screen check.
7. **Infra & monitoring:** separate staging/prod DBs and keys; HTTPS + security headers;
   Sentry + UptimeRobot; alerts (error > 5%, queue > 50, p95 > 2 s) with runbooks;
   backups with tested restore; billing alerts.
8. **Incident plan:** abuse acknowledge 24 h / investigate 72 h; breach detect →
   contain → notify → postmortem; DPDP retention rules. User's logins/OTPs stay his —
   never ask in chat, secure sign-in flow only.
9. **Rate limits:** login/signup/reset 5 attempts / 15 min per IP + per email; per-user
   plan quotas (Free: 1 active scan, 3/month — locked 11 Nov 2026, 1,000 requests/scan); per-target politeness
   (5 req/s, 2 concurrent, respect robots.txt + Retry-After); 429 with Retry-After.
10. **Security review before EVERY release:** broken access control, injection, XSS,
    CSRF, open redirects, SSRF, insecure uploads, secrets in code/logs, security
    headers, verbose errors, insecure cookies — report file, line, severity, exploit
    scenario, fix for each finding.

## Commands

| Command | Where | Purpose |
|---|---|---|
| `npm run dev` / `npm run build` / `npm run lint` | `apps/web` | Frontend dev / build / lint |
| `uvicorn app.main:app --reload` | `apps/api` | API dev server |
| `celery -A app.workers.celery_app worker --loglevel=info` | `apps/api` | Celery worker (Week 1 — `app.workers` does not exist yet in Phase 0) |
| `pytest` | `apps/api` | Unit tests — 11 passing in Phase 0 (integration vs real DB lands Week 1) |
| `curl localhost:8000/health` | anywhere | Health check (expect 200 `{"status": "ok"}` — liveness-only in Phase 0; component checks land Week 1) |
| `supabase db push` | repo root | Apply migrations (staging first, then prod) — Week 1, no migrations exist yet |

## Decisions so far

- **Brand:** WebSurfaceHQ (locked 11 Nov 2026). websurfacehq.com/.io/.in/.app/.co free
  per RDAP (unverified until registrar confirms); @websurfacehq verified free.
  Numerology 2/2 (weak) — accepted by the owner; availability + meaning won.
- **Format:** website SaaS, not .exe. CLI for CI/CD and PWA are post-MVP options.
- **ADR-0001:** modular monolith (not microservices) — `docs/decisions/adr-0001-modular-monolith.md`.
- **ADR-0002:** Next.js + FastAPI + Go stack — `docs/decisions/adr-0002-nextjs-fastapi-go-stack.md`.
- **ADR-0003:** Supabase Auth + Postgres + Storage with RLS — `docs/decisions/adr-0003-supabase-auth-rls.md`.
- **ADR-0004:** Celery + Upstash Redis, 3 routed queues — `docs/decisions/adr-0004-celery-redis-queues.md`.
- **ADR-0005:** Next.js 14 → 16 upgrade (owner decision 11 Nov 2026) — `docs/decisions/adr-0005-nextjs-16-upgrade.md`. 14.2.35 carried an unpatched critical; the glob override from the run #1 audit fix is removed (Next 16's tree has no glob); ESLint 9 flat config closes the Phase 0 ESLint 8 pin.
- **Cut from MVP:** auto-exploitation, authenticated scanning, scheduled scans, team
  roles, custom template editor, autonomous remediation, identity blast radius.
- **Pricing (blueprint):** Free (1 domain, 3 scans/month — locked 11 Nov 2026 by the owner; blueprint §0.4/§1.6 saying 3/day is superseded); Starter Rs 499/mo; Pro Rs 1,499/mo; Business Rs 4,999/mo;
  pay-per-scan Rs 199. No ads, never sell data, never sell a "clean" report.
- **Phase 0 scope (this task):** scaffold + docs, completed 11 Nov 2026 by four
  agents (web, API, docs/root, CI/tooling) plus an independent review pass and
  its fixes. `apps/web`, `apps/api`, `.github`, pre-commit/gitleaks configs all
  exist now — the "owned by other agents" note below no longer applies.

## Open blockers

- [x] **Go installed on this VM** — Go 1.27.4, 11 Nov 2026 (Phase 0, user-local
      `~/go`, SHA256-verified). The Go scanner-agent phase is unblocked.
- [ ] **GitHub repo not created** — `Siddharthpeeyush/websurfacehq` (public, main).
      Owner creates it if the connector cannot.
- [ ] **Supabase project not created** — owner creates it in the dashboard when asked (Week 1).
- [ ] **Domain not registered** — `websurfacehq.com` availability unverified until
      checkout (RDAP "no record" is not proof).
- [x] **Free-tier quota** — RESOLVED 11 Nov 2026: 3 scans/month (owner's pick;
      blueprint §0.4/§1.6 saying 3/day is superseded).
- [ ] **CI gitleaks findings (11 Nov 2026, CI agent report, confirmed by
      coordinator re-scan):** gitleaks flagged 3 findings in `apps/web/.next/`
      build output — per-build ephemeral encryption/signing keys
      (`previewModeEncryptionKey`, `previewModeSigningKey`, `encryptionKey` in
      `prerender-manifest.json` and `server-reference-manifest.json`), rotated
      every build. Not long-lived credentials and worthless in this scaffold
      (no preview mode, no Server Actions exist) — but they ARE real keys, not
      "hashes". Fix is `.gitignore`: `.next/` and `node_modules/` are ignored,
      so generated build output can never be committed and trip the CI secrets
      job. Do NOT add `.next` to the gitleaks allowlist. Also ignored: Python
      tool caches `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/`,
      `__pycache__/` (generated output must never be committed or trip CI
      secrets/audit jobs). The ignore is operative only once the repo is in
      git (see the GitHub-repo blocker above).
