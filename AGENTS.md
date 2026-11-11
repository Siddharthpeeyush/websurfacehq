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
| `celery -A app.workers.celery_app worker --loglevel=info` | `apps/api` | Celery worker (Week 1 — exists; needs a Redis broker, see `.env.example`) |
| `pytest` | `apps/api` | Tests — 168 passing in Week 1 (incl. 401/403/404 matrix, cross-tenant, SSRF, idempotency, DLQ, review-fix tests) |
| `curl localhost:8000/health` | anywhere | Health check: 200 `{"status": "ok" \| "degraded", "components": {...}}` (DB / Redis / queue) |
| `supabase db push` | repo root | Apply migrations (staging first, then prod) — Week 1 migrations 0001–0004 exist; the project exists now (see blockers) but this VM has no DB password / access token, so the parent applies them via the dashboard SQL editor: 0001 → 0002 → 0003 → 0004, then `seed.sql` (seed auth users first, exact UUIDs in `seed.sql`) |

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
- **ADR-0006:** Week 1 foundation decisions (11 Nov 2026) — `docs/decisions/adr-0006-week-1-foundation.md`. Token-hash storage, `websurfacehq-verify=<token>` TXT format, PyJWT verification, auth through our API (localStorage token trade-off), two-layer tenancy (can() + RLS, service-role delete reasoning), Store protocol + InMemoryStore, best-effort dispatch, Celery backoff 60/120/240, CSP `connect-src` API origin, locked constants (token 32B / 7d, signed URL 15 min, Free 3/month + 1 active, login 5/15 min).
- **PyJWT 2.10.1 → 2.15.0 (11 Nov 2026, CI run #6 audit fix):** pip-audit found 22 known vulnerabilities in PyJWT 2.10.1 (incl. GHSA-pxh4-856f-4h89, HMAC key validation); 2.15.0 is the first version clearing all of them — pip-audit now reports "No known vulnerabilities found". Drop-in for our HS256 usage (`jwt.decode(..., algorithms=["HS256"])` + `jwt.PyJWTError` in `app/auth/jwt.py`); 168 API tests, ruff, and mypy all green after the bump. Note: the GHSA IDs in the original CI report (GHSA-75c2-4v7v-6mww, GHSA-ffqj-6fqr-9h24, GHSA-8cf7-32cx-333g) were NOT reproduced by local pip-audit — do not cite them; the verified IDs are the PYSEC-2026-* entries plus GHSA-pxh4-856f-4h89.
- **CI run #6 fix (11 Nov 2026):** run #6 on Week 1 head 39c0a232 failed 3/4 jobs. (1) api: `test_memory_prunes_stale_keys` failed on CI only — root cause was a clock-dependent fixture, not a limiter defect: it seeded `[stale, 1]` and the literal `1` only counts as stale when `time.monotonic() > 901`, so on a fresh CI runner nothing was pruned (10002 keys). Fixed by seeding `[stale, stale]`; the assertion is unchanged and the limiter code was not touched. (2) secrets: gitleaks flagged 6 generic-api-key hits — AGENTS.md:110 (`websurfacehq-verify=` reworded to `websurfacehq-verify=<token>`), test_auth.py TEST_SECRET replaced with a clearly-fake spaced value (test-only, verified by usage), seed.sql header hash copies removed (canonical hashes stay in the INSERT VALUES, untouched — live seed apply in progress). No real secret was found; nothing to rotate. No `.gitleaks.toml` allowlist was needed.
- **Week 1 scope (completed 11 Nov 2026, pending live Supabase):** migrations 0001–0004 + RLS on all 13 tables (live-Postgres validated 83/83 incl. the 0004 H4 PostgREST simulation + M4/M3 partial indexes + INSERT probes + REVOKE proofs) + 2-tenant seed; Supabase Auth flows via our API; central `can()` on every route; FastAPI + Celery skeleton (3 queues, idempotent task ids, retry/DLQ); target verification (DNS TXT / well-known file); SSRF blocklist + DNS-rebinding check; frontend shell + design system + auth screens. 168 API tests passing; web lint/typecheck/build green; live smoke (API + web servers) verified. Independent review #1 returned NOT APPROVED (5 High, 10 Medium, 16 Low, no Critical) — all 5 Highs + most Mediums/Lows fixed in the working tree (see ADR-0006 Addendum A). Re-review #2 ALSO returned NOT APPROVED (2 blockers: H4 INSERT bypass — the UPDATE triggers did not stop a forged-verified INSERT; M3 cap race — no DB enforcement) + 10 non-blocking findings — all fixed in the working tree (INSERT trigger, M3 partial unique index + TargetCapError, server-table REVOKEs, M5 dead-code fix, H1 code match, worker audit hashing, lock retry, list_scans filter, sign_out trust_env, celery comment). Focused re-check #3 returned **APPROVED** (11 Nov 2026) — both blockers verified closed with independent evidence — and its 3 new Lows were folded in the same pass (attack_paths REVOKE, INSERT-trigger expiry/method, NULL-hash verify guard; validator fidelity fix: pre-grant + has_table_privilege REVOKE proofs). Week 1 is ready to push. NOT proven live yet: the full auth flow and the cross-tenant check against real Supabase (migrations not yet applied — parent applies via dashboard), and the Celery worker against a real broker.
- **Week 1 review-fix rules (11 Nov 2026, from the fix pass):** a column-level REVOKE is a NO-OP against a table-level UPDATE grant in Postgres — use a trigger for field-level write bans (proven by the pgserver run). UPDATE triggers do NOT cover INSERT — every write ban needs both (proven by the round-2 re-review's INSERT probe). RLS UPDATE with no UPDATE policy affects 0 rows silently (no error); a missing GRANT raises InsufficientPrivilege — a validator must check the row state, not just expect an exception. A validator's own GRANT block can silently undo the migration's REVOKEs — model the real privilege state (table-level DML except where the migration revoked). A validator that CONSTRUCTS the expected privilege state cannot prove a REVOKE — pre-grant the default privileges before applying the migration and assert with `has_table_privilege` (round-3 lesson). An INSERT trigger must cover EVERY verification-evidence field (status, hash, verified_at, verified_by, expires_at, method) — a field left out is a forgery vector (round-3 lesson). A server-created table is only closed when it is in the REVOKE list — `attack_paths` was missed in the first pass because it lives in 0003, not 0001 (round-3 lesson). `hmac.compare_digest` raises TypeError on a None hash — guard NULL stored hashes before comparing (round-3 lesson). `httpx.stream` needs `trust_env=False` in the scanner (this VM's proxy env breaks httpx URL parsing; a proxy would also defeat SSRF checks). fakeredis has no EVAL — use WATCH/MULTI for atomic compare-and-delete. `pkill -f` self-matches when the literal pattern sits in the shell's cmdline — build the pattern via a variable (or kill by PID); port-closed is the reliable "server stopped" proof. `UnsafeUrlError` subclasses `ValueError` — never raise it inside a `try/except ValueError`. The `Scan` dataclass had no `deleted_at` field at all — a list filter on it crashes; the field must exist on the row shape, not just in SQL. provider.py binds `create_client` at import — tests must patch `app.auth.provider.create_client`, not `supabase.create_client`.
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
- [x] **GitHub repo created** — `Siddharthpeeyush/websurfacehq` (public, main), created 11 Nov 2026 by the owner; Phase 0 scaffold + Next 16 migration pushed and verified on main.
- [x] **Supabase project not created** — RESOLVED 11 Nov 2026: project **websurfacehq** exists (ref `dpwfshafzyxyfoktsggo`, `https://dpwfshafzyxyfoktsggo.supabase.co`, Singapore ap-southeast-1, Nano, Healthy — verified live via `/auth/v1/settings` 200). URL + anon key wired into gitignored local env files only (`apps/api/.env`, `apps/web/.env.local`); `.env.example` keeps placeholders. **Still open:** (a) migrations 0001 → 0002 → 0003 → 0004 + `seed.sql` are NOT applied — this VM has no DB password / access token / service-role key, so the parent applies them via the dashboard SQL editor (seed auth users first, exact UUIDs in `seed.sql`); (b) the **service-role key and JWT secret were deliberately NOT retrieved** — until they are set, `supabase_configured` is False, auth endpoints answer 503, JWT verification answers 401 (by design, never a silent anon-key fallback). Do NOT substitute the anon key for either.
- [ ] **Domain not registered** — `websurfacehq.com` availability unverified until
      checkout (RDAP "no record" is not proof).
- [x] **Free-tier quota** — RESOLVED 11 Nov 2026: 3 scans/month (owner's pick;
      blueprint §0.4/§1.6 saying 3/day is superseded).
- [x] **CI gitleaks findings (11 Nov 2026)** — RESOLVED: the flagged keys were
      per-build ephemeral keys in `apps/web/.next/` build output; `.next/` and
      `node_modules/` are gitignored, so generated output can never be
      committed or trip the CI secrets job. CI run #3 (Next 16) passed the
      secrets job; no allowlist entry was added. Python tool caches
      (`.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/`, `__pycache__/`) are
      ignored the same way.
