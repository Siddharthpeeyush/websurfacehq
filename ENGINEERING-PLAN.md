# WebSurfaceHQ — Engineering Plan

**Status:** BUILD AUTHORIZED 11 Nov 2026. Name locked: **WebSurfaceHQ**.
**Product:** international vulnerability-scanner SaaS (domain-input scanning, AI triage, safe PoC, JS secret scraper, attack-surface diff). Blueprint v4 (24pp) is the spec: `~/workspace/vuln-scanner-platform/PDF-SOURCE.md`.
**Tagline:** "Your attack surface, under control."
**Owner instruction (11 Nov 2026):** strict security — this is a security company, not a normal product. No mistakes, no wrong implementations, no excuses. Quality over speed; proper time is given. Software engineering done in a structured way, reported phase by phase.

## 0. Decisions (recorded, not assumed)

- **Brand:** WebSurfaceHQ. websurfacehq.com/.io/.in/.app/.co all free per RDAP (unverified until registrar confirms); no Google company; no Product Hunt launch; @websurfacehq verified free. Numerology 2/2 (weak) — accepted by the user anyway; availability + meaning won.
- **Format:** website SaaS, not .exe. CLI for CI/CD and PWA are post-MVP options.
- **Architecture:** modular monolith (playbook default). Frontend Next.js 16 + TypeScript + Tailwind on Vercel. API FastAPI (Python) on Render. Hot path: Go `scanner-agent` binary. DB/Auth/Storage: Supabase Postgres + Auth + Storage, RLS on all tables, `user_id` on every tenant table. Queue: Celery + Upstash Redis, 3 routed queues (recon / crawl / vuln).
- **Repo:** local scaffold at `~/workspace/websurfacehq/` → GitHub `Siddharthpeeyush/websurfacehq` (public, main). User creates the repo if the connector cannot; pushes via the GitHub connector.
- **Toolchain gap — RESOLVED 11 Nov 2026 (Phase 0):** Go 1.27.4 installed from
  go.dev (SHA256-verified, user-local `~/go`), `go version go1.27.4 linux/amd64`
  verified. The Go scanner-agent phase is unblocked. Do not fake the agent in
  Python and call it done.
- **ADR-0007 (11 Nov 2026):** ES256 JWT verification via cached JWKS by `kid` (1 h TTL, refresh on unknown `kid`, stale-cache fallback); HS256 removed entirely — `docs/decisions/adr-0007-es256-jwks-jwt-verification.md`. Owner decision (23:19 IST): ES256 with JWKS — do NOT revert to legacy HS256.
- **Week 1 live-proof fix round (11 Nov 2026):** the Week 1 live proof FAILED with three High blockers, all fixed in the working tree (not yet pushed); full evidence in `docs/live-proof-evidence-2026-11-11.md`. **F1** — VM proxy env breaks httpx (bracketed IPv6 `[::1]` in `no_proxy` → `InvalidURL` in `supabase.create_client`): new proxy-safe shared client `apps/api/app/core/http.py` (`trust_env=False` + operator's explicit proxy + `SSL_CERT_FILE` CA re-applied when configured; verification never disabled) + `sanitize_no_proxy_env()` at launch + redacted GoTrue error logging. **F2** — zero GRANTs on the live DB (migrations 0001–0004 contain no GRANT; all roles 42501): new `supabase/migrations/0005_grants.sql` (full DML to `service_role` on all 13 tables; `authenticated` full DML on 5 user-writable tables, SELECT-only on the 8 server-created/read-only tables; `anon` nothing; all eight 0004 REVOKEs re-asserted after the GRANTs). **F3** — ES256 project vs HS256-only verifier (every Bearer token 401): `app/auth/jwt.py` rewritten to ES256 via cached JWKS by `kid`; HS256 removed entirely.
- **Key rotation (11 Nov 2026, dashboard-verified):** the legacy HS256 key is REVOKED ("No previously used keys"; ECC signing key unchanged); old anon + service_role HS256 JWTs disabled; replacements are the new-style keys (publishable = anon, secret key = service_role), re-synced into the gitignored local env files by the parent. The legacy `SUPABASE_JWT_SECRET` is retired — removed from `apps/api/.env`, `config.py`, `supabase_configured` (now URL + anon + service-role only), and `.env.example`.
- **Validator methodology change (11 Nov 2026):** never pre-grant in validation — the old 83/83 validator was blind to missing grants because it pre-granted DML. The durable validator `supabase/validate_migrations.py` asserts grants present AND revokes holding on a fresh DB with NO pre-grant: 278/278 passed (0001-0006); the control run without 0005/0006 fails 126 checks.
- **VM-egress assumption (not proven fact):** on this VM direct egress is blocked — only proxy-env clients reach the internet; the proxy-safe helper re-applies the operator's proxy + CA so VM traffic works, and on Render (no proxy/CA env) it is exactly a bare `trust_env=False` direct client. Production Render is assumed unaffected by the VM-only proxy issue.
- **Live re-proof is the next step (not done in this round):** the re-proof runs after the 0005 live apply + email rate-limit reset (parent's follow-up). What worked live so far: `/live` 200, login vs real Supabase, Admin API user creation, all 13 tables exist. Still unproven live: cross-tenant 404s, H4 trigger denials at the RLS/trigger layer, M3 429, healthy `/health`, signup 502 root cause.

## 1. Engineering method — the working loop (every layer, no exceptions)

Follow `~/workspace/custom-skills/real-saas-playbook/SKILL.md` (15-layer playbook) in order. Do not skip a layer because the happy path works.

Per task: **plan first → review the plan → implement in small steps on a branch → verify with lint + typecheck + tests → review the diff → record the decision** in the repo `AGENTS.md` and `docs/decisions/`.

**Do-not-fool-me check before calling any task done:** show lint + typecheck + test output; list every file changed and why; list anything skipped / stubbed / mocked / hard-coded; list assumptions the user should confirm. Never describe work as complete if any test is failing or skipped. Never edit a test to make it pass. Ask before adding a dependency; record the reason for every dependency added.

**Independent review:** a separate reviewer agent security-reviews each phase before it is reported as done. A phase is not done until the reviewer signs off.

## 2. Security rules — non-negotiable (this is a security company)

From the blueprint's 8 security procedures + playbook harden layer:

1. **Threat model first:** STRIDE + OWASP Top 10 per entry point, in `docs/threat-model.md`, before the code for that entry point.
2. **Auth never hand-rolled:** Supabase Auth only. RLS on all tables. One central `can(user, action, resource)` used by every endpoint; frontend only hides actions, server is the source of truth.
3. **Scanner safety:** ownership proof BEFORE any scan (DNS TXT or `/.well-known/scan-verify.txt`). Worker-side SSRF blocklist: `10/8, 172.16/12, 192.168/16, 127/8, 169.254.169.254`, localhost, plus DNS-rebinding check. Safe payloads only. 5 req/s per domain. Found secrets flagged redacted and NEVER used.
4. **Data protection:** encryption at rest for sensitive fields; 90-day evidence auto-delete; instant user deletion; structured JSON logs with redaction; private storage with short-lived signed URLs; never cache one tenant's data for another.
5. **Secrets & code hygiene:** no secrets in code / committed .env / frontend bundle. CI secret scanner blocks merges. Dependency audit in CI.
6. **Testing test-first:** unit + integration against a real DB; 401/403/404 matrix on every endpoint; SSRF / injection / XSS tests; run the scanner on itself before launch; live screen-by-screen check.
7. **Infra & monitoring:** separate staging/prod DBs and keys; HTTPS + security headers; Sentry + UptimeRobot; alerts (error >5%, queue >50, p95 >2s) with runbooks; backups with tested restore; billing alerts.
8. **Incident plan:** abuse acknowledge 24h / investigate 72h; breach detect → contain → notify → postmortem; DPDP retention rules. User's logins/OTPs stay his — never ask in chat, secure sign-in flow only.
9. **Rate limits:** login/signup/reset 5 attempts / 15 min per IP + per email; per-user plan quotas (Free: 1 active scan, 3/month, 1000 requests/scan — locked 11 Nov 2026 by the user; blueprint §0.4/§1.6 saying 3/day is superseded); per-target politeness (5 req/s, 2 concurrent, respect robots.txt + Retry-After); 429 with Retry-After header.
10. **Security review before EVERY release:** broken access control, injection, XSS, CSRF, open redirects, SSRF, insecure uploads, secrets in code/logs, security headers, verbose errors, insecure cookies — report file, line, severity, exploit scenario, fix for each finding.

## 3. Phases (blueprint roadmap, quality-gated)

### Phase 0 — Scaffold (this week)
Repo, `AGENTS.md` (product, stack, rules, commands, decisions), `docs/system-design.md` (problem, roles, flows, requirements, out-of-scope), `docs/architecture.md` (diagram, stack + one rejected alternative each, folder structure, job placement, third-party costs at launch and 10x, three riskiest decisions), `docs/decisions/`, `.env.example` (every variable documented), README with setup steps, health-check endpoint, lint/format/typecheck, pre-commit hooks, secret scanner, CI (install → lint → typecheck → unit → integration vs real DB → build, fails fast). **Exit gate:** dev servers run, health endpoint returns 200, CI green on an empty skeleton. **Evidence:** CI log, health-check output.

### Week 1 — Foundation
Supabase schema + migrations (all tables from blueprint Part 6 + Part 7: `attack_paths`, `findings.reachable`, `findings.reachability_evidence`, `findings.fix_verified_at`, `findings.fix_snippet`), RLS policies, seed data for 2 tenants, cross-tenant proof (user A cannot fetch user B's data by changing an id in the URL), Supabase Auth (signup/login/logout/email verification/reset/expiry), central `can()`, permissions matrix in `docs/permissions.md`, FastAPI + Celery skeleton with idempotent `task_id = scan_id:stage:target_hash`, target verification flow, SSRF blocklist + DNS-rebinding check, frontend shell + design system (tokens, buttons, inputs, modals, toasts, tables, empty/error/skeleton states), auth screens. **Exit gate:** security review #1 + 401/403/404 matrix green on every endpoint + cross-tenant test passing. **Evidence:** test output, review report, files changed. **Live-proof status (11 Nov 2026):** migrations 0001–0004 + seed applied live; the live proof FAILED on three High blockers (F1 VM proxy env, F2 missing GRANTs, F3 ES256/HS256 mismatch) — fixes landed in the working tree, incl. `supabase/migrations/0005_grants.sql` + `0006_policy_cleanup.sql` (both pending live apply) and the ES256/JWKS rewrite (see §0). The live re-proof, after the 0005 + 0006 apply + email rate-limit reset, is the next step; it was not re-run in the fix round.

### Week 2 — Recon
subfinder / crt.sh, httpx, naabu, JS secret scraper (Katana-collected JS, regex + entropy >4.5 + context scoring, redacted flags), tech fingerprint / TLS / screenshots, first live scan on the owner's own domain ONLY. **Exit gate:** end-to-end recon scan on websurfacehq.com (or owner's domain) with findings stored, diff hashing working. **Evidence:** scan report, test output.

### Week 3 — Vuln + Triage
Nuclei curated ~200 templates, dalfox, heuristic + LLM triage (Gemini/Groq free tier, Medium+ only, max 50 LLM calls/scan, cached by finding hash), KEV/EPSS enrichment, safe PoC generator (read-only only), attack-path chaining, reachability triage (httpx probe per finding before LLM). **Exit gate:** a scan produces triaged findings with verdicts (confirmed / likely_fp / needs_manual) + confidence, PoC evidence, and at least one attack path. **Evidence:** scan report, triage accuracy sample, test output.

### Week 4 — Report / Limits / Launch
PDF/HTML report, attack-surface diff, verified closure (re-run exact check on re-scan, "Fix verified" badge), copy-paste fix snippets, compliance-mapped reporting (OWASP Top 10 + PCI DSS / SOC 2 / ISO 27001), lite attack-surface map, rate limits + quotas, self-scan (scanner on itself), prod deploy (staging/prod separate), 5 beta users (own + friends' sites WITH written permission only). **Exit gate:** pre-launch checklist (playbook) all green — cross-tenant blocked, auth proven, every endpoint validates + checks permissions server-side, CI blocks failing merges, rollback documented, backups + restore tested, security review + dependency audit done, rate limits on, no tenant data cached at shared layers, errors tracked, logs structured + redacted, uptime checks + runbooks, load test done, billing alerts set, Terms + Privacy published. **Evidence:** full checklist with proof per item.

### Cut from MVP (do not build unless the user orders it)
Auto-exploitation, authenticated scanning, scheduled scans, team roles, custom template editor, autonomous remediation (breaks read-only rule), identity blast radius (enterprise scope).

## 4. Quality gates (apply to every phase)

- Lint + typecheck + unit + integration (real DB) + build all green in CI before merge.
- Authorization tests per endpoint: unauthenticated → 401, unauthorized → 403, other tenant → 404.
- Bug fixes test-first: failing test reproducing the bug first, then fix, then full suite green.
- No test edited to make it pass. No skipped tests reported as done.
- Money as integer paise/cents, never floats. Cursor pagination on all list endpoints. One error format with error codes. Input validation at the boundary.
- Mobile 375px + desktop; WCAG 2.1 AA basics; four states on every data view (loading skeleton / empty / error + retry / success).
- Search the frontend bundle for secrets before every release.

## 5. Reporting (to the user)

After each phase: a short report with (a) what shipped, (b) evidence — lint/typecheck/test outputs and the security-review sign-off, (c) what was skipped/stubbed and why, (d) what's next, (e) blockers that need him. No phase is reported as done without its evidence. No excuses — if something is blocked, say exactly what and what unblocks it.

## 6. His action items (not the assistant's)

1. Register **websurfacehq.com** at a registrar (verify it is actually available at checkout — RDAP "no record" is not proof).
2. Create the Supabase project when asked (dashboard step; the schema/migrations will be ready to apply).
3. Create the GitHub repo `Siddharthpeeyush/websurfacehq` if the connector cannot create it.
4. Domain/hosting/promotion stay his per the original split; development stays the assistant's.
5. Apply `supabase/migrations/0005_grants.sql` then `0006_policy_cleanup.sql` live via the dashboard SQL editor (parent), plus the email rate-limit reset — the live re-proof runs after both.

## 7. Cost ledger (blueprint, $0 at MVP)

Vercel Hobby, Render Free (UptimeRobot ping every 14 min to /health), Supabase Free, Upstash Redis Free (~30–50 scans/day), Gemini/Groq Free, Sentry Free, NVD/KEV/EPSS Free. First paid at ~100 scans/day: Redis ~$10/mo, then Render ~$7/mo.
