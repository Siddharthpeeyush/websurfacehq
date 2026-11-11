# ADR-0006: Week 1 foundation decisions (11 Nov 2026)

**Status:** Accepted (coordinator integration pass, Week 1).

## Context

Week 1 builds the foundation: Supabase schema + RLS, Supabase Auth,
central `can()`, FastAPI + Celery skeleton, target verification, SSRF
guard, frontend shell + auth screens. The Supabase project does not exist
yet (owner creates it), so every decision below must work in two modes:
real Supabase when configured, honest degradation when not.

## Decisions

### 1. Verification tokens are stored hashed, never plaintext

`targets` stores `verification_token_hash` (SHA-256 hex), not the
blueprint's `verification_token` column. The raw token is returned to the
user exactly once at target creation. Verification compares the hash of
the published value against the stored hash. Same rule for
`api_keys.key_hash`. A database read must never leak a usable token or key.

### 2. DNS TXT format is `websurfacehq-verify=<token>`

The TXT record lives on the bare domain with exactly that value; the
well-known file is HTTPS-only (`https://<domain>/.well-known/scan-verify.txt`,
exact trimmed match, no HTTP fallback). The blueprint's older
`scan-verify=` prefix is rejected. Token TTL is 7 days; verifying with an
expired token answers 410 `VERIFICATION_EXPIRED`.

### 3. JWTs are verified in the API with PyJWT + SUPABASE_JWT_SECRET

Supabase Auth is the only identity source (no hand-rolled auth). The API
verifies the JWT itself (HS256, exp + sub required, iss/aud/role checked
when present) instead of calling Supabase on every request. Missing
secret → 401, never accept an unverifiable token.

### 4. Auth goes through our API, not supabase-js

Frontend auth screens call `/api/v1/auth/*` (signup/login/logout/reset/
callback/me), which proxy to Supabase GoTrue. Email-link (verification /
reset) codes are exchanged by `POST /api/v1/auth/callback`. This keeps one
auth surface. Consequence: the access token lives in `localStorage`
(MVP trade-off — frontend and API are cross-origin with no shared cookie
domain; httpOnly cookies land when they share a domain). Mitigations: CSP
+ no inline scripts, token never in a URL or log line, cleared on 401.

### 5. Two-layer tenancy: `can()` in the API, RLS in Postgres

Every endpoint calls central `can()`; cross-tenant access returns 404,
never 403. RLS is the second layer for direct DB access. The API's
SupabaseStore connects with the service-role key (RLS bypassed), so
tenancy on the API path rests on `can()` + the store's `user_id` scoping.
Soft-delete is the one place the two layers visibly differ: a plain
`UPDATE deleted_at` fails under the RLS SELECT policy on the user-JWT
path, so the migrations provide SECURITY DEFINER helpers
(`soft_delete_target` etc.) for that path; the service-role store uses a
direct UPDATE (which works because RLS is bypassed, and the helpers check
`auth.uid()`, which is NULL for service-role requests). If the store ever
switches to per-user JWTs, delete MUST switch to the RPC helpers.

### 6. Store protocol with an in-memory implementation for tests

`app/db/store.py` defines the `Store` protocol; `InMemoryStore` is the
tested path (all 150 tests run against it) and the dev fallback when
Supabase is not configured; `SupabaseStore` is the production path.
Selection is explicit and logged. Tests never touch a live database;
the SupabaseStore is untested against a real project until the owner
creates one.

### 7. Scan dispatch is best-effort at creation

`POST /api/v1/scans` creates the scan (`status='queued'`) and then calls
`dispatch_scan()`; if the broker is unreachable the scan stays queued
and the failure is logged — dispatch never fails scan creation. The
worker-side verification gate (not dispatch) is the enforcement point
for unverified targets.

### 8. Celery backoff is 60/120/240s, not the blueprint's 60/300/900s

Celery's native backoff formula is `min(900, 60·2^retries)`; 60/300/900
is not expressible as its doubling formula. Configured as
`retry_backoff=60, retry_backoff_max=900, max_retries=3` and asserted in
tests. The nominal 60/300/900 in the blueprint is superseded by the
realized 60/120/240.

### 9. `connect-src` allows the API origin

The shipped CSP had `connect-src 'self'`, which blocks browser fetches
to the cross-origin API. It now allows one explicit origin from
`NEXT_PUBLIC_API_URL` (dev default `http://localhost:8000`) — never a
wildcard.

### 10. Recorded constants (from the plan, locked Week 1)

Verification token entropy 32 random bytes; token TTL 7 days; signed-URL
expiry 15 min; Free quota 3 scans/month + max 1 active scan; login
rate limit 5 attempts / 15 min per IP + per email.

## Addendum A — Independent review fixes (11 Nov 2026, post-integration)

The Week 1 independent review returned NOT APPROVED (5 High, 10 Medium,
16 Low, no Critical). All 5 Highs and most Mediums/Lows were fixed in
the working tree before the push; the re-review is the gate before the
report back. What changed, by finding:

- **H1 (signup enumeration oracle):** signup now returns the same 201
  `MessageResponse` for a new and an already-registered email; the
  provider returns `None` for a duplicate instead of raising. Round-2:
  duplicate detection matches the stable `AuthApiError.code`
  (`user_already_exists`) first, with the human message only as a
  fallback.
- **H2 (token TTL column):** `token_created_at` renamed to the existing
  `verification_expires_at` everywhere (no schema change).
- **H3 (`scan_jobs.idempotency_key`):** column + index added in
  migration 0004 (the key is functionally unique via
  `UNIQUE(scan_id, stage)`, so the index is not unique).
- **H4 (direct-PostgREST writes):** (a) verification-field changes are
  blocked by a BEFORE UPDATE trigger
  (`targets_prevent_verification_tamper`) for every role except
  service_role and postgres — a column-level REVOKE was tried first and
  REJECTED after the pgserver validation proved it a no-op (a
  table-level UPDATE grant implies UPDATE on every column); (a2) the
  SAME rule on INSERT (`targets_require_unverified_insert` — a fresh
  target must start pending with no verification evidence), added in
  the round-2 fix pass after the re-review PROVED an INSERT bypassed
  the UPDATE triggers (forged verified target via PostgREST); (b) a
  second trigger blocks retargeting a verified target (same
  exemptions); (c) subscriptions + api_keys are user-read-only (their
  user-write policies dropped, INSERT/UPDATE/DELETE revoked from
  authenticated); (c2) scans, findings, scan_jobs, assets, audit_logs
  are not user-writable at all (INSERT/UPDATE/DELETE revoked from
  authenticated — no direct scan inserts, no PATCH of own scan status /
  finding AI fields, no forged audit entries). postgres is exempt from
  both triggers because it is the SQL-editor admin-fix path and the
  database owner (it can drop the trigger anyway).
- **H5 (subscriptions `owner_id`):** the store now filters/maps on
  `owner_id`, not `user_id`.
- **M1 (XFF):** `X-Forwarded-For` is ignored unless
  `TRUST_X_FORWARDED_FOR=true` (trusted reverse proxy only). Round-2:
  the router takes the LEFTMOST entry — correct only if the proxy
  OVERWRITES XFF; if Render appends, take the entry the proxy added.
  VERIFY at Render deploy time (tracked).
- **M2 (logout):** the frontend now calls `POST /api/v1/auth/logout`
  before clearing the local token.
- **M3 (1-domain cap):** enforced at target creation (429
  QUOTA_EXCEEDED; duplicate check runs first, still 409). Round-2: the
  count-then-create race is now closed atomically by the partial unique
  index `targets_one_live_per_user` (migration 0004); the store maps
  the violation to `TargetCapError` → 429. Known gap: `UNIQUE(user_id,
  domain)` still blocks re-adding the SAME domain after a soft-delete
  (tracked follow-up).
- **M4 (quota race):** partial unique index in migration 0004
  (`scans_one_active_per_user_key`); the store maps the violation to
  `ScanConflictError` → 429. The monthly 3/month cap race remains
  (no DB equivalent yet) — atomic counter lands in Week 4.
- **M5 (bounded fetch):** `safe_get` streams with a 64 KiB cap and a
  Content-Length pre-check; `trust_env=False` (direct fetch, never via
  a proxy — a proxy would defeat the SSRF checks, and this VM's proxy
  env breaks httpx's URL parsing). Round-2: the pre-check's raise was
  INSIDE the `except ValueError` handler (UnsafeUrlError subclasses
  ValueError) so it was dead code — the raise now sits outside the try.
- **M6 (rate-limiter wiring):** the Redis limiter is wired at startup
  in staging/production (falls back to in-memory with a loud warning);
  the in-memory dict prunes fully-stale keys past 10,000 entries.
  Round-2: fail-open during a Redis outage is a deliberate logged
  tradeoff — alert on the warning; revisit fail-closed for login in
  Week 2.
- **M7 (lock ownership):** `acquire_vuln_lock` returns a token;
  release is a WATCH/MULTI compare-and-delete (Lua was rejected —
  fakeredis has no EVAL). Round-2: release now retries the WATCH loop
  up to 3 times (fresh pipeline per attempt) instead of returning
  False on the first contention.
- **M8 (cross-tenant audit):** `Store.get_owner()` + router-level
  probe logging — a cross-tenant id still answers 404 but is now
  audit-logged (resource id hashed, never raw).
- **L2/L3/L5/L6/L7/L8/L9/L10/L11/L12/L14/L15/L16:** fixed as listed in
  the coordinator's report (fieldErrors Pydantic-list shape, audit ids
  hashed, per-queue Celery time limits, Redis timeouts + DLQ cap 1000,
  `set_updated_at` search_path, `gotrue` pinned as a direct dep, seed
  hygiene, assert→404, docs-exposure note, reset 502 on provider
  failure, DNS timeout 5s, `can("scan.create")` is the source of truth
  for the verified-target precondition). Round-2 additions: worker
  audit metadata now hashes the scan id too (was raw in the four
  refusal paths); `list_scans` filters soft-deleted scans (both
  stores); `sign_out` uses `trust_env=False` like `safe_get`; the
  celery_app recon comment corrected (the global 1800s ceiling applies
  to recon too).
- **Tracked, not silently closed:** M9 (localStorage token +
  `unsafe-inline` CSP — httpOnly cookies + nonces when frontend and API
  share a domain; Week 2 gate), M10 (SSRF TOCTOU — pinned-IP transport
  before any intrusive scan stage in Week 2), L4 (pagination tiebreak
  on the real path), L12 (store-level tenancy defense). Round-2
  additions: the 23505/index-name mapping in SupabaseStore
  (create_target + create_scan) keys on postgrest-py's error string,
  which is unproven against a live project — if it surfaces
  differently, a cap hit becomes a 500 instead of a 429 (fail-closed,
  wrong status); prove once the migrations are applied. Same-domain
  recreate after soft-delete is blocked by UNIQUE(user_id, domain).
- **Round-3 focused re-check (11 Nov 2026): APPROVED.** Both round-2
  blockers verified closed with independent evidence (reviewer re-ran
  pytest 167, ruff, mypy, web gates, and the 70-check validator itself,
  plus its own pgserver probes). Three new Lows were folded in the
  same pass: (1) `attack_paths` was missing from the 0004 (c2)
  server-table REVOKEs — added, with validator probes (INSERT/DELETE
  blocked, SELECT kept); (2) the INSERT trigger did not check
  `verification_expires_at` / `verification_method` — both added to
  `require_unverified_target_insert`, with probes (harmless as
  implemented — no stored hash means verification can never match —
  but closed as defense in depth); (3) `check_verification_hash`
  crashed with an unhandled 500 when the stored hash is NULL —
  returns `(False, True)` now, with a unit test. The reviewer also
  proved the validator could not prove the REVOKEs (it constructed the
  SELECT-only state itself) — the validator now pre-grants full DML to
  `authenticated` before applying 0004 and asserts the REVOKEs with
  `has_table_privilege` (8 checks); latest run **83/83, 0 failed**,
  API tests **168 passed**. New tracked item: `get_scan` still
  returns soft-deleted scans in both stores (the test pins this as
  accepted; `service_role` bypasses the RLS SELECT policy that hides
  them from user-JWT reads) — a soft-deleted scan stays readable /
  cancellable via the API; flag for a future pass, do not fix silently
  inside a review round.

## Addendum B — Live Supabase project (11 Nov 2026)

The project now EXISTS: **websurfacehq**, ref `dpwfshafzyxyfoktsggo`,
`https://dpwfshafzyxyfoktsggo.supabase.co`, Singapore (ap-southeast-1),
Nano, Healthy (verified in the dashboard). The URL + anon key are wired
into gitignored local env files only (`apps/api/.env`,
`apps/web/.env.local`); `.env.example` keeps placeholders. Live
reachability proven 11 Nov 2026: `GET /auth/v1/settings` returns 200
(email enabled, signup enabled, `mailer_autoconfirm: false` — email
verification is enforced; no OAuth providers enabled). **Not yet
provided:** the service-role key and the JWT secret (deliberately not
retrieved). Until they are set, `supabase_configured` is False, the API
falls back to the in-memory store, auth endpoints answer 503
`SUPABASE_NOT_CONFIGURED`, and JWT verification answers 401 — all by
design, never a silent fallback to the anon key. **Migrations are NOT
applied yet:** no database password / access token / service-role key
exists on this VM, so the parent applies 0001 → 0002 → 0003 → 0004 then
`seed.sql` via the dashboard SQL editor (seed auth users must be created
first with the exact UUIDs in `seed.sql`). The full live auth flow and
the `SupabaseStore` integration tests stay unproven until then.

## Consequences

- The full live auth flow (signup → email verification → login → scan)
  cannot be proven until the Supabase project exists; the API tests prove
  the same flows against the fake provider + real JWT verifier.
- `pip-audit` in CI is the first run that exercises the Python dependency
  audit against the Week 1 requirements (it was skipped in CI runs #1–2
  because `npm audit` failed first).
- `findings.cvss`/`epss` are `numeric(3,1)` / `numeric(5,4)` in the
  migrations, not float (blueprint says "float"; the blueprint's own money
  rule is "never float" and exact decimal is safer here).
- Restore endpoints do not exist yet (the SQL helpers do); account
  deletion + 90-day retention cleanup land in Week 4.
