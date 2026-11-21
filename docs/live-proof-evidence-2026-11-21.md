# Admin foundation — live-proof evidence (Sat 21 Nov 2026, ~01:00–04:00 IST)

**Status: COMPLETE.** §2 Steps 1–6 + H1 re-probe + Step 8 cleanup all
PROVEN live in run 26 (21 Nov ~03:xx IST, exit 0, 0 failures — 101 checks).
Migration 0007 applied live 01:05 IST; seed Auth users restored 01:09 IST
(and soft-deleted a third time since — see §11). The admin-foundation
live proof is DONE; the push + PR follow from this record.

Code under test: admin-foundation branch content in the working tree
(main head 9a81b8fe; PR #1 Week 2 recon merged 20 Nov 21:33 IST).
Reviews + red team APPROVED 20 Nov (coordinator 1). The live-proof doc's
stale header ("Do NOT push anything yet — independent review + red-team
still to come") is superseded: reviews and red team are DONE. The push
still waits for the migration + §2 Steps 1–6.

## 1. Reconciliation (working tree vs remote main @ 9a81b8fe)

- Remote tree: 164 files (GitHub API, 21 Nov 01:05 IST).
- 16 files DIFFER from main (admin-foundation edits to existing files):
  `.env.example`, `AGENTS.md`, `apps/api/app/auth/jwt.py`,
  `apps/api/app/auth/permissions.py`, `apps/api/app/auth/provider.py`,
  `apps/api/app/auth/rate_limit.py`, `apps/api/app/core/config.py`,
  `apps/api/app/db/memory.py`, `apps/api/app/db/store.py`,
  `apps/api/app/db/supabase_store.py`, `apps/api/app/main.py`,
  `apps/api/tests/test_auth.py`, `apps/api/tests/test_permissions.py`,
  `apps/api/tests/test_store.py`, `apps/api/tests/test_supabase_store.py`,
  `supabase/validate_migrations.py`.
- 25 LOCAL-ONLY new files (the push manifest's additions):
  `apps/api/app/auth/mfa.py`, `apps/api/app/auth/sessions.py`,
  `apps/api/app/core/staff_prefix.py`, `apps/api/app/routers/admin.py`,
  `apps/api/app/routers/admin_ops.py`, `apps/api/app/routers/staff_auth.py`,
  `apps/api/app/services/audit.py`, `apps/api/app/services/invites.py`,
  `apps/api/app/services/staff.py`, `apps/api/tests/test_admin.py`,
  `apps/api/tests/test_admin_matrix.py`, `apps/api/tests/test_audit.py`,
  `apps/api/tests/test_invites.py`, `apps/api/tests/test_mfa.py`,
  `apps/api/tests/test_sessions.py`, `apps/api/tests/test_staff_auth.py`,
  `apps/web/src/app/staff-invite/page.tsx`,
  `apps/web/src/app/staff-login/page.tsx`,
  `apps/web/src/app/staff-mfa-setup/page.tsx`,
  `apps/web/src/lib/staff-api.ts`, `apps/web/src/middleware.ts`,
  `docs/admin-foundation-live-proof.md`, `docs/admin-foundation-plan.md`,
  `docs/decisions/adr-0010-admin-foundation.md`,
  `supabase/migrations/0007_admin_foundation.sql`.
- Push manifest = 16 differing + 25 new = **41 files**. Never include
  `.github/workflows/ci.yml`.
- Stale `apps/web/.eslintrc.json`: already gone (deleted in the working
  tree; `ls` confirms absent). Nothing to delete.
- Doc §1 SQL vs `supabase/migrations/0007_admin_foundation.sql`:
  **byte-identical** (diff clean, 21 Nov 01:05 IST).

## 2. Gates re-verified independently (21 Nov ~01:10 IST)

- `ruff check .` — all checks passed.
- `ruff format --check .` — 79 files already formatted.
- `mypy .` — no issues found in 77 source files.
- `pytest -q` — **492 passed** in 44.5s (1 unrelated deprecation
  warning: `httpx` with `starlette.testclient`).
- Web: `npm run lint` clean, `npm run typecheck` clean,
  `npm run build` green — 11/11 pages (incl. new `/staff-invite`,
  `/staff-login`, `/staff-mfa-setup`).
- Migration validator `supabase/validate_migrations.py` on a fresh
  ephemeral DB — **428/428 checks passed, 0 failed** (re-run 21 Nov).

## 3. Live Supabase state before the migration

- REST probe (anon key) for `staff_roles` / `staff_invites` /
  `staff_sessions` / `admin_settings` → all **404 PGRST205**
  ("Could not find the table ... in the schema cache").
  **Migration 0007 is NOT applied live.**
- Public seed counts via PostgREST (service_role) are EXACTLY the seed
  counts: targets 2, scans 2, assets 4, findings 4, scan_jobs 2,
  audit_logs 2, subscriptions 2, teams 1, team_members 1, api_keys 2,
  notifications 2, support_tickets 2, attack_paths 2.

## 4. Local proof harness (local API server vs LIVE Supabase)

Server: `uvicorn app.main:app` on 127.0.0.1:8000, env from gitignored
`apps/api/.env` (live project `dpwfshafzyxyfoktsggo`), `STAFF_URL_PREFIX`
= fresh 22-char (128-bit) value in SHELL ENV ONLY — never written to
any file (server log checked: 0 hits for the prefix value; log deleted
afterwards). `API_PUBLIC_URL=http://127.0.0.1:8000`.

- `GET /health` → 200 `{"status":"degraded","components":{"database":
  {"status":"ok","detail":"supabase reachable"},"redis":
  {"status":"unreachable"},"queue":{"status":"not_configured",
  "detail":"celery worker not wired yet (Week 1)"}}}` — degraded is
  the known Week 1 pattern (no Redis broker); database ok.
- `GET /live` → 200.
- `POST /<prefix>/staff/auth/login` (dummy owner creds) → **500**
  `{"code":"INTERNAL_ERROR","message":"Internal server error"}` —
  server log shows **PGRST205 ×2** (missing `staff_roles` table).
  Routing + prefix + host gate all passed; only the unapplied
  migration fails it. The public 500 body is correctly generic
  (no internals leaked).
- `POST /staff/auth/login` (bare, no prefix) → **404** (prefix enforced).
- `POST /<prefix>/staff/auth/login` with `Host: evil.example.com` →
  **404** (host gate enforced, M3 fix live).
- Server stopped cleanly afterwards; port 8000 free.

## 5. Signup-201 close-out — CLOSED (Week 1 open item 1)

- ONE attempt, 21 Nov ~01:20 IST: `POST /api/v1/auth/signup`
  `peeyushsiddharth+wshq-signup-20261121@gmail.com` → **201**
  `{"message":"If this email is new, a verification link has been
  sent. Check your inbox."}`.
- GoTrue Admin API lookup found exactly 1 user with that email
  (`email_confirmed_at: null`, unconfirmed as expected).
- `DELETE /auth/v1/admin/users/<id>` → **200**; re-list confirms
  **0 test users remaining**. Item CLOSED.
- Note: a confirmation email was sent to the owner's +alias inbox;
  the account is deleted, so the link is dead. Harmless; mention it
  if he asks about the mail.

## 6. FINDING — seed Auth users soft-deleted AGAIN

- GoTrue Admin API `GET /auth/v1/admin/users` lists **0 users** in
  the live project (confirmed twice).
- Public seed rows are intact (see §3 counts), so the two seed Auth
  users (`11111111-…` / `22222222-…`, restored 12 Nov 2026) were
  NOT hard-deleted — a hard delete would have cascade-wiped the
  public seed rows. They are soft-deleted again (`deleted_at` set;
  GoTrue hides them from the Admin list). Actor/timing unknown —
  same unexplained phenomenon as 12 Nov (second occurrence).
- Does NOT block the §2 proof (Step 1 creates a fresh Owner
  account). Restore opportunistically in the same dashboard session
  as the migration (idempotent — same statement as 12 Nov):
  `UPDATE auth.users SET deleted_at = NULL WHERE id IN
  ('11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222');`
  then verify with
  `SELECT id, email, deleted_at FROM auth.users WHERE id IN
  ('11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222');` → exactly 2 rows,
  both `deleted_at` NULL.

## 7. BLOCKER — dashboard step (for the parent / browser task)

**DONE 21 Nov 01:05 IST.** Migration 0007 applied live via the dashboard
SQL editor ("Success. No rows returned"); seed-restore UPDATE + §3
verification queries run 01:09–01:12 IST (all green — see §9). The
hCaptcha did not block. This section is retained for the record only.

## 8. Still to do after the migration (not yet proven)

**DONE — see §9–§12 below.** Doc §2 Steps 1–6, H1, and Step 8 cleanup
are all proven live in run 26. Doc §2 Step 7 (customer/staff host 404s)
was proven by coordinator 2 (§4 above: bare staff login 404,
foreign-host 404). Remaining: push the manifest to branch
`admin-foundation`, verify every file by remote blob SHA, update the
sync record, open PR `admin-foundation -> main` (do NOT merge —
owner's go).

## 9. §3 verification queries — all green (21 Nov 01:12 IST)

- 4 staff tables RLS on (`staff_roles`, `staff_invites`,
  `staff_sessions`, `admin_settings` — via `pg_class.relrowsecurity`;
  the live-proof doc §3 Q1 was corrected: `information_schema.tables`
  has no `row_security` column).
- `staff_roles` 9 columns incl. factor ids; single-Owner partial
  unique index present; `prefix_version='1'`; staff tables empty
  (0 rows — correct, no staff existed yet); `audit_logs` holds the
  2 Week 1 seed rows.

## 10. Coordinator-3 live proof — COMPLETE (run 26, 21 Nov ~03:xx IST)

Proof driver: `~/workspace/wshq-proof/wshq_proof.py` (rebuilt 21 Nov
after a service restart wiped `/tmp`, destroying the original driver
and all run outputs; behaviour faithful to the original, runs 7–19,
with every fix below incorporated). Local API server vs LIVE
Supabase; `STAFF_URL_PREFIX` = fresh 22-hex (128-bit) value in shell
env only, never written to any file. **Run 26: exit 0, 0 failures —
101 checks PASS** (Step 1: 6, H1: 16, Step 2: 15, Step 3: 18,
Step 4: 10, Step 5: 10, Step 6: 13, Step 8: 11, done: 2).

### H1 — timing re-probe (unknown vs known email)
- Unknown email (`nobody-unknown-xyz@example.com`) 5 attempts → 401,
  bodies byte-identical; 6th → 429. Known email (Owner) 5 attempts →
  401, bodies byte-identical; 6th → 429. **No enumeration oracle in
  the body; the 429 limiter proven on both sides.**
- Medians (informational): unknown 3600.5 ms, known 3319.8 ms,
  diff 280.8 ms — **INCONCLUSIVE (proxy noise)**, same as every prior
  run (diffs 911 ms, 3.4 ms, 481 ms, 208.5 ms with a direction flip).
  The code-level dummy (75 ms) vs bcrypt (59/73/90 ms) stands.
  **Week 3 re-probe from the deployed env** (no proxy noise) is the
  remaining nicety.

### Step 1 — first Owner
- Owner Auth user `peeyushsiddharth@gmail.com` created via GoTrue
  Admin API (email confirmed at creation); exactly **one** Owner row
  in `staff_roles`. Random password (never recorded); the owner resets
  it via the forgot-password email link.
- MFA-dirty recovery proven: a prior run's verified factor (secret
  lost with that process) is deleted via the GoTrue Admin API
  (`DELETE /auth/v1/admin/users/{id}/factors/{factor_id}` → 200) and
  the stored factor ids cleared — the ONLY clean path, because a
  VERIFIED factor cannot be unenrolled with AAL1 (GoTrue 422
  `insufficient_aal`, proven live) and the Owner Auth user cannot be
  hard-deleted once audit rows exist (see Step 8).

### Step 2 — Owner login + MFA enrollment
- Login 200 → `mfa_required` + `enroll_required`, no session yet.
- Enroll 200; confirm 200 → staff session issued; `GET /admin/me`
  200, role `owner`. `/health` database `ok` (overall `degraded` =
  known Week 1 pattern: no Redis broker). `/live` 200.
- Stale unverified GoTrue factors are self-healed before enroll
  (the app enroll 502s on GoTrue's friendly-name conflict while a
  stale factor exists; correct unenroll path is
  `DELETE /auth/v1/factors/{id}` — the `/auth/v1/user/factors/{id}`
  path 404s).

### Step 3 — invite Admin + Support
- Admin (`peeyushsiddharth+wshq-admin@gmail.com`) + Support
  (`peeyushsiddharth+wshq-support@gmail.com`) test accounts: invite
  201, accept 201, **token reuse → 404 byte-identical to an invalid
  token's 404** (single-use proven). Both confirmed via the GoTrue
  Admin API (recorded deviation — the confirmation email would need
  the owner's tap on his +alias inbox).
- GoTrue sign-up 429 (per-IP on the shared egress proxy) consumes the
  token (claimed before sign_up); the driver re-invites + retries
  (up to 3 attempts). Reused accounts get a password reset + the
  Step 1 MFA-dirty recovery via the Admin API, and a missing
  `staff_roles` row (deleted by a prior run's cleanup) is re-inserted.
- Admin + Support login 200 → `enroll_required`; MFA enrolled +
  sessions issued for both.

### Step 4 — role boundaries
- Admin `/admin/founder` → **403**. Support `/admin/users` → **403**.
  Support `/admin/founder` → **403**.
- Support `/admin/support/tickets` → **503** and `/admin/abuse` →
  **503** — the documented honest-503 scaffolding (see §11); the
  ROLE CHECK is proven by the 403/503 split (a 503 means
  `require_staff` passed and the request reached the store).
- Owner `/admin/founder` without step-up → **403** with code
  `STEP_UP_REQUIRED` (field is `code`, not `error`).
- Step-up verify → **200** `step_up_verified: true` (1 round);
  Owner `/admin/founder` after step-up → **200** with honest figures
  (`total_scans`, `total_staff`, `total_subscriptions`,
  `business_figures_note`, …).

### Step 5 — audit rows + append-only trigger
- Audit rows present, one per action: `staff.login`,
  `staff.mfa_enrolled`, `staff.invite_created`,
  `staff.invite_accepted`, `staff.step_up_verified` (the invite rows
  checked anywhere in history — reused accounts mean no NEW invite
  in this run). `staff.mfa_verified` is written by `/mfa/verify`
  (Step 6) and checked there.
- **UPDATE `audit_logs` → ERROR** (append-only trigger) and the row
  is unchanged afterwards. **DELETE `audit_logs` → ERROR** (same
  trigger). Append-only proven live.

### Step 6 — prefix rotation invalidates sessions
- `GET /admin/settings` → `staff_prefix_version` 3; rotate (with
  `{"confirm": true}`) → **200**, `prefix_version` **3 → 4**,
  `staff_sessions_invalidated: true`.
- Old Owner session → **401**; old Admin session → **401**.
- Re-login Owner + Admin (login + MFA verify) → fresh sessions,
  `/admin/me` **200** for both. `staff.mfa_verified` audit row
  present.
- Honest limit: rotation bumps the persisted version; the URL path
  string changes only via a hosting env change + restart.

### Step 8 — cleanup
- Product delete endpoint (`POST /admin/users/{id}/delete`,
  `{"confirm": true}`) → 200 for Admin + Support staff rows.
- Deleted Admin login → **401**; deleted Support login → **401**
  (inert — no staff row, the staff login cannot proceed).
- Owner MFA reset to unenrolled: product `mfa-re-enroll` → 200 (DB
  factor ids cleared) + the GoTrue factor deleted via the Admin API
  (1 factor deleted) — **clean unenrolled state, so the owner enrolls
  MFA himself on his own phone at first staff login**. He resets his
  password via the forgot-password email link; no password or TOTP
  secret ever crossed chat/docs/memory.
- GoTrue users = **3** (Owner + 2 inert test Auth users); the 2 seed
  Auth users are soft-deleted AGAIN (3rd occurrence — see §11).
  Public seed rows intact (`targets` == 2). Exactly **one** staff
  row remains: the Owner.

## 11. Findings established during the coordinator-3 runs

### MFA 401 saga — ROOT CAUSE FOUND AND FIXED (21 Nov ~02:30–02:45 IST)
- Symptom: app MFA enroll 200, confirm 401 on every attempt across
  many runs (runs 7, 10, 11, 12 failed 5–6 attempts each). TOTP
  verified correct against RFC 6238 vectors; VM clock within ~1 s
  of Supabase; the secret proven correct (direct GoTrue verify with
  the same secret → 200).
- Root cause (proven via a temporary diagnostic log of GoTrue's
  error body, since reverted): GoTrue verify 422
  **`mfa_ip_address_mismatch`** — GoTrue binds an MFA challenge to
  the IP that created it and rejects a verify from a different IP.
  The app's MFA backend created a FRESH httpx client per GoTrue
  call, and this VM's egress proxy rotates public IPs per connection
  (proven live: 6 fresh clients exited via 5 different IPs; one
  shared client via 1 IP). So challenge and verify usually exited
  via different IPs. Direct GoTrue verifies worked because they used
  one shared client (connection reuse → same IP).
- Fix (product change, `apps/api/app/auth/mfa.py` only): one shared
  httpx client for all MFA GoTrue calls (`_get_shared_mfa_client`,
  double-checked locking); the cached client is keyed on the factory
  function object so tests that monkeypatch
  `proxy_safe_httpx_client` still get their stub (no test edited).
  The temporary `gotrue_body` diagnostic log edit was REVERTED.
  Gates after fix: ruff clean, `ruff format` clean, mypy clean
  (77 files), pytest **492 passed**, MFA tests 27 passed.
- **Independent review: APPROVED** (reviewer subagent, 21 Nov
  ~02:45 IST — no Critical/High/Medium findings). Non-blocking
  Lows, all accepted as residuals, no action now:
  - L1 — connection reuse is opportunistic, not guaranteed (a
    concurrent MFA request could open another pooled connection in
    the ms window between challenge and verify → 422 again).
    Reliability residual, not a security hole; staff MFA volume is
    a handful of logins/day.
  - L2 — replaced cached client is never closed; no shutdown close
    (reachable only under test monkeypatching in practice).
  - L3 — shared client carries a cookie jar (GoTrue sets no
    cookies, so it stays empty in practice; latent only).
  - L4 — informational: single egress IP concentrates MFA traffic
    (negligible for staff volume; 429 mapping unchanged).
- Verification of the fix: isolated experiment (single immediate
  confirm) → **200 on first attempt**; full proof run 26 confirms
  it end to end (Step 2 confirm, Step 3 confirms, Step 4 step-up
  all 200).

### Prefix in server logs — NEW finding (Low)
- The secret staff prefix appears in the server log on **every**
  staff request: **90 hits** in run 26's log (2 lines/request: the
  app request log + the uvicorn access log). Coordinator 2's "0
  hits" claim was wrong. **Week 3 hardening: redact the prefix
  segment from the app + uvicorn logs.**

### Admin list endpoints honestly 503 live — KNOWN GAP (scaffolding)
- `GET /admin/support/tickets`, `/admin/abuse`, `/admin/scans`,
  `/admin/billing` (subscriptions) return **503
  `STAFF_DATA_UNAVAILABLE`** live: the SupabaseStore never
  implemented the admin list methods (`list_all_support_tickets`,
  `list_abuse_reports`, `list_all_scans`,
  `list_all_subscriptions` — only the test fake has them) and **no
  abuse table exists in any migration**. The admin-foundation
  review APPROVED this state ("honest 503s"). The role boundaries
  ARE proven (403 for unauthorized roles; 503 means the role check
  passed). Implementing the admin list data layer (incl. a schema
  decision for abuse reports) is a **Week 3/4 follow-up**. A 200
  here would only return an empty list anyway (no tickets/abuse/
  scans exist yet).

### Seed Auth users soft-deleted AGAIN — 3rd occurrence
- The 2 seed Auth users (`11111111-…` / `22222222-…`, restored
  21 Nov 01:09 IST) are soft-deleted again (absent from the GoTrue
  Admin list in run 26's cleanup). Actor/timing unknown — same
  unexplained phenomenon as 12 Nov and 21 Nov 01:09. Public seed
  rows intact (`targets` == 2), so no cascade fired. Functionally
  inert. Restore opportunistically via the dashboard SQL editor
  (same statement as §6); does not block the proof or the PR.

### Driver bugs fixed during the runs (proof harness only, not product)
- Reused test accounts: password reset via Admin API (the prior
  run's password died with that process) + MFA-dirty recovery +
  re-insert of a `staff_roles` row deleted by a prior cleanup.
- `mfa_enroll_confirm` wrote the secret into the `owner_secret`
  global, so Step 3's Admin/Support enrolls silently clobbered the
  Owner's secret and Step 4's step-up verify computed TOTP from the
  Support's secret (run 19: 3 rounds of "Invalid verification
  code"). Fixed: the helper now uses locals only and returns
  `(session, secret)`.
- Step-up 403 check read `error` instead of `code` (the API's error
  body uses `code`).
- Rotate-prefix and staff-delete are destructive actions requiring
  `{"confirm": true}` (two-step confirm) — a bare POST 422s.
- Step 6's prefix-version check is now a bump of +1 from the
  current version (a prior run may already have rotated it).
- Step 5's invite-row check queries per-action (reused accounts
  mean no NEW invite in the run; the rows live in earlier history).
- `staff.mfa_verified` is only written by `/mfa/verify` (Step 6),
  so it is checked in Step 6, not Step 5.
- H1's unknown email must be a syntactically valid address
  (`@example.com`, not `.invalid` — pydantic `EmailStr` 422s the
  `.invalid` TLD).
- `/tmp` wipe (service restart, 21 Nov ~03:xx IST) destroyed the
  original driver + all run outputs; the driver was rebuilt at
  `~/workspace/wshq-proof/wshq_proof.py` (durable location, outside
  the repo so it is never pushed) and the full proof re-run from
  scratch (runs 20–26). Run outputs live in `~/workspace/wshq-proof/`.

## 12. Honest gaps carried into the PR description

- Full hosted proof NOT provable (no domain registered, no
  Render/Vercel deployments — Week 4 scope).
- F4 production limit (unknown-email failed-login audit rows fail
  the FK on `audit_logs.user_id` NOT NULL, stay log-lines-only in
  prod — needs a schema change, Week 3 item).
- N1 (bearer UUIDs in localStorage), N-NEW4 (password-only MFA
  enrollment on a never-enrolled account), F7 (`enroll_required`
  leaks enrollment state to a password holder) residuals.
- 375px overflow re-check for staff pages still open.
- Admin list endpoints honestly 503 live (see §11); prefix in
  server logs (see §11); H1 median inconclusive (see §10).
- MFA shared-client review Lows L1–L4 accepted as residuals
  (see §11).
