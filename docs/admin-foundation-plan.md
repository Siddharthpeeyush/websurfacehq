# Admin foundation — build plan (Fri 20 Nov 2026, resumption)

**Status:** PLAN. Implementation follows the repo working loop: plan → review →
small steps on a branch → lint + typecheck + tests → review diff → independent
security review → live proof → PR. Branch: `admin-foundation` (from main @
`9a81b8fe`). Do NOT push straight to main. NEVER include
`.github/workflows/ci.yml` in any push-files manifest.

**Spec sources (read before writing code):**
- `~/workspace/websurfacehq-brand/DESIGN-LOCK.md` — "Admin panel + Founder
  screen (LOCKED 14 Nov 2026)" section + "LOCKED FOR DEVELOPMENT (15 Nov 2026,
  00:12 IST)" freeze + secret-staff-address bullet + staff-sessions bullet.
- Visual spec: `~/workspace/websurfacehq-brand/kavora/websurfacehq-kavora-admin.html`
  (9 screens; the prototype is the VISUAL spec — build the REAL backend + API,
  do not copy it as code; screens wire to real data as Weeks 2–4 land theirs).
- Repo rules: `AGENTS.md` ("Standing quality order" — triple-angle gate),
  `ENGINEERING-PLAN.md` §2 (10 security rules) + §4 (quality gates).

**State (Step 0, verified 20 Nov 2026):** local tree is byte-identical to merged
main `9a81b8fe` (blob-SHA comparison, 0 drift). Stale git-index entry for
`apps/web/.eslintrc.json` removed (file was deleted in the Next 16 migration and
does not exist on disk or on remote — do NOT re-create or push it). ADR-0008
(billing) and ADR-0009 (Week 2 recon) are on main.

## 1. Locked design decisions (do not re-decide)

- Platform roles **Owner / Admin / Support**, separate from team roles.
  Support sees Support + Abuse screens only. Admin on `/founder` → 403.
- Audit log is **append-only**: every admin action writes (actor, action,
  target, before/after, IP, timestamp). No update/delete path for audit rows
  (Week 1 pattern: triggers + REVOKEs, validator-proof).
- **MFA (TOTP via Supabase Auth MFA) enforced for all staff sessions**; setup
  during invite onboarding; re-enrollment is an Owner power.
- **Step-up MFA for Founder: flag `STAFF_STEP_UP_MFA`, DEFAULT ON** (owner
  decision still open; ON is the recommended default). One-line toggle.
  When on, opening Founder requires a fresh MFA check once per session.
- **Two doors:** customers `websurfacehq.com` (`/login`, `/dashboard`,
  `/signup`); staff `admin.websurfacehq.com` under a **secret random path
  prefix** (128-bit, generated at setup, server config only, never in
  repo/docs/chat). Everything outside the prefix on the staff subdomain
  answers a generic 404. No links / sitemap / noindex / no-referrer on staff
  pages. Supabase redirect allowlist uses wildcard
  `https://admin.websurfacehq.com/**` so rotation never breaks invites.
  Owner rotates the prefix from Settings (Founder-only, audit-logged);
  rotation signs all staff out. Web wiring (NEW1 fix, 20 Nov 2026):
  the web middleware serves staff pages under the prefix by internal
  rewrite to the bare route, and staff API calls go same-origin
  `/api/staff/*`, proxied server-side to the API with the prefix added
  by the middleware — the browser never sees the prefix
  (`STAFF_API_URL` + `STAFF_URL_PREFIX`, server env only, same prefix
  value on both deployments; see `docs/admin-foundation-live-proof.md`
  §5). Staff-page-to-staff-page links are relative so the prefix
  survives navigation.
- **Staff accounts:** Owner alone creates/suspends/deletes/re-roles staff
  (Settings → Roles, audit-logged). Invite links **single-use, 72h expiry**;
  staff set their OWN password + MFA (Owner never sees/sets passwords).
  Suspend/delete revokes sessions instantly; audit history kept. Force
  password reset, revoke sessions, MFA re-enrollment are Owner powers.
  Staff login is **SIGN-IN ONLY** (no self-registration); forgot-password
  (email) stays for recovery. First Owner account created once at setup.
- **Role-first staff login:** page asks the role first (Owner / Admin /
  Support cards, none pre-selected, button names the chosen role). The server
  verifies the account's REAL role and refuses a mismatch with the SAME
  generic error as a wrong password (no enumeration — messages AND timing).
- **Staff sessions:** absolute lifetime 12h; idle 60 min → sign in again;
  TOTP at EVERY staff sign-in; no trusted-device bypass; session cookies
  scoped to the staff subdomain + secret prefix; prefix rotation invalidates
  all staff sessions.
- **No "login as user"** — read-only support view only (evidence redacted,
  every view logged). Customer accounts at the staff door → same generic
  error as a wrong password.
- Owner-only destructive actions (delete tenant, refunds, role grants, kill
  switches, maintenance mode) need two-step confirm.
- **Out of scope:** the 9 screens' full UI (Weeks 3–4), Week 3 vuln/triage,
  billing implementation (Week 4, ADR-0008), scheduled scans, team roles,
  authenticated scanning. Week 2 residuals (live smoke test, screenshots,
  request counting, queue-naming one-liner) carry into Week 3.

## 2. Data model (migration 0007_admin_foundation.sql)

- `staff_roles`: `user_id` UUID PK (FK to `auth.users`), `role`
  `owner|admin|support`, `status` `active|suspended`, `invited_by` UUID,
  `created_at`, `updated_at`. RLS: service_role full; authenticated none
  (server reads via service_role only — staff role is NEVER trusted from the
  client). UPDATE/DELETE restricted to service_role; a trigger blocks any
  attempt to set two Owners (exactly one Owner row, enforced in DB).
- `staff_invites`: `id`, `token_hash` (SHA-256, never the raw token),
  `email`, `role`, `invited_by`, `expires_at` (created + 72h), `used_at`
  NULL, `created_at`. Single-use enforced by `used_at IS NULL` check +
  atomic claim (UPDATE … WHERE used_at IS NULL RETURNING). Expired/used
  tokens are indistinguishable from invalid ones in API responses.
- `staff_sessions`: `id`, `user_id`, `issued_at`, `last_seen_at`,
  `revoked_at` NULL, `ip`, `user_agent`, `prefix_version` (int — bumped on
  every prefix rotation; sessions with an older version are dead).
- `audit_logs` (exists, Week 1): extend with a trigger blocking UPDATE and
  DELETE on audit rows + REVOKE UPDATE/DELETE from all roles; validator
  asserts the blocks hold. Audit writes go through the service only.
- Validator: extend `supabase/validate_migrations.py` — fresh DB, NO
  pre-grant; assert grants present AND revokes/triggers holding (the Week 1
  lesson: a validator that pre-grants is blind).

## 3. API contracts (fixed — children build to these, do not renegotiate)

Auth (staff door; all responses use the one standard error shape):
- `POST /staff/auth/login` `{role, email, password}` → 200 `{mfa_required:
  bool, session?}` or 401 generic `INVALID_CREDENTIALS` (same message, same
  code, for wrong password / wrong role / unknown email / suspended account;
  do the password check and the role check in constant-order work — never
  short-circuit in a way that leaks which check failed via timing; hash
  comparison always runs).
- `POST /staff/auth/mfa/verify` `{challenge_id, code}` → session on success.
- `POST /staff/auth/mfa/enroll` (authed) → `{qr_uri, secret}` — secret shown
  ONCE; `POST /staff/auth/mfa/confirm` `{code}` activates.
- `POST /staff/auth/logout` → revokes the session row.
- `POST /staff/auth/forgot-password` `{email}` → always 200 (no enumeration).
- `POST /staff/auth/invite/accept` `{token, password}` → creates the Auth
  user, sets `staff_roles`, starts MFA enrollment; token single-use + 72h.
- `POST /staff/auth/step-up/verify` `{code}` → marks the session
  step-up-verified (Founder gate, when the flag is on).

Admin (all under `/admin`, all require a valid staff session + `can()`):
- `GET /admin/me` → own staff profile + role + MFA status.
- Users: `GET /admin/users`, `GET /admin/users/{id}`,
  `POST /admin/users/invite` (Owner only), `POST /admin/users/{id}/suspend`,
  `POST /admin/users/{id}/delete` (Owner only, two-step confirmed client-side),
  `POST /admin/users/{id}/role` (Owner only),
  `POST /admin/users/{id}/revoke-sessions`, `POST /admin/users/{id}/force-reset`,
  `POST /admin/users/{id}/mfa-re-enroll` (all Owner only unless noted).
- `GET /admin/scans`, `GET /admin/scans/queue` (real Celery queue depths +
  DLQ counts), `GET /admin/billing` (read-only summaries from subscriptions;
  NO payment actions this phase), `GET /admin/abuse`, `GET /admin/support/tickets`,
  `GET /admin/security` (login events, API keys, active sessions),
  `GET /admin/system/audit` (filters: actor, action, date, search),
  `GET|POST /admin/settings` (flags, quotas; prefix rotation
  `POST /admin/settings/rotate-prefix`, Founder-only),
  `GET /admin/founder` (Owner only + step-up MFA when the flag is on).
- Every admin action writes an audit row via the audit service. No endpoint
  returns fake/demo data. Lists use cursor pagination; one error format.

Config (new keys in `.env.example`, placeholders only):
- `STAFF_URL_PREFIX` (128-bit random, generated at setup; empty = prefix
  enforcement OFF in local dev only — production refuses to start without it).
- `STAFF_STEP_UP_MFA=true` (default on; one-line toggle).
- `STAFF_SESSION_ABSOLUTE_HOURS=12`, `STAFF_SESSION_IDLE_MINUTES=60`.

## 4. Work split (strict file ownership — no two children touch the same file)

- **Child A — schema + roles + audit:** `supabase/migrations/0007_admin_foundation.sql`,
  `supabase/validate_migrations.py` (extend), `apps/api/app/auth/permissions.py`
  (platform-role `can()`), `apps/api/app/services/audit.py` (new),
  `apps/api/app/db/store.py` (append audit methods ONLY),
  `apps/api/tests/test_audit.py` (new), `apps/api/tests/test_permissions.py`.
- **Child B — MFA + sessions + iat leeway:** `apps/api/app/auth/mfa.py` (new),
  `apps/api/app/auth/sessions.py` (new), `apps/api/app/auth/jwt.py`
  (add `leeway=5` to `jwt.decode` + regression test),
  `apps/api/app/auth/provider.py` (MFA hooks ONLY),
  `apps/api/app/core/config.py` (new staff settings),
  `apps/api/tests/test_mfa.py`, `apps/api/tests/test_sessions.py` (new).
  Also owns the signup-201 close-out? NO — that goes to Child F (live checks).
- **Child C — staff accounts + invites + role-first login + prefix:**
  `apps/api/app/services/invites.py` (new), `apps/api/app/services/staff.py`
  (new), `apps/api/app/routers/staff_auth.py` (new),
  `apps/api/app/core/staff_prefix.py` (new),
  `apps/api/tests/test_staff_auth.py`, `apps/api/tests/test_invites.py` (new).
  C uses A's `can()` + audit service and B's MFA/session functions — does NOT
  edit their files; if an interface is missing, note it in the report, do not
  work around it silently.
- **Child D — admin API scaffolding:** `apps/api/app/routers/admin.py` (new;
  split into `admin_*.py` only if it exceeds ~600 lines),
  `apps/api/app/main.py` (mount `staff_auth` + `admin` routers ONLY — no other
  edits), `apps/api/tests/test_admin.py` (new).
- **Child E — staff login page (web):** `apps/web/src/app/staff-login/page.tsx`
  (new; role-first cards, Kavora tokens), `apps/web/src/lib/staff-api.ts`
  (new), `apps/web/src/middleware.ts` (new; Host-based routing — admin
  subdomain serves staff pages only, customer host never serves them).
  E touches NO other web files. Mobile 375px + desktop; four states on any
  data view; no secrets in the bundle.
- **Child F — integration + matrix + gates + live checks (AFTER A–E return):**
  401/403/404 matrix per new endpoint, cross-tenant 404s, role-confusion
  tests (customer at staff door, Support on /founder, role-picker spoof,
  invite reuse/expiry, session expiry/idle, prefix rotation invalidates
  sessions), timing-enumeration probe, full gate run with CI's exact commands
  (`ruff check`, `ruff format --check`, `mypy .`, full `pytest`, web
  lint/typecheck/build). Signup-201 close-out: ONE live signup attempt with a
  fresh address against the live API (GoTrue window long reset); if 502,
  capture the REDACTED GoTrue 400 body; do not retry; delete the test user
  afterwards via the Admin API.
- **Reviewer (independent security review, AFTER F):** separate agent reviews
  the diff + gates; APPROVED required before push. Fix High/Medium or explain
  in writing why not.
- **Red-team (attacker angle, AFTER reviewer fixes):** tries to break the
  running API (auth bypass, role confusion, privilege escalation, enumeration
  incl. timing, session theft/fixation, CSRF, SSRF, invite reuse, MFA bypass,
  secret-prefix guessing). Records every attempt + outcome. Findings go back
  for fix + re-verify.
- **Push child (AFTER live proof):** branch `admin-foundation` + PR via
  push-files (NEVER ci.yml); verify every file by remote blob SHA; update the
  sync record only for files whose writes succeeded; PR description carries
  gate results, review status, honest gaps.

## 5. Gates (all must pass before the coordinator reports done)

- Playbook loop + do-not-fool-me check per child (lint/typecheck/test output
  shown; files changed + why; skipped/stubbed/mocked listed; assumptions
  listed). Never edit a test to make it pass. Never report done with a
  failing/skipped test or a known failure.
- Exact CI commands green (see §4 Child F).
- Independent security review APPROVED. Triple-angle verification
  (developer / attacker / customer) complete with evidence; anything found
  fixed AND re-verified at all three angles.
- Live proof (coordinator + parent): migration 0007 applied via the dashboard
  SQL editor (parent feeds verbatim SQL to the browser task); then prove live
  against Supabase project `dpwfshafzyxyfoktsggo`: invite → setup → login
  with role → MFA → Founder as Owner / 403 as Admin / queue-only as Support;
  audit rows written; prefix rotation invalidates sessions. The VM has no DB
  password — dashboard SQL editor only.
- ADR: `docs/decisions/adr-0010-admin-foundation.md` (coordinator writes
  after implementation, from what was actually built) + `AGENTS.md` updated.
