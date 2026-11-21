# Admin foundation — live-proof handoff (Child F, Fri 20 Nov 2026)

For the coordinator / parent: the parent feeds §1 to the browser task for
the dashboard SQL editor, then runs §2 against the live project
(`dpwfshafzyxyfoktsggo`, Singapore). The VM has no DB password — dashboard
SQL editor only. **Do NOT push anything yet** — independent review + red-team
still to come; this handoff is the live-proof procedure, not a merge approval.

Status of the code under test: migration 0007 AMENDED by the security-review
fix round (factor-id columns + partial unique single-Owner index + email
column + admin_settings table + TRUNCATE revokes; validator 428/428,
exclude-0007 control fails 132). All gates green (API: ruff check,
ruff format --check, mypy ., pytest 476 passed; web: lint,
typecheck, build). Matrix tests 14/14 in `apps/api/tests/test_admin_matrix.py`.
The fix round also changed the API (C1/C2/C3/H1/H3/M1/M2/M3 + N4/N6/N7/N9) —
see the fix report; N1 (HttpOnly cookies + CSRF) is deliberately NOT fixed
here (Week 3 hardening).

## 0. Prerequisites (before §1)

- Live project is `dpwfshafzyxyfoktsggo` (Singapore). Migrations 0001–0006
  are already applied live (0005 + 0006 on 12 Nov 2026). Apply §1 AFTER
  them, in order — do not re-apply 0001–0006.
- The live API must be running the `admin-foundation` branch build with
  `STAFF_URL_PREFIX` set (128-bit random, generated at setup, server
  config only) — with the prefix empty the staff routers mount at root
  and the prefix checks in §2 steps 8–9 cannot be proven. The prefix
  VALUE is never written in this file or any repo file: the operator
  holds it and substitutes it for `<STAFF_PREFIX>` below.
- The live WEB deployment (Vercel) must carry the SAME `STAFF_URL_PREFIX`
  value plus `STAFF_API_URL` (the deployed API origin), both server env
  only — see §5 for the wiring. Without them the staff pages 404 (the
  web middleware serves staff pages only under the prefix) and the
  staff login cannot reach the API.
- Live API base: the deployed Render URL (replace `<API_BASE>` below).
  Staff host: `admin.websurfacehq.com` (replace `<STAFF_HOST>` if the
  deploy uses a different staff host; the DNS CNAME must exist first).
- You need an authenticator app (TOTP) on a phone for the MFA steps,
  and the Owner's email inbox for the invite-accept confirmation mail.

## 1. Migration 0007 — apply VERBATIM via the dashboard SQL editor

Copy the whole block below into the Supabase dashboard SQL editor for
project `dpwfshafzyxyfoktsggo` and run it. It is the exact content of
`supabase/migrations/0007_admin_foundation.sql` in this tree (amended
20 Nov 2026, security-review fix round: `current_factor_id` /
`pending_factor_id` on `staff_roles` + partial unique index
`staff_roles_single_owner_idx`, PLUS `email` on `staff_roles` with a
unique index, the `admin_settings` table seeding `prefix_version = 1`
(C3 — the prefix version is persisted, not process-local), and
`REVOKE TRUNCATE ON audit_logs` from service_role / authenticated /
anon / PUBLIC (N6)). Expected result:
"Success. No rows returned". If any statement errors, STOP and report
the exact error — do not apply a partial fix by hand.

```sql
-- WebSurfaceHQ — Migration 0007: admin foundation (staff roles, invites, sessions; audit append-only)
-- =============================================================================================
-- WHY THIS MIGRATION EXISTS (admin foundation, 20 Nov 2026; plan
-- docs/admin-foundation-plan.md §2; DESIGN-LOCK.md "Admin panel +
-- Founder screen", frozen 15 Nov 2026 00:12 IST):
-- Platform roles Owner / Admin / Support, separate from team roles and
-- from the customer "owner" role. Staff accounts are Owner-managed,
-- invite-only, single-use 72h setup links; staff sessions are 12h
-- absolute / 60 min idle with TOTP at every sign-in; the audit log
-- becomes provably append-only.
--
-- WHAT CHANGES (frozen schema — implement exactly as specified):
--   * staff_roles: user_id UUID PK (FK auth.users), email (lowercased,
--     UNIQUE — one staff row per email, the login lookup key),
--     role owner|admin|support, status active|suspended, invited_by,
--     created_at, updated_at, current_factor_id / pending_factor_id
--     (nullable text: the GoTrue TOTP factor ids the staff login flow
--     challenges — Child C, 20 Nov 2026; needed for MFA re-enrollment
--     enforcement once the in-memory registry is replaced by this
--     table). A BEFORE INSERT OR UPDATE trigger enforces AT MOST ONE
--     Owner row (see the "exactly one" note below), AND a partial
--     unique index closes the concurrent-insert race the trigger
--     cannot see.
--   * admin_settings: key text PK, value text, updated_at — server
--     settings the API must persist across restarts (first key:
--     prefix_version, seeded to 1 — the staff-prefix version counter
--     is DB-backed, so a rotation survives a restart/redeploy; C3
--     fix, 20 Nov 2026). service_role only (RLS, no policies).
--   * staff_invites: id, token_hash (SHA-256 hex of the token — the
--     raw token is never stored), email, role, invited_by,
--     expires_at (created + 72h, set by the API at insert), used_at
--     NULL, created_at. Single-use is enforced by the atomic claim
--     (UPDATE ... WHERE used_at IS NULL RETURNING) in the API, not
--     by a DB constraint; token_hash is UNIQUE so one token maps to
--     exactly one invite. Expired/used/invalid tokens are
--     indistinguishable in API responses (the API checks expiry).
--   * staff_sessions: id, user_id, issued_at, last_seen_at,
--     revoked_at NULL, ip, user_agent, prefix_version int (bumped
--     on every staff-prefix rotation; sessions with an older version
--     are dead — the API checks this, the DB only stores it),
--     step_up_verified_at NULL (set when a step-up MFA check passes
--     for this session — the Founder gate, POST
--     /staff/auth/step-up/verify; NULL until then).
--   * audit_logs (exists, 0001): a trigger blocking UPDATE and
--     DELETE on audit rows + REVOKE UPDATE/DELETE from all roles.
--     The trigger has NO role exemption — not even service_role or
--     postgres: the API only INSERTs audit rows, and the table owner
--     can drop the trigger if a genuine admin fix is ever needed
--     (same reasoning as 0004's postgres exemption, inverted: for
--     audit history the whole point is immutability, so no writer
--     is exempted). The REVOKEs close the grant path; the trigger
--     is the backstop for any role that still holds the grant
--     (postgres, the table owner).
--
-- "EXACTLY ONE Owner" — what the DB can and cannot enforce: the
-- trigger below enforces AT MOST one Owner row (a second Owner insert
-- or a re-role to Owner raises). It cannot enforce AT LEAST one: the
-- first Owner must be created when zero exist, so "exactly one" as a
-- standing invariant is a setup + application concern (first Owner
-- created once at setup; the API must refuse suspend/delete/re-role
-- of the last Owner). The trigger is the atomic backstop against
-- two Owners ever existing at once, including under concurrent
-- inserts — the EXISTS check inside the trigger sees committed rows
-- only, so two concurrent Owner inserts CAN both pass the trigger
-- check and commit. That race is closed by the partial unique index
-- `staff_roles_single_owner_idx` (added 20 Nov 2026, Child F): the
-- index check is atomic at commit, so at most one of two concurrent
-- Owner inserts can commit — the loser gets a unique violation. The
-- trigger stays as the sequential backstop with the readable error
-- message; the index is the race closer.
--
-- GRANTS (0005 lesson: grants ship WITH the tables, never later):
-- service_role gets full DML on the new tables (staff_roles,
-- staff_invites, staff_sessions, admin_settings); authenticated
-- and anon get NOTHING on them (explicit REVOKE ALL pins the intent
-- even though no grants exist today — a future broad grant would
-- otherwise silently re-open them, the exact failure mode 0005 was
-- written to repair). audit_logs keeps its 0005 grants except
-- UPDATE/DELETE, which are revoked from service_role too — the API
-- never updates or deletes audit rows. TRUNCATE on audit_logs is
-- revoked from authenticated, anon, service_role, and PUBLIC as
-- well (N6 fix): TRUNCATE is not covered by the UPDATE/DELETE
-- REVOKEs, and a truncate would wipe the whole audit trail in one
-- statement. RESIDUAL (inherent, documented): the table OWNER
-- (postgres / the role that ran this migration) can still TRUNCATE
-- or drop the table — Postgres gives the owner that power and no
-- REVOKE can take it away; the trigger backstop does not fire on
-- TRUNCATE either. Audit immutability therefore rests on nobody
-- holding the owner credentials except the deploy operator.
--
-- APPLY ORDER: 0001 -> 0002 -> 0003 -> 0004 -> 0005 -> 0006 -> 0007.
-- The parent applies this via the dashboard SQL editor, same path as
-- 0001–0006. This file does NOT create roles.
--
-- ROLES: assumes the Supabase roles anon / authenticated /
-- service_role already exist (they do in every Supabase project).

BEGIN;

-- ------------------------------------------------------------------
-- staff_roles — one row per staff account: the platform role.
-- ------------------------------------------------------------------
CREATE TABLE public.staff_roles (
  user_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  -- Lowercased staff email: the login lookup key (the service
  -- resolves accounts by email before it knows the user id) and the
  -- address force-reset emails go to. UNIQUE: one staff row per
  -- email (C2 fix — the API enforced this in its registry; the DB
  -- enforces it now that the table is the source of truth).
  email text NOT NULL,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'support')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  -- Who invited this staff member; NULL for the first Owner, who is
  -- created once at setup and has no inviter.
  invited_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  -- GoTrue TOTP factor ids (identifiers, NOT secrets — the TOTP
  -- secret itself lives only in GoTrue and is never stored here).
  -- current_factor_id: the verified factor the login flow challenges;
  -- clearing it (Owner MFA re-enrollment) retires the old factor
  -- from the staff flow. pending_factor_id: the factor being enrolled
  -- until /mfa/confirm activates it. Both NULL until enrollment.
  current_factor_id text,
  pending_factor_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER staff_roles_set_updated_at
  BEFORE UPDATE ON public.staff_roles
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Exactly one Owner (at most — see the header note): a second Owner
-- insert, or re-roling another staff member to Owner while one
-- exists, raises. Updating the existing Owner's own row (e.g. a
-- status change) is allowed — the check excludes the row itself.
CREATE OR REPLACE FUNCTION public.enforce_single_owner()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF NEW.role = 'owner' AND EXISTS (
    SELECT 1 FROM public.staff_roles
    WHERE role = 'owner' AND user_id IS DISTINCT FROM NEW.user_id
  ) THEN
    RAISE EXCEPTION 'only one Owner may exist';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER staff_roles_enforce_single_owner
  BEFORE INSERT OR UPDATE ON public.staff_roles
  FOR EACH ROW EXECUTE FUNCTION public.enforce_single_owner();

-- Concurrent-insert race closer (Child F, 20 Nov 2026): the trigger's
-- EXISTS check sees committed rows only, so two concurrent Owner
-- inserts could both pass it. This partial unique index is checked
-- atomically at commit — at most one Owner row can ever exist, even
-- under concurrency. It indexes only Owner rows, so admin/support
-- rows are unaffected.
CREATE UNIQUE INDEX staff_roles_single_owner_idx
  ON public.staff_roles (role) WHERE role = 'owner';

-- One staff row per email (see the email column note above).
CREATE UNIQUE INDEX staff_roles_email_key ON public.staff_roles (email);

-- ------------------------------------------------------------------
-- admin_settings — persisted server settings (C3 fix, 20 Nov 2026).
-- The staff-prefix version counter lives here (key
-- 'prefix_version', seeded to '1' below): a rotation must survive
-- a restart/redeploy, which a process-local counter cannot do.
-- service_role only (RLS, no policies); the API reads the version
-- on every session validation and bumps it on rotation.
-- ------------------------------------------------------------------
CREATE TABLE public.admin_settings (
  key text PRIMARY KEY,
  value text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER admin_settings_set_updated_at
  BEFORE UPDATE ON public.admin_settings
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
INSERT INTO public.admin_settings (key, value) VALUES ('prefix_version', '1')
  ON CONFLICT (key) DO NOTHING;
ALTER TABLE public.admin_settings ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.admin_settings TO service_role;
REVOKE ALL ON public.admin_settings FROM authenticated;
REVOKE ALL ON public.admin_settings FROM anon;

-- ------------------------------------------------------------------
-- staff_invites — single-use, 72h setup links (Owner-created).
-- token_hash is the SHA-256 hex of the token; the raw token is
-- returned once at creation and never stored (same pattern as the
-- verification token hash in 0001, deviation D2).
-- ------------------------------------------------------------------
CREATE TABLE public.staff_invites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL,
  email text NOT NULL,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'support')),
  invited_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  -- Set by the API at insert: created_at + 72 hours. The DB does not
  -- enforce expiry; the API rejects expired tokens (and answers them
  -- exactly like invalid ones — no enumeration).
  expires_at timestamptz NOT NULL,
  used_at timestamptz, -- NULL until claimed; the atomic claim sets it
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT staff_invites_email_not_empty CHECK (length(btrim(email)) > 0)
);
-- One token maps to exactly one invite (a token is a single-use
-- credential; a duplicate hash would make two invites claimable by
-- the same link).
CREATE UNIQUE INDEX staff_invites_token_hash_key ON public.staff_invites (token_hash);

-- ------------------------------------------------------------------
-- staff_sessions — one row per staff sign-in. Absolute lifetime 12h
-- and idle 60 min are enforced by the API (Child B), which compares
-- issued_at / last_seen_at; revocation sets revoked_at; prefix_version
-- is bumped on every staff-prefix rotation and the API treats sessions
-- with an older version as dead.
-- ------------------------------------------------------------------
CREATE TABLE public.staff_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  issued_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz, -- NULL while the session is live
  ip text,
  user_agent text,
  prefix_version int NOT NULL DEFAULT 1 CHECK (prefix_version >= 1),
  -- NULL until a step-up MFA check passes for this session (POST
  -- /staff/auth/step-up/verify, the Founder gate when the
  -- STAFF_STEP_UP_MFA flag is on). The API (Child B's session
  -- manager) writes it only when a step-up time is set, and reads it
  -- to decide whether the session is step-up-verified; the DB only
  -- stores it.
  step_up_verified_at timestamptz
);
CREATE INDEX staff_sessions_user_id_idx ON public.staff_sessions (user_id);

-- ------------------------------------------------------------------
-- ROW LEVEL SECURITY — staff tables: service_role only.
-- RLS is enabled on all three tables and NO policy is created for
-- any of them, so every role is denied by default at the policy
-- layer. service_role bypasses RLS and is the only reader/writer;
-- the API resolves the staff role server-side from these tables and
-- NEVER trusts a role claim from the client. (admin_settings gets
-- the same treatment in its own block above.)
-- ------------------------------------------------------------------
ALTER TABLE public.staff_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_sessions ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------------
-- GRANTS — service_role full DML on the new tables; authenticated
-- and anon hold nothing (REVOKE ALL pins the intent; see header).
-- ------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON public.staff_roles TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.staff_invites TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.staff_sessions TO service_role;

REVOKE ALL ON public.staff_roles FROM authenticated;
REVOKE ALL ON public.staff_roles FROM anon;
REVOKE ALL ON public.staff_invites FROM authenticated;
REVOKE ALL ON public.staff_invites FROM anon;
REVOKE ALL ON public.staff_sessions FROM authenticated;
REVOKE ALL ON public.staff_sessions FROM anon;

-- ------------------------------------------------------------------
-- audit_logs — append-only, enforced at two layers.
-- (1) Trigger: UPDATE or DELETE on any audit row raises, for every
-- role — no exemption, not even service_role or postgres (see header).
-- (2) REVOKE UPDATE/DELETE from every role that could hold the grant
-- (authenticated, anon, service_role). INSERT + SELECT stay granted
-- exactly as 0005 left them, so the API keeps writing audit rows and
-- staff keep reading them through the admin API.
-- (3) REVOKE TRUNCATE (N6 fix, 20 Nov 2026): TRUNCATE is a
-- separate privilege — the UPDATE/DELETE REVOKEs do not cover it,
-- and one TRUNCATE would wipe the whole audit trail. Revoked from
-- authenticated, anon, service_role, and PUBLIC. Residual: the
-- table OWNER can still TRUNCATE (inherent — see the GRANTS header).
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.prevent_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only: rows may never be updated or deleted';
  RETURN NULL; -- unreachable (the RAISE always fires); present so the
               -- function has the trigger return on every path.
END;
$$;

CREATE TRIGGER audit_logs_prevent_update
  BEFORE UPDATE ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_mutation();

CREATE TRIGGER audit_logs_prevent_delete
  BEFORE DELETE ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_mutation();

REVOKE UPDATE, DELETE ON public.audit_logs FROM authenticated;
REVOKE UPDATE, DELETE ON public.audit_logs FROM anon;
REVOKE UPDATE, DELETE ON public.audit_logs FROM service_role;
REVOKE TRUNCATE ON public.audit_logs FROM authenticated;
REVOKE TRUNCATE ON public.audit_logs FROM anon;
REVOKE TRUNCATE ON public.audit_logs FROM service_role;
REVOKE TRUNCATE ON public.audit_logs FROM PUBLIC;

COMMIT;
```

## 2. Live verification script (run in order; stop at the first failure)

`<API_BASE>` = live API origin. `<STAFF_PREFIX>` = the secret path prefix
(operator-held). All staff calls go under `/<STAFF_PREFIX>/...`. `curl -H
"Host: ..."` is NOT needed against the real staff host — the Host header
is already `admin.websurfacehq.com` there; the `-H "Host:"` lines below
are only for probing from a machine where DNS does not resolve yet.

### Step 1 — Create the FIRST Owner (one-time setup, dashboard + SQL editor)

1. In the Supabase dashboard → Authentication → Users → Add user:
   create the Owner account (email + password, auto-confirm ON).
   Copy the new user's UUID — call it `<OWNER_UUID>`, email `<OWNER_EMAIL>`.
2. In the SQL editor, run:

```sql
INSERT INTO public.staff_roles (user_id, email, role, status)
VALUES ('<OWNER_UUID>', '<OWNER_EMAIL>', 'owner', 'active');
```

3. Verify: `SELECT user_id, email, role, status FROM public.staff_roles;` →
   exactly one row, role `owner`, email `<OWNER_EMAIL>`.

### Step 2 — Owner login + MFA enrollment (proves the login contract)

1. `POST <API_BASE>/<STAFF_PREFIX>/staff/auth/login`
   `{"role": "owner", "email": "<OWNER_EMAIL>", "password": "<OWNER_PASSWORD>"}`
   → 200 `{"mfa_required": true, "enroll_required": true,
   "supabase_access_token": "<AAL1>"}`. NOTE: no session yet — that is
   correct; a session exists only after MFA verifies.
2. `POST <API_BASE>/<STAFF_PREFIX>/staff/auth/mfa/enroll` with
   `Authorization: Bearer <AAL1>` → 200 `{"qr_uri", "secret", "factor_id"}`.
   Scan the QR in the authenticator app. The secret is shown ONCE.
3. `POST <API_BASE>/<STAFF_PREFIX>/staff/auth/mfa/confirm`
   `{"factor_id": "<FACTOR_ID>", "code": "<6-digit TOTP>"}` with
   `Authorization: Bearer <AAL1>` → 200 with `access_token` (staff
   session UUID), `user.role == "owner"`, `expires_in == 43200`.
   Save it as `<OWNER_SESSION>`.
4. `GET <API_BASE>/<STAFF_PREFIX>/admin/me` with
   `Authorization: Bearer <OWNER_SESSION>` → 200, role `owner`.

### Step 3 — Owner invites Admin + Support (proves invite + audit)

1. `POST <API_BASE>/<STAFF_PREFIX>/admin/users/invite`
   `{"email": "<ADMIN_EMAIL>", "role": "admin"}` with `<OWNER_SESSION>`
   → 201 with `invite_token`. Save it as `<ADMIN_INVITE_TOKEN>`.
   Repeat for Support (`<SUPPORT_EMAIL>`, role `support`).
2. `POST <API_BASE>/<STAFF_PREFIX>/staff/auth/invite/accept`
   `{"token": "<ADMIN_INVITE_TOKEN>", "password": "<ADMIN_PASSWORD>"}` →
   201 `{"user": {"email": "<ADMIN_EMAIL>", "role": "admin"}, "message": ...}`.
   No MFA material, no session — correct.
3. Reuse the same token → 404 `NOT_FOUND` "Invalid or expired invite link"
   (same body as an invalid token — check both are byte-identical).
4. New Admin logs in (Step 2 pattern, but `enroll_required` is true on
   first login → enroll → confirm) and saves `<ADMIN_SESSION>`. Same for
   Support → `<SUPPORT_SESSION>`.

### Step 4 — Role boundaries (proves can() + Founder gate)

1. Admin: `GET <API_BASE>/<STAFF_PREFIX>/admin/founder` with
   `<ADMIN_SESSION>` → **403 `FORBIDDEN`**.
2. Support: `GET <API_BASE>/<STAFF_PREFIX>/admin/users` → **403**;
   `GET <API_BASE>/<STAFF_PREFIX>/admin/support/tickets` → **200**;
   `GET <API_BASE>/<STAFF_PREFIX>/admin/abuse` → **200**;
   `GET <API_BASE>/<STAFF_PREFIX>/admin/founder` → **403**.
3. Owner without step-up: `GET <API_BASE>/<STAFF_PREFIX>/admin/founder`
   with `<OWNER_SESSION>` → **403 `STEP_UP_REQUIRED`** (flag ON by default).
4. Owner step-up: `POST <API_BASE>/<STAFF_PREFIX>/staff/auth/step-up/verify`
   `{"password": "<OWNER_PASSWORD>", "code": "<fresh TOTP>"}` with
   `Authorization: Bearer <OWNER_SESSION>` → 200 `{"step_up_verified": true}`.
5. Owner: `GET <API_BASE>/<STAFF_PREFIX>/admin/founder` again → **200**
   with subscription/scan figures (or `subscriptions_available: false`
   until the store methods land — never fake figures).

### Step 5 — Audit rows written (proves append-only audit)

Run §3 query Q6. Expect rows for `staff.login`, `staff.mfa_verified` /
`staff.mfa_enrolled`, `staff.invite_created`, `staff.invite_accepted` (and
`staff.step_up_verified` after Step 4.4), each with actor + timestamp.
One row per action (M1 fix): e.g. a suspend writes exactly one
`staff.suspended` row with `metadata.before.status == "active"` and
`metadata.after.status == "suspended"` — the old `admin.users.*` router
rows are gone.
Then prove append-only: `UPDATE public.audit_logs SET action='tampered'
WHERE id='<one id>';` → ERROR (trigger), and the row is unchanged.

### Step 6 — Prefix rotation invalidates sessions

1. `POST <API_BASE>/<STAFF_PREFIX>/admin/settings/rotate-prefix`
   `{"confirm": true}` with `<OWNER_SESSION>` → 200
   `{"prefix_version": 2, "staff_sessions_invalidated": true,
   "sessions_revoked": <count of live sessions killed>,
   "prefix_path_note": "Rotation bumps the persisted prefix version and
   revokes all live staff sessions. The URL path string itself changes
   only by setting a new STAFF_URL_PREFIX value and restarting the API."}`.
   `sessions_revoked` counts the sessions explicitly revoked in the DB
   at rotation time (C3 fix — belt and braces next to the version bump).
2. `GET <API_BASE>/<STAFF_PREFIX>/admin/me` with `<OWNER_SESSION>` AND
   with `<ADMIN_SESSION>` → **401 `INVALID_SESSION`** for BOTH.
3. Owner + Admin log in again (Step 2 pattern, MFA each time) → fresh
   sessions work; `GET /admin/me` → 200.
4. HONEST LIMIT (recorded, not hidden): `rotate-prefix` bumps the session
   VERSION (which is what kills sessions). The PATH prefix string itself
   lives in server config (`STAFF_URL_PREFIX`): changing the actual URL
   path is a separate ops step — set a new value in the hosting env and
   restart/redeploy the API, then distribute the new address through
   fresh setup links. The old path stops working only after that restart.

### Step 7 — Customer host + staff host 404s (proves the two doors)

1. `GET https://websurfacehq.com/<STAFF_PREFIX>/staff/auth/login` (customer
   host, staff path) → **404** (API host gate on the staff mounts AND
   web middleware; the customer site never serves staff pages — even a
   valid staff session on the customer host gets 404 from the API).
2. `GET https://admin.websurfacehq.com/anything-else` (staff host, outside
   the prefix) → **404** generic, body contains no prefix string.
3. `GET https://admin.websurfacehq.com/<STAFF_PREFIX>-evil/staff/auth/login`
   (lookalike prefix) → **404** generic.

### Step 8 — Cleanup

Delete the Admin + Support test Auth users via the dashboard
(Authentication → Users) or the GoTrue Admin API, and delete their
`staff_roles` rows. Keep the Owner. Record the run (date, who, every
status above) in `docs/live-proof-evidence-*.md`.

## 3. Exact verification queries (dashboard SQL editor, project dpwfshafzyxyfoktsggo)

```sql
-- Q1: staff tables exist, RLS on, factor columns present
-- (corrected 21 Nov 2026: information_schema.tables has no row_security
-- column — RLS status lives on pg_class.relrowsecurity)
SELECT c.relname AS table_name, c.relrowsecurity AS row_security
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname IN ('staff_roles', 'staff_invites', 'staff_sessions',
                    'admin_settings');
SELECT table_name, column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'staff_roles'
ORDER BY ordinal_position;

-- Q2: partial unique single-Owner index (race closer)
SELECT indexname, indexdef FROM pg_indexes
WHERE schemaname = 'public' AND indexname = 'staff_roles_single_owner_idx';

-- Q3: exactly one Owner; list all staff
SELECT user_id, email, role, status, current_factor_id IS NOT NULL AS has_factor,
       created_at FROM public.staff_roles ORDER BY created_at;

-- Q4: invites (single-use 72h) — used_at set after accept, never reused
SELECT id, email, role, expires_at, used_at, created_at
FROM public.staff_invites ORDER BY created_at DESC LIMIT 20;

-- Q5: staff sessions — live vs revoked, prefix versions
SELECT id, user_id, issued_at, last_seen_at, revoked_at, prefix_version,
       step_up_verified_at FROM public.staff_sessions
ORDER BY issued_at DESC LIMIT 20;

-- Q6: audit rows for the proof run (newest first)
SELECT id, user_id, action, target_domain, created_at
FROM public.audit_logs
WHERE action LIKE 'staff.%' OR action LIKE 'admin.%'
ORDER BY created_at DESC LIMIT 30;

-- Q7: counts snapshot (record before + after the proof run)
SELECT (SELECT count(*) FROM public.staff_roles) AS staff_roles,
       (SELECT count(*) FROM public.staff_invites) AS staff_invites,
       (SELECT count(*) FROM public.staff_sessions) AS staff_sessions,
       (SELECT count(*) FROM public.audit_logs) AS audit_logs;

-- Q10: admin_settings seed (C3) — prefix_version must be '1' before any rotation
SELECT key, value FROM public.admin_settings ORDER BY key;

-- Q8: append-only proof — MUST ERROR (trigger), row unchanged afterwards
-- UPDATE public.audit_logs SET action = 'tampered'
-- WHERE id = '<one audit id from Q6>';

-- Q9: second-Owner insert MUST ERROR (trigger + unique index)
-- INSERT INTO public.staff_roles (user_id, email, role)
-- VALUES ('00000000-0000-4000-8000-000000000000', 'second@example.com', 'owner');
-- (Fails on the auth.users FK first for a fake UUID — use a real second
--  Auth user id to see the 'only one Owner may exist' error instead.)
```

## 4. Known gaps carried into the live proof (do not re-prove as done)

- Audit writes are NOT atomic with mutations (store has no transactions);
  a failed audit after a successful mutation leaves a real action with no
  audit row — but the failure is LOUD now (M1 fix): the API returns 500
  `AUDIT_WRITE_FAILED` telling the admin the action succeeded but was NOT
  audited, and logs an ERROR. One row per action (the service's, with
  correct before/after). Check Q6 after every mutation.
- Staff accounts/invites/factor ids now live in the store (C2 fix — the
  Supabase tables ARE the source of truth; the in-memory registry is
  gone) and the prefix version is persisted in `admin_settings` (C3 fix).
  The first-Owner bootstrap (Step 1 SQL) is the only manual staff row.
- TRUNCATE on `audit_logs` is revoked from service_role / authenticated /
  anon / PUBLIC (N6 fix), but the table OWNER (postgres) can still
  TRUNCATE — that is inherent to Postgres, not a gap in the migration.
  Never run TRUNCATE as the owner against this table.
- Invite-accept for an already-registered email consumes the invite and
  answers the generic 404 (linking an existing Auth user needs an Admin-API
  lookup the provider protocol does not have yet).
- `enroll_required` leaks MFA-enrollment state to a password holder
  (the login response differs enrolled vs unenrolled) — ACCEPTED
  residual (red-team F7, 20 Nov 2026): the exposure is limited to
  someone who already holds the password, and the client needs the
  signal to route the user to enrollment. Do not "fix" by removing
  the signal.
- `delete_staff` does not delete the Supabase Auth user (provider protocol
  has no delete-user method); delete test Auth users via the dashboard or
  the GoTrue Admin API (Step 8).
- Orphaned GoTrue factor after Owner MFA re-enroll: the staff flow retires
  the factor (stored `current_factor_id` cleared), but the GoTrue factor
  row itself remains until removed via GoTrue's Admin API.
- `middleware.ts` vs Next 16.4.6 `proxy.ts` deprecation: kept as
  `middleware.ts` since it works (build lists it as "Proxy (Middleware)").
- The staff API now ALSO enforces the host gate (M3 fix): a customer
  host presenting the prefixed path + a valid staff session gets 404
  from the API itself, not only from the web middleware (Step 7.1).

## 5. Production wiring — web (staff host + same-origin API proxy)
   (NEW1 fix, 20 Nov 2026; the shipped web client could not call the
   prefixed API at all before this — see the fix report)

The prefix is held SERVER-SIDE only. Nothing in the browser ever sees
it: no `NEXT_PUBLIC_` variable carries it (the staff client,
`apps/web/src/lib/staff-api.ts`, calls same-origin `/api/staff/...`
and never touches `NEXT_PUBLIC_API_URL`), no link, no redirect, no
log, no bundle. Verified locally 20 Nov 2026: a production build
run with a 22-char test prefix in server env only — `grep` of the
whole `.next` output for the test prefix value returns zero hits,
and the built staff client fetches `` `/api${path}` ``.

### 5.1 Env vars (both deployments, same prefix value)

| Variable | Where | Value |
|---|---|---|
| `STAFF_URL_PREFIX` | API deployment (Render) AND web deployment (Vercel) | The same 128-bit random value on both. Server env only, never committed, never `NEXT_PUBLIC_`. Empty = enforcement off (local dev only). |
| `STAFF_API_URL` | Web deployment (Vercel) only, server env | The deployed API origin, e.g. `https://your-api.onrender.com` (placeholder — the operator substitutes the real origin). Local dev default is `http://localhost:8000`. |

### 5.2 How a staff request flows

1. Browser (on `admin.websurfacehq.com/<STAFF_PREFIX>/staff-login`):
   the web middleware (`apps/web/src/middleware.ts`) strips the prefix
   and rewrites INTERNALLY to the bare route `/staff-login`. The
   browser URL keeps the prefix; the page renders from the bare route.
2. A bare staff page (`/staff-login`, no prefix) on the staff host
   answers a generic 404 with NO redirect — a redirect would hand the
   secret prefix to anyone probing the bare path. Everything outside
   the prefix on the staff host 404s the same way.
3. The staff client calls same-origin `/api/staff/auth/login` (etc.).
   The middleware proxies it to `<STAFF_API_URL>/<STAFF_PREFIX>/staff/
   auth/login`, adding the prefix server-side. Method, headers, body,
   and query string are forwarded.
4. Staff-page-to-staff-page links are RELATIVE (`href="staff-mfa-setup"`,
   not `/staff-mfa-setup`) so navigation keeps the browser under the
   prefix; an absolute link would drop the prefix and 404.
5. Customer host (`websurfacehq.com`): every staff path — bare,
   prefixed, and `/api/staff/*` — answers the generic 404.

### 5.3 Prefix rotation (ops step, both deployments)

Rotation is an env change, not a code change: set a NEW
`STAFF_URL_PREFIX` value in BOTH deployments (API + web, same value)
and restart/redeploy both. Until both carry the new value, staff
requests fail (web 404s the old prefix; the API 404s the new one if
only the web moved). This is consistent with the API-side step in
§2 Step 6: `POST /admin/settings/rotate-prefix` bumps the persisted
prefix version and revokes all live staff sessions — run it as part
of the same rotation, and distribute the new address through fresh
setup links (the old path stops working after the restart).

### 5.4 MUST-CONFIRM: `API_PUBLIC_HOST` / `API_PUBLIC_URL` on the API deployment

Proven locally 20 Nov 2026 with a header-echo origin: the web
proxy's upstream request carries `Host: <API origin>` (the API
origin's host — the staff web host arrives only as
`X-Forwarded-Host`, which the API's host gate does not read). The
API's `check_staff_host` accepts the staff host (`STAFF_HOST`,
default `admin.websurfacehq.com`), the API's own public host(s)
(`API_PUBLIC_HOST`, plus the host parsed from `API_PUBLIC_URL`),
or localhost in dev. So on the API deployment, **`API_PUBLIC_HOST`
(or `API_PUBLIC_URL`) must be set to the API's own public host**
(the Render origin host); with neither set, `get_api_public_hosts()`
is empty and EVERY proxied staff call 404s in production — and so do
the direct-API steps in §2 (they call `<API_BASE>`, the Render URL,
whose Host is the Render host, not the staff host). **`STAFF_HOST`
stays `admin.websurfacehq.com`** — do NOT point it at the API host.
Confirm this setting with the API side before the live proof; it is
an env setting on the API deployment, not a code change.

### 5.5 Local verification (20 Nov 2026, `next start` + real API,
   22-char test prefix in shell env only, never written to a file)

- Staff host + `/<prefix>/staff-login|staff-invite|staff-mfa-setup`
  → 200 (page renders, `X-Robots-Tag: noindex, nofollow`); the same
  paths bare → 404. `/<prefix>/dashboard`, `/<prefix>-evil/
  staff-login`, `/<prefix>/` (after a 308 to `/<prefix>`, which only
  repeats the prefix the requester already sent) → 404.
- Through-proxy login `POST /api/staff/auth/login` and direct-API
  `POST /<prefix>/staff/auth/login` return the IDENTICAL response;
  direct-API bare `POST /staff/auth/login` → 404. At the time of
  this run both answered 500 `INTERNAL_ERROR` from inside the API's
  `staff_login` (PostgREST `PGRST205`: table `public.staff_roles`
  not found — migration 0007 is not yet applied to the live
  project). That 500 is itself the proof the proxy delivers the
  request to the real login logic (routing + prefix + host gate all
  passed; only the missing table failed it). The 200/401 login
  outcome is therefore NOT proven here — it needs migration 0007
  applied live + a seeded staff account, which is §2 Step 1–2 of
  this handoff.
- Customer host: `/staff-login`, `/<prefix>/staff-login`, and `POST
  /api/staff/auth/login` → 404. Local dev (localhost, prefix set):
  bare `/staff-login` → 200 and the proxy adds the prefix (same 500
  from the API, same cause as above).
- Bundle: zero hits for the test prefix value in `.next`; the built
  staff client contains only relative `href="staff-login"` /
  `href="staff-mfa-setup"` links (no absolute `/staff-*` hrefs in
  any client chunk) and fetches `` `/api${path}` ``.
- NOT re-verified here: real-browser click-through between staff
  pages (no live-browser access in this session; hand-made RSC /
  prefetch fetches via curl return the same 307 on staff and
  non-staff routes — stock Next behaviour for incomplete
  router-fetch headers, not a middleware effect) and the 375px /
  desktop overflow re-check (no layout-affecting code changed — the
  diff is href values + two error strings only; the pages' prior
  375px QA stands). Both belong in the coordinator's live check.
