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
