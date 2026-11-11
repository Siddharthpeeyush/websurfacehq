-- WebSurfaceHQ — Migration 0004: Week 1 review fixes
-- =====================================================
-- Fixes the independent security review's High findings that need schema
-- changes (11 Nov 2026). Nothing here changes existing data (no project
-- exists yet; 0001–0003 are unapplied) — it only adds a column, an index,
-- and hardens direct-PostgREST writes.
--
-- H3: scan_jobs.idempotency_key — the store (app/db/supabase_store.py)
--   inserts and filters on this column, but 0001 never created it, so
--   dispatch / the worker gate / the DLQ were inoperable on real
--   Postgres. Added here with a lookup index. Uniqueness is NOT re-added:
--   the key is scan_id:stage:target_hash and (scan_id, stage) is already
--   UNIQUE (0001), so the key is functionally unique.
-- H4: direct-PostgREST writes to security-critical rows. The anon key is
--   public by design and every user holds a valid JWT, so RLS alone let a
--   user PATCH their own target to "verified" (or retarget a verified
--   target to a victim domain) and PATCH their plan to "pro". Fixed by
--   triggers + user-read-only tables:
--   (a) a trigger blocking changes to the verification fields
--       (verification_status, verification_token_hash,
--       verification_expires_at, verified_at, verified_by_user_id) for
--       any role except service_role and postgres — only the API's
--       verification flow (service_role) may change them, and postgres
--       (the SQL editor) stays able to make an admin fix. NOTE: a
--       column-level REVOKE was considered first and REJECTED — in
--       Postgres a table-level UPDATE grant (which authenticated holds
--       by default in Supabase) implies UPDATE on every column, and a
--       column REVOKE does not remove it; the REVOKE is a no-op against
--       a table-level grant. The trigger is the enforcement, whatever
--       the grants say (proven by the pgserver validation run,
--       11 Nov 2026);
--   (a2) the SAME rule on INSERT (round-2 review, Blocker 1): the UPDATE
--       triggers did not stop an authenticated user from INSERTing a
--       target that was already "verified" (with a forged token hash
--       and verified_at) via PostgREST — the API then treated it as
--       verified and the M3 cap / scan quota were bypassed too. A
--       BEFORE INSERT trigger now requires a user-inserted target to
--       start pending with no verification evidence at all. The worker's
--       live re-check was the only backstop; it is no longer the only
--       one.
--   (b) a trigger blocking a domain change on a verified target for any
--       role except service_role and postgres (the API never changes
--       domains);
--   (c) subscriptions + api_keys are user-READ-only: their user-write
--       policies are dropped and INSERT/UPDATE/DELETE are revoked from
--       authenticated (webhooks / the API's service_role own all writes).
--   (c2) scans, findings, scan_jobs, assets, audit_logs are
--       server-created rows (round-2 review): INSERT/UPDATE/DELETE are
--       revoked from authenticated, closing direct PostgREST inserts
--       of scans (quota bypass), PATCHes of own scans.status /
--       findings.ai_* (fake "fixed" findings), and forged own audit
--       entries. The API (service_role) owns all writes to these
--       tables; users act on them only through the API.
-- M4: one active scan per user, enforced atomically. The router's
--   count-then-create check races under parallel requests, so a partial
--   unique index enforces the cap in the database; the store maps the
--   unique violation to ScanConflictError and the router answers 429.
--   Active statuses match ACTIVE_SCAN_STATUSES in app/db/store.py.
--   (The monthly 3/month cap has no DB equivalent yet — its race is a
--   known Week 1 limitation, closed by an atomic counter in Week 4.)
-- M3 (round-2 review, Blocker 2): one LIVE target per user, enforced
--   atomically the same way. The router's count-then-create check races
--   under parallel requests; the partial unique index
--   targets_one_live_per_user enforces the Free 1-domain cap in the
--   database and the store maps the violation to TargetCapError (429).
--   The WHERE deleted_at IS NULL predicate means the INDEX does not
--   block recreate-after-delete — but note UNIQUE(user_id, domain)
--   (0001) still blocks re-adding the SAME domain after a soft-delete
--   (pre-existing; the router's duplicate check also sees soft-deleted
--   rows as gone, so the user would get a confusing 409). Tracked
--   follow-up, not fixed here: make the domain unique partial too, or
--   hard-delete on recreate.
-- M4: one active scan per user, enforced atomically. The router's
--   count-then-create check races under parallel requests, so a partial
--   unique index enforces the cap in the database; the store maps the
--   unique violation to ScanConflictError and the router answers 429.
--   Active statuses match ACTIVE_SCAN_STATUSES in app/db/store.py.
--   (The monthly 3/month cap has no DB equivalent yet — its race is a
--   known Week 1 limitation, closed by an atomic counter in Week 4.)
--
-- Apply after 0001 -> 0002 -> 0003, before the seed:
--   supabase db push

BEGIN;

-- ------------------------------------------------------------------
-- H3: scan_jobs.idempotency_key
-- ------------------------------------------------------------------
ALTER TABLE public.scan_jobs ADD COLUMN idempotency_key text;
CREATE INDEX scan_jobs_idempotency_key_idx ON public.scan_jobs (idempotency_key);

-- ------------------------------------------------------------------
-- H4 (a): verification fields are not user-writable (trigger, not REVOKE)
-- ------------------------------------------------------------------
-- A column-level REVOKE does NOT work here: authenticated holds a
-- table-level UPDATE grant in Supabase, and that implies UPDATE on every
-- column — revoking the column privilege is a no-op. The trigger below
-- is the enforcement and holds whatever the grants say.
CREATE OR REPLACE FUNCTION public.prevent_verification_field_tamper()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  -- service_role (the API's verification flow) and postgres (the
  -- Supabase SQL editor — the admin-fix path) are the only writers of
  -- these fields. Every other role — an authenticated user via
  -- PostgREST — is blocked from changing any of them, including flipping
  -- their own target to "verified" or forging verified_at. (postgres is
  -- exempt because it is the database owner: it can drop the trigger
  -- anyway, so exempting it changes no real boundary — and without the
  -- exemption an admin could never fix a verification field from the
  -- SQL editor.)
  IF current_user NOT IN ('service_role', 'postgres')
     AND (OLD.verification_status IS DISTINCT FROM NEW.verification_status
          OR OLD.verification_token_hash IS DISTINCT FROM NEW.verification_token_hash
          OR OLD.verification_expires_at IS DISTINCT FROM NEW.verification_expires_at
          OR OLD.verified_at IS DISTINCT FROM NEW.verified_at
          OR OLD.verified_by_user_id IS DISTINCT FROM NEW.verified_by_user_id) THEN
    RAISE EXCEPTION 'verification fields may only be changed by the verification flow';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER targets_prevent_verification_tamper
  BEFORE UPDATE ON public.targets
  FOR EACH ROW EXECUTE FUNCTION public.prevent_verification_field_tamper();

-- ------------------------------------------------------------------
-- H4 (a2): a user-inserted target must start unverified (round-2,
-- Blocker 1). The UPDATE trigger above cannot see an INSERT, and
-- targets_insert_own only checks user_id = auth.uid() — so an
-- authenticated user could INSERT a row that was already "verified"
-- (forged token hash + verified_at) and the API would treat it as
-- verified. This trigger requires a fresh target to start pending with
-- no verification evidence. The API inserts as service_role (exempt);
-- the seed inserts as postgres (exempt).
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.require_unverified_target_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF current_user NOT IN ('service_role', 'postgres')
     AND (NEW.verification_status IS DISTINCT FROM 'pending'
          OR NEW.verified_at IS NOT NULL
          OR NEW.verified_by_user_id IS NOT NULL
          OR NEW.verification_token_hash IS NOT NULL
          OR NEW.verification_expires_at IS NOT NULL
          OR NEW.verification_method IS NOT NULL) THEN
    RAISE EXCEPTION 'a new target must start unverified (pending, no verification evidence)';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER targets_require_unverified_insert
  BEFORE INSERT ON public.targets
  FOR EACH ROW EXECUTE FUNCTION public.require_unverified_target_insert();

-- ------------------------------------------------------------------
-- H4 (b): a verified target cannot be retargeted to another domain
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.prevent_verified_target_retarget()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  -- service_role (the API) never changes domains, but it is allowed
  -- through so an admin fix is not painted into a corner; postgres (the
  -- SQL editor) is exempt for the same reason. Every other role (i.e.
  -- an authenticated user via PostgREST) is blocked.
  IF current_user NOT IN ('service_role', 'postgres')
     AND OLD.verification_status = 'verified'
     AND OLD.domain IS DISTINCT FROM NEW.domain THEN
    RAISE EXCEPTION 'cannot change the domain of a verified target';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER targets_prevent_verified_retarget
  BEFORE UPDATE ON public.targets
  FOR EACH ROW EXECUTE FUNCTION public.prevent_verified_target_retarget();

-- ------------------------------------------------------------------
-- H4 (c): subscriptions + api_keys are user-read-only
-- ------------------------------------------------------------------
DROP POLICY IF EXISTS subscriptions_update_own ON public.subscriptions;
DROP POLICY IF EXISTS subscriptions_insert_own ON public.subscriptions;
DROP POLICY IF EXISTS subscriptions_delete_own ON public.subscriptions;
REVOKE INSERT, UPDATE, DELETE ON public.subscriptions FROM authenticated;

DROP POLICY IF EXISTS api_keys_update_own ON public.api_keys;
DROP POLICY IF EXISTS api_keys_insert_own ON public.api_keys;
DROP POLICY IF EXISTS api_keys_delete_own ON public.api_keys;
REVOKE INSERT, UPDATE, DELETE ON public.api_keys FROM authenticated;

-- ------------------------------------------------------------------
-- H4 (c2): server-created tables are not user-writable (round-2 review).
-- Scans, findings, scan jobs, assets and audit logs are written only by
-- the API (service_role) — a user must never INSERT a scan (quota
-- bypass), PATCH their own scan status / finding AI fields (fake "fixed"
-- findings), or forge their own audit entries via PostgREST. The RLS
-- policies stay (second layer for other roles); the REVOKE is what
-- closes the PostgREST path for the authenticated role.
-- ------------------------------------------------------------------
REVOKE INSERT, UPDATE, DELETE ON public.scans FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.findings FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.scan_jobs FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.assets FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.audit_logs FROM authenticated;
-- attack_paths is in the same class (server-created, via the API as
-- service_role): a user must never INSERT a forged path or DELETE a
-- real one from their own report via PostgREST (round-3 review, Low).
REVOKE INSERT, UPDATE, DELETE ON public.attack_paths FROM authenticated;

-- ------------------------------------------------------------------
-- M4: one active scan per user (partial unique index)
-- ------------------------------------------------------------------
CREATE UNIQUE INDEX scans_one_active_per_user_key ON public.scans (user_id)
  WHERE status IN ('queued', 'recon', 'crawling', 'scanning', 'triaging');

-- ------------------------------------------------------------------
-- M3: one LIVE target per user (partial unique index; round-2, Blocker 2)
-- ------------------------------------------------------------------
CREATE UNIQUE INDEX targets_one_live_per_user ON public.targets (user_id)
  WHERE deleted_at IS NULL;

COMMIT;
