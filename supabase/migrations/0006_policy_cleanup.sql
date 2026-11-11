-- WebSurfaceHQ — Migration 0006: drop write RLS policies on server-created tables
-- ==================================================================================
-- WHY THIS MIGRATION EXISTS (independent review, fix round F-L1, 11 Nov 2026):
-- Migration 0004 (c2) revoked INSERT/UPDATE/DELETE on the six server-created
-- tables (scans, findings, scan_jobs, assets, audit_logs, attack_paths)
-- from `authenticated`, and 0005 re-asserted those REVOKEs after its GRANTs.
-- But 0001/0003 still define user-write RLS policies on those same six
-- tables (INSERT/UPDATE/DELETE policies for the row owner), and 0004's
-- header claimed those policies "stay (second layer for other roles)".
-- That claim is vacuous: there IS no other role the policies would
-- protect. `service_role` bypasses RLS entirely, `postgres` owns the
-- tables, and `anon` holds no grant and matches no owner policy
-- (auth.uid() is NULL for anon). The only role the policies could ever
-- admit is `authenticated` — the exact role the REVOKE already bars.
-- So the policies are dead weight that only obscures the real barrier,
-- and worse: if a future migration ever issued a broad re-grant without
-- re-asserting the REVOKEs (exactly the failure mode 0005 was written
-- to repair — 0004's REVOKEs were no-ops live because no grants existed
-- yet), the surviving write policies would immediately re-open forged
-- scans / findings / audit rows via PostgREST. Dropping them makes the
-- REVOKE the single barrier, matching what 0004 already did for
-- subscriptions and api_keys (whose user-write policies were dropped in
-- the same change that revoked them).
--
-- WHAT CHANGES: DROP POLICY IF EXISTS for the INSERT/UPDATE/DELETE
-- policies on the six tables only. Every SELECT policy is KEPT — users
-- still read their own rows via PostgREST / the API's user-JWT path,
-- and the SELECT-only grants in 0005 are unchanged. `audit_logs` has
-- only an INSERT policy to drop (it never had UPDATE/DELETE policies —
-- it is append-only by design, see migrations README "RLS summary").
-- No GRANT or REVOKE changes here: the 0004/0005 REVOKEs already bar
-- `authenticated` writes, and `service_role` (the API) still owns all
-- writes to these tables. The API path is unaffected — SupabaseStore
-- connects as service_role, which bypasses RLS.
--
-- APPLY ORDER: 0001 -> 0002 -> 0003 -> 0004 -> 0005 -> 0006. This file
-- must run AFTER 0005 (it assumes the 0005 grant state). The parent
-- applies it via the dashboard SQL editor, same path as 0001–0005;
-- 0005 and 0006 are both pending live apply (neither is applied live
-- yet). DROP POLICY IF EXISTS is idempotent, so re-running is safe.
--
-- ROLES: assumes the Supabase roles already exist (they do in every
-- Supabase project). This file does NOT create roles or grants.

BEGIN;

-- scans (server-created rows; API/service_role owns all writes)
DROP POLICY IF EXISTS scans_insert_own ON public.scans;
DROP POLICY IF EXISTS scans_update_own ON public.scans;
DROP POLICY IF EXISTS scans_delete_own ON public.scans;

-- findings (same class: no user PATCH of ai_* / status)
DROP POLICY IF EXISTS findings_insert_own ON public.findings;
DROP POLICY IF EXISTS findings_update_own ON public.findings;
DROP POLICY IF EXISTS findings_delete_own ON public.findings;

-- scan_jobs (same class)
DROP POLICY IF EXISTS scan_jobs_insert_own ON public.scan_jobs;
DROP POLICY IF EXISTS scan_jobs_update_own ON public.scan_jobs;
DROP POLICY IF EXISTS scan_jobs_delete_own ON public.scan_jobs;

-- assets (same class)
DROP POLICY IF EXISTS assets_insert_own ON public.assets;
DROP POLICY IF EXISTS assets_update_own ON public.assets;
DROP POLICY IF EXISTS assets_delete_own ON public.assets;

-- audit_logs: INSERT policy only — there are no UPDATE/DELETE policies
-- to drop (append-only by design).
DROP POLICY IF EXISTS audit_logs_insert_own ON public.audit_logs;

-- attack_paths (same class; tenancy flows through its scan)
DROP POLICY IF EXISTS attack_paths_insert_own ON public.attack_paths;
DROP POLICY IF EXISTS attack_paths_update_own ON public.attack_paths;
DROP POLICY IF EXISTS attack_paths_delete_own ON public.attack_paths;

COMMIT;
