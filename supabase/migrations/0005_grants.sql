-- WebSurfaceHQ — Migration 0005: base GRANTs on all app tables
-- ============================================================
-- WHY THIS MIGRATION EXISTS (live-proof finding F2, 11 Nov 2026):
-- Migrations 0001–0004 contain NO GRANT statement at all. Tables
-- created via the Supabase dashboard SQL editor run as `postgres`,
-- and Postgres gives a new table's privileges ONLY to its owner —
-- no default grants to `service_role`, `anon`, or `authenticated`.
-- The design assumed the default grants Supabase applies ONLY to
-- tables created in the dashboard TABLE EDITOR (which issues GRANTs
-- for anon/authenticated/service_role automatically). Tables made in
-- the SQL editor never get those. Result, proven live: every
-- PostgREST call failed with 42501 "permission denied for table
-- targets" — for `service_role` (so the API's SupabaseStore could
-- not read or write anything) AND for `authenticated` (so no user
-- could read their own rows). RLS policies exist on all 13 tables
-- but are inert without base GRANTs: Postgres checks the GRANT
-- first, and a missing GRANT fails before any policy is evaluated.
-- This migration supplies the missing base grants, per the RLS
-- design in 0001–0003 and the hardening in 0004.
--
-- APPLY ORDER: 0001 -> 0002 -> 0003 -> 0004 -> 0005. This file must
-- run AFTER 0004, and its REVOKE block (below) must run AFTER its
-- own GRANT block in this same file. Reason: 0004's REVOKEs were
-- applied live when NO grants existed, so they were no-ops — a
-- broad GRANT issued afterwards would silently undo them. Issuing
-- the GRANTs first and then RE-ISSUING every 0004 REVOKE in this
-- file makes the final privilege state correct regardless of
-- whether 0004's REVOKEs ever took effect. (On a fresh database
-- the order is simply 0004's no-op REVOKEs, then this file's
-- GRANTs, then this file's REVOKEs — same final state.)
-- The parent applies this via the dashboard SQL editor (same path
-- as 0001–0004 + seed); there is no `supabase db push` from this VM.
--
-- GRANT MATRIX (table x role):
--   service_role:  SELECT, INSERT, UPDATE, DELETE on ALL 13 tables.
--     The API (SupabaseStore) and webhooks own all writes; RLS is
--     bypassed for service_role by design, so it needs the base
--     grants to do anything at all.
--   authenticated: full DML (SELECT, INSERT, UPDATE, DELETE) ONLY on
--     the five user-writable tables whose RLS policies allow user
--     writes — targets, teams, team_members, notifications,
--     support_tickets. SELECT-ONLY on the other eight:
--     scans, findings, scan_jobs, assets, audit_logs, attack_paths
--     (server-created rows, 0004 (c2)) and subscriptions, api_keys
--     (user-read-only, 0004 (c)). Those eight keep their SELECT
--     policy (users read their own rows via PostgREST / the API's
--     user-JWT path) but NO write grants — the 0004 REVOKEs below
--     re-assert that.
--   anon: NOTHING on any app table. No SELECT policy for anon exists
--     in 0001–0003 (every policy requires auth.uid() = the row owner,
--     and auth.uid() is NULL for anon), so anon needs no grant; the
--     validator asserts anon holds no privilege on all 13 tables.
--     (The anon key still works for Supabase Auth endpoints — those
--     live in the auth schema, not in these tables.)
--
-- SCHEMA USAGE: deliberately NOT granted here. USAGE on the public
-- schema is granted to PUBLIC by default in Postgres (and in
-- Supabase), so anon/authenticated/service_role can already reach
-- the tables; only the missing TABLE grants caused the live 42501s
-- (the error hints asked for table GRANTs, never schema USAGE). The
-- validator proves this: it asserts has_schema_privilege USAGE on
-- public for all three roles on a fresh database with no USAGE
-- grant in any migration. If that ever fails, add
--   GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
-- here — do not guess it in.
--
-- ROLES: assumes the Supabase roles anon / authenticated /
-- service_role already exist (they do in every Supabase project).
-- The validator creates them as stubs on bare Postgres; this file
-- does NOT create roles.
--
-- Only GRANTs/REVOKEs live here — no tables, triggers, or indexes
-- (0004's triggers and indexes already exist live and are NOT
-- re-asserted).

BEGIN;

-- ------------------------------------------------------------------
-- service_role: full DML on all 13 tables.
-- ------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON public.targets TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scans TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.assets TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.findings TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scan_jobs TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.audit_logs TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.subscriptions TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.teams TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.team_members TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.api_keys TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.notifications TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.support_tickets TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.attack_paths TO service_role;

-- ------------------------------------------------------------------
-- authenticated: full DML only on the user-writable tables.
-- targets (verification fields are guarded by the 0004 triggers,
-- not by grants — a column REVOKE is a no-op against a table-level
-- UPDATE grant, see 0004 header), teams, team_members,
-- notifications, support_tickets.
-- ------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON public.targets TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.teams TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.team_members TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.notifications TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.support_tickets TO authenticated;

-- ------------------------------------------------------------------
-- authenticated: SELECT-only on the eight read-only-for-users tables.
-- ------------------------------------------------------------------
GRANT SELECT ON public.scans TO authenticated;
GRANT SELECT ON public.findings TO authenticated;
GRANT SELECT ON public.scan_jobs TO authenticated;
GRANT SELECT ON public.assets TO authenticated;
GRANT SELECT ON public.audit_logs TO authenticated;
GRANT SELECT ON public.attack_paths TO authenticated;
GRANT SELECT ON public.subscriptions TO authenticated;
GRANT SELECT ON public.api_keys TO authenticated;

-- ------------------------------------------------------------------
-- anon: intentionally NO grants. No anon SELECT policy exists in
-- 0001–0003, so there is nothing for anon to be granted; the
-- validator asserts anon holds no privilege on all 13 tables.
-- ------------------------------------------------------------------

-- ------------------------------------------------------------------
-- Re-assert ALL 0004 REVOKEs (must come AFTER the GRANTs above).
-- 0004's REVOKEs were no-ops live (no grants existed to revoke), so
-- without this block the GRANTs above would leave `authenticated`
-- with write access to the server-created and read-only tables.
-- Re-issuing them here makes the final state correct regardless of
-- apply order or of whether 0004's REVOKEs ever took effect.
-- ------------------------------------------------------------------
REVOKE INSERT, UPDATE, DELETE ON public.subscriptions FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.api_keys FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.scans FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.findings FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.scan_jobs FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.assets FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.audit_logs FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.attack_paths FROM authenticated;

COMMIT;
