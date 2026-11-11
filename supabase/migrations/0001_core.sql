-- WebSurfaceHQ — Migration 0001: core tables
-- ============================================================
-- Creates the six core tables from blueprint v4 §1.4:
--   targets, scans, assets, findings, scan_jobs, audit_logs
-- Plus RLS on every table and the indexes from Appendix B.
--
-- DOCUMENTED DEVIATIONS from blueprint §1.4 (required by the
-- engineering plan's own rules, see supabase/migrations/README.md):
--   D1. `user_id uuid NOT NULL` is added to findings, assets and
--       scan_jobs. Blueprint §1.4 lists user_id only on targets and
--       scans, but the plan rule is "every tenant-owned table carries
--       user_id" (system-design.md §6) — the denormalized owner column
--       is what RLS policies and tenant-scoped queries filter on, so a
--       finding/asset/job is enforceable without joining its scan.
--   D2. targets stores `verification_token_hash text` (SHA-256 hex of
--       the token), NOT the plaintext `verification_token` in §1.4.
--       The raw token is returned to the user once at creation and is
--       never stored; verification compares hashes. No plaintext token
--       column exists anywhere in this schema.
--
-- Other additions vs §1.4 (all documented in the README):
--   * targets: `verification_expires_at` (token TTL 7 days, §0.1),
--     `verified_at`, `verified_by_user_id`, `deleted_at` (soft delete).
--   * scans: `deleted_at` (soft delete).
--   * findings.status CHECK gains 'not_reachable' (Part 7 §9.2:
--     unreachable findings auto-close, never reach the LLM).
--   * findings.ai_verdict CHECK: confirmed | likely_fp | needs_manual.
--   * scans.status CHECK: queued|recon|crawling|scanning|triaging|
--     done|failed|cancelled (blueprint §1.4 list, enforced as CHECK).
--   * Every table: `id uuid PRIMARY KEY DEFAULT gen_random_uuid()`,
--     `created_at timestamptz NOT NULL DEFAULT now()`.
--     `updated_at` is present on tables whose rows are updated in
--     place (targets, scans, findings, scan_jobs, assets); audit_logs
--     is append-only and has created_at only. A trigger keeps
--     updated_at current (see public.set_updated_at() below).
--
-- Assumes the Supabase Auth schema exists: FKs reference
-- auth.users(id). On a bare Postgres (validation harness) create a
-- stub auth.users table and an auth.uid() function first — see the
-- validation notes in supabase/migrations/README.md.
--
-- Apply order: 0001 -> 0002 -> 0003 -> seed.sql (seed is data, not a
-- migration; it is NOT applied by `supabase db push`).

BEGIN;

-- ------------------------------------------------------------------
-- Helper: keep updated_at current on UPDATE.
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

-- ------------------------------------------------------------------
-- targets — a domain a user owns and wants scanned.
-- Unique (user_id, domain). Verification before any intrusive stage.
-- ------------------------------------------------------------------
CREATE TABLE public.targets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  domain text NOT NULL,
  -- D2: SHA-256 hex of the verification token. The raw token is
  -- returned once at creation and never stored. NULL once verified
  -- (the hash is no longer needed after verification succeeds).
  verification_token_hash text,
  verification_method text CHECK (verification_method IN ('dns', 'file')),
  verification_status text NOT NULL DEFAULT 'pending'
    CHECK (verification_status IN ('pending', 'verified', 'failed', 'expired')),
  verified_at timestamptz,
  verified_by_user_id uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  -- Token TTL: 7 days from creation (§0.1). Set by the API at insert.
  verification_expires_at timestamptz,
  deleted_at timestamptz, -- soft delete; SELECT policies hide these rows
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT targets_domain_not_empty CHECK (length(btrim(domain)) > 0)
);
CREATE UNIQUE INDEX targets_user_id_domain_key ON public.targets (user_id, domain);
CREATE INDEX targets_user_id_domain_idx ON public.targets (user_id, domain);
CREATE TRIGGER targets_set_updated_at
  BEFORE UPDATE ON public.targets
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- scans — one scan run against a verified target.
-- ------------------------------------------------------------------
CREATE TABLE public.scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.targets (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'recon', 'crawling', 'scanning', 'triaging', 'done', 'failed', 'cancelled')),
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  progress int NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
  started_at timestamptz,
  finished_at timestamptz,
  error text,
  deleted_at timestamptz, -- soft delete; SELECT policies hide these rows
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scans_target_id_status_idx ON public.scans (target_id, status);
CREATE INDEX scans_user_id_idx ON public.scans (user_id);
CREATE TRIGGER scans_set_updated_at
  BEFORE UPDATE ON public.scans
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- assets — recon output: subdomains, IPs, ports, URLs, tech, JS, certs.
-- `hash` drives the attack-surface diff between scans (§2.4).
-- ------------------------------------------------------------------
CREATE TABLE public.assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE, -- D1
  scan_id uuid NOT NULL REFERENCES public.scans (id) ON DELETE CASCADE,
  type text NOT NULL
    CHECK (type IN ('subdomain', 'ip', 'port', 'url', 'tech', 'js_file', 'cert')),
  value text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  hash text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX assets_scan_id_type_idx ON public.assets (scan_id, type);
CREATE INDEX assets_value_idx ON public.assets (value);
CREATE TRIGGER assets_set_updated_at
  BEFORE UPDATE ON public.assets
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- findings — one deduplicated vulnerability (template + URL + param).
-- ------------------------------------------------------------------
CREATE TABLE public.findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE, -- D1
  scan_id uuid NOT NULL REFERENCES public.scans (id) ON DELETE CASCADE,
  target_id uuid NOT NULL REFERENCES public.targets (id) ON DELETE CASCADE,
  template_id text,
  title text NOT NULL,
  severity text NOT NULL
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  cvss numeric(3, 1) CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
  epss numeric(5, 4) CHECK (epss IS NULL OR (epss >= 0 AND epss <= 1)),
  kev boolean NOT NULL DEFAULT false,
  cve text,
  url text,
  evidence text,
  ai_verdict text CHECK (ai_verdict IN ('confirmed', 'likely_fp', 'needs_manual')),
  ai_confidence int CHECK (ai_confidence IS NULL OR (ai_confidence >= 0 AND ai_confidence <= 100)),
  ai_reason text,
  status text NOT NULL DEFAULT 'new'
    CHECK (status IN ('new', 'confirmed', 'false_positive', 'fixed', 'not_reachable')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX findings_scan_id_severity_idx ON public.findings (scan_id, severity);
CREATE INDEX findings_target_id_status_idx ON public.findings (target_id, status);
CREATE TRIGGER findings_set_updated_at
  BEFORE UPDATE ON public.findings
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- scan_jobs — one row per pipeline stage per scan.
-- Idempotency key: scan_id:stage:target_hash (§1.5); enforced by the
-- UNIQUE(scan_id, stage) index below — re-running a stage updates the
-- existing row instead of duplicating it.
-- ------------------------------------------------------------------
CREATE TABLE public.scan_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE, -- D1
  scan_id uuid NOT NULL REFERENCES public.scans (id) ON DELETE CASCADE,
  stage text NOT NULL,
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'done', 'failed', 'skipped')),
  attempt int NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  celery_task_id text,
  started_at timestamptz,
  finished_at timestamptz,
  log text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_jobs_scan_id_stage_idx ON public.scan_jobs (scan_id, stage);
CREATE UNIQUE INDEX scan_jobs_scan_id_stage_key ON public.scan_jobs (scan_id, stage);
CREATE TRIGGER scan_jobs_set_updated_at
  BEFORE UPDATE ON public.scan_jobs
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- audit_logs — append-only: who scanned what, when, with what scope.
-- No UPDATE/DELETE policy is created for this table (see RLS below).
-- ------------------------------------------------------------------
CREATE TABLE public.audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  action text NOT NULL,
  target_domain text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_user_id_created_at_idx ON public.audit_logs (user_id, created_at);

-- ==================================================================
-- ROW LEVEL SECURITY — every table, owner-only.
-- SELECT/INSERT/UPDATE/DELETE filter on the table's own user_id
-- column (D1 is what makes this possible on assets/findings/
-- scan_jobs without a join). Soft-deleted targets/scans are hidden
-- from SELECT (deleted_at IS NULL). NOTE: a plain UPDATE cannot
-- soft-delete or restore a row under this RLS — Postgres rejects
-- an UPDATE whose new row would stop satisfying the SELECT policy,
-- and a soft-deleted row is invisible to an UPDATE's row scan.
-- Soft-delete / restore therefore go through the SECURITY DEFINER
-- helpers at the end of this file (soft_delete_target,
-- restore_target, soft_delete_scan, restore_scan). These are for the
-- DIRECT / user-JWT path (dashboard, SQL): a plain UPDATE of deleted_at
-- fails there under the SELECT policy. The API's service-role store does
-- NOT use them — service_role bypasses RLS, and the helpers check
-- auth.uid(), which is NULL for service-role requests (see
-- app/db/supabase_store.py delete_target). If the store ever switches to
-- per-user JWTs, delete MUST switch to these helpers.
-- ==================================================================
ALTER TABLE public.targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- targets
CREATE POLICY targets_select_own ON public.targets FOR SELECT
  USING (user_id = auth.uid() AND deleted_at IS NULL);
CREATE POLICY targets_insert_own ON public.targets FOR INSERT
  WITH CHECK (user_id = auth.uid());
CREATE POLICY targets_update_own ON public.targets FOR UPDATE
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY targets_delete_own ON public.targets FOR DELETE
  USING (user_id = auth.uid());

-- scans
CREATE POLICY scans_select_own ON public.scans FOR SELECT
  USING (user_id = auth.uid() AND deleted_at IS NULL);
CREATE POLICY scans_insert_own ON public.scans FOR INSERT
  WITH CHECK (user_id = auth.uid());
CREATE POLICY scans_update_own ON public.scans FOR UPDATE
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY scans_delete_own ON public.scans FOR DELETE
  USING (user_id = auth.uid());

-- assets
CREATE POLICY assets_select_own ON public.assets FOR SELECT
  USING (user_id = auth.uid());
CREATE POLICY assets_insert_own ON public.assets FOR INSERT
  WITH CHECK (user_id = auth.uid());
CREATE POLICY assets_update_own ON public.assets FOR UPDATE
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY assets_delete_own ON public.assets FOR DELETE
  USING (user_id = auth.uid());

-- findings
CREATE POLICY findings_select_own ON public.findings FOR SELECT
  USING (user_id = auth.uid());
CREATE POLICY findings_insert_own ON public.findings FOR INSERT
  WITH CHECK (user_id = auth.uid());
CREATE POLICY findings_update_own ON public.findings FOR UPDATE
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY findings_delete_own ON public.findings FOR DELETE
  USING (user_id = auth.uid());

-- scan_jobs
CREATE POLICY scan_jobs_select_own ON public.scan_jobs FOR SELECT
  USING (user_id = auth.uid());
CREATE POLICY scan_jobs_insert_own ON public.scan_jobs FOR INSERT
  WITH CHECK (user_id = auth.uid());
CREATE POLICY scan_jobs_update_own ON public.scan_jobs FOR UPDATE
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY scan_jobs_delete_own ON public.scan_jobs FOR DELETE
  USING (user_id = auth.uid());

-- audit_logs: append-only. INSERT + SELECT only — deliberately NO
-- UPDATE or DELETE policy, so no role (including the owner) can alter
-- or erase audit history through RLS.
CREATE POLICY audit_logs_select_own ON public.audit_logs FOR SELECT
  USING (user_id = auth.uid());
CREATE POLICY audit_logs_insert_own ON public.audit_logs FOR INSERT
  WITH CHECK (user_id = auth.uid());

-- ------------------------------------------------------------------
-- Soft-delete helpers (SECURITY DEFINER).
-- Why functions, not a plain UPDATE: Postgres rejects an UPDATE
-- whose new row would no longer satisfy the SELECT policy — setting
-- deleted_at = now() makes the row invisible to targets_select_own /
-- scans_select_own, so a direct UPDATE fails with "new row violates
-- row-level security policy". A soft-deleted row is likewise invisible
-- to an UPDATE's row scan, so it could never be restored that way
-- either. These helpers run as the function owner (bypassing RLS)
-- and check ownership themselves with auth.uid(); they return FALSE
-- (not an error naming the row) when the id is missing or belongs to
-- another tenant — the same no-existence-oracle rule as the 404s.
-- The API must call these for soft-delete / restore; hard DELETE of
-- a live (non-deleted) row works directly under the user's own RLS.
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.soft_delete_target(p_target_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.targets SET deleted_at = now()
  WHERE id = p_target_id AND user_id = auth.uid() AND deleted_at IS NULL;
  RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION public.restore_target(p_target_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.targets SET deleted_at = NULL
  WHERE id = p_target_id AND user_id = auth.uid() AND deleted_at IS NOT NULL;
  RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION public.soft_delete_scan(p_scan_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.scans SET deleted_at = now()
  WHERE id = p_scan_id AND user_id = auth.uid() AND deleted_at IS NULL;
  RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION public.restore_scan(p_scan_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.scans SET deleted_at = NULL
  WHERE id = p_scan_id AND user_id = auth.uid() AND deleted_at IS NOT NULL;
  RETURN FOUND;
END;
$$;

COMMIT;
