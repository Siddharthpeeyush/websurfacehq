-- WebSurfaceHQ — Migration 0003: Part 7 additions (blueprint §9)
-- ============================================================
-- Attack-path chaining (§9.1), reachability triage (§9.2), verified
-- closure (§9.3) and copy-paste fix snippets (§9.4). All six Part 7
-- features slot into Weeks 3-4 at $0 added cost; this migration is
-- the schema half of that work — no new collection stage is needed,
-- attack_paths is built from existing findings + assets.
--
--   * New table attack_paths (id, scan_id, entry_finding_id,
--     pivot_finding_ids, target_asset, target_data, severing_fix,
--     created_at). NOTE: attack_paths deliberately has NO user_id
--     column — tenancy is enforced through its scan (see RLS below),
--     so a path can never disagree with its scan about who owns it.
--   * findings gains: reachable ('true' | 'false' | 'unknown'),
--     reachability_evidence (jsonb), fix_verified_at, fix_snippet.
--
-- reachable is TEXT holding the strings 'true'/'false'/'unknown'
-- (per blueprint §9.2), not a boolean — 'unknown' is a real third
-- state (probe inconclusive), and a boolean + NULL would conflate
-- "not yet probed" with "probe failed".
--
-- Apply after 0002.

BEGIN;

-- ------------------------------------------------------------------
-- attack_paths — entry point -> pivot(s) -> crown jewel.
-- A path outranks any single finding; the severing_fix leads the
-- Top 5 Fixes list (§9.1). pivot_finding_ids is a plain uuid[]
-- (no FK array enforcement in Postgres); entry_finding_id is a real
-- FK. Both findings and the scan cascade-delete their paths.
-- ------------------------------------------------------------------
CREATE TABLE public.attack_paths (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES public.scans (id) ON DELETE CASCADE,
  entry_finding_id uuid NOT NULL REFERENCES public.findings (id) ON DELETE CASCADE,
  pivot_finding_ids uuid[] NOT NULL DEFAULT '{}'::uuid[],
  target_asset text,
  target_data text,
  severing_fix text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX attack_paths_scan_id_idx ON public.attack_paths (scan_id);
CREATE INDEX attack_paths_entry_finding_id_idx ON public.attack_paths (entry_finding_id);

-- ------------------------------------------------------------------
-- findings — Part 7 columns.
-- ------------------------------------------------------------------
ALTER TABLE public.findings
  ADD COLUMN reachable text NOT NULL DEFAULT 'unknown'
    CHECK (reachable IN ('true', 'false', 'unknown')),
  ADD COLUMN reachability_evidence jsonb,
  ADD COLUMN fix_verified_at timestamptz,
  ADD COLUMN fix_snippet text;

-- ==================================================================
-- ROW LEVEL SECURITY — via the parent scan.
-- A path belongs to whoever owns its scan; there is no separate
-- owner column to drift out of sync with it.
-- ==================================================================
ALTER TABLE public.attack_paths ENABLE ROW LEVEL SECURITY;

CREATE POLICY attack_paths_select_own ON public.attack_paths FOR SELECT
  USING (EXISTS (
    SELECT 1 FROM public.scans
    WHERE scans.id = attack_paths.scan_id AND scans.user_id = auth.uid()
  ));
CREATE POLICY attack_paths_insert_own ON public.attack_paths FOR INSERT
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.scans
    WHERE scans.id = attack_paths.scan_id AND scans.user_id = auth.uid()
  ));
CREATE POLICY attack_paths_update_own ON public.attack_paths FOR UPDATE
  USING (EXISTS (
    SELECT 1 FROM public.scans
    WHERE scans.id = attack_paths.scan_id AND scans.user_id = auth.uid()
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.scans
    WHERE scans.id = attack_paths.scan_id AND scans.user_id = auth.uid()
  ));
CREATE POLICY attack_paths_delete_own ON public.attack_paths FOR DELETE
  USING (EXISTS (
    SELECT 1 FROM public.scans
    WHERE scans.id = attack_paths.scan_id AND scans.user_id = auth.uid()
  ));

COMMIT;
