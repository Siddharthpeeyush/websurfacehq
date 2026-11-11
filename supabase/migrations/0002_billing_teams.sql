-- WebSurfaceHQ — Migration 0002: billing + teams
-- ============================================================
-- Tables from blueprint v4 §8.2 (Part 6):
--   subscriptions, teams, team_members, api_keys, notifications,
--   support_tickets
-- Plus: targets gains nullable team_id (post-MVP; plain column +
-- index only, deliberately NO foreign key — team features are not
-- built in the MVP and a dangling team_id must never block target
-- writes; enforcement moves to the app layer when teams land).
--
-- Money: subscriptions.amount_paise is INTEGER paise, never float.
-- Secrets: api_keys stores key_hash only, never the raw key; the raw
-- key is shown once at creation, exactly like the verification token
-- in 0001 (deviation D2). Same rule for any future secret column.
--
-- RLS: owner-only via owner_id / user_id, except team_members (see
-- the SECURITY DEFINER helpers below — a policy that queries its own
-- table recurses under RLS, so membership checks go through a
-- function that bypasses RLS by design and returns only a boolean).
--
-- Apply after 0001.

BEGIN;

-- ------------------------------------------------------------------
-- subscriptions — one row per owner in the MVP (UNIQUE owner_id).
-- Plan limits are read from this row, so plan changes are data
-- changes, not deploys (§8.1). Webhooks are the source of truth for
-- subscription state — the checkout page never upgrades an account.
-- ------------------------------------------------------------------
CREATE TABLE public.subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  plan text NOT NULL DEFAULT 'free'
    CHECK (plan IN ('free', 'starter', 'pro', 'business')),
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'trialing', 'past_due', 'unpaid', 'cancelled', 'incomplete')),
  gateway text CHECK (gateway IN ('razorpay', 'lemonsqueezy', 'stripe')),
  gateway_customer_id text,
  gateway_subscription_id text,
  current_period_end timestamptz,
  amount_paise integer NOT NULL DEFAULT 0 CHECK (amount_paise >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX subscriptions_owner_id_key ON public.subscriptions (owner_id);
CREATE TRIGGER subscriptions_set_updated_at
  BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- teams — post-MVP (Month 2-3). white_label holds logo / brand
-- colour for agency white-label PDFs (§6.3).
-- ------------------------------------------------------------------
CREATE TABLE public.teams (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(btrim(name)) > 0),
  owner_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  white_label jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX teams_owner_id_idx ON public.teams (owner_id);
CREATE TRIGGER teams_set_updated_at
  BEFORE UPDATE ON public.teams
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- team_members — post-MVP. One membership per (team, user).
-- ------------------------------------------------------------------
CREATE TABLE public.team_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES public.teams (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'viewer'
    CHECK (role IN ('owner', 'admin', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT team_members_team_id_user_id_key UNIQUE (team_id, user_id)
);
CREATE INDEX team_members_team_id_idx ON public.team_members (team_id);
CREATE INDEX team_members_user_id_idx ON public.team_members (user_id);
CREATE TRIGGER team_members_set_updated_at
  BEFORE UPDATE ON public.team_members
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- api_keys — Pro feature (Month 2-3), schema lands now.
-- key_hash only; the raw key is shown once at creation and never
-- stored. `prefix` (e.g. "wsh_live_...") lets support identify a key
-- without seeing it. Scopes are a JSON array, e.g. ["scans:read"].
-- ------------------------------------------------------------------
CREATE TABLE public.api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  key_hash text NOT NULL,
  prefix text NOT NULL,
  scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_owner_id_idx ON public.api_keys (owner_id);
CREATE TRIGGER api_keys_set_updated_at
  BEFORE UPDATE ON public.api_keys
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- notifications — in-app feed (scan_done / new_critical / diff /
-- billing); email/Slack are sent from the same events, not stored here.
-- ------------------------------------------------------------------
CREATE TABLE public.notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  type text NOT NULL
    CHECK (type IN ('scan_done', 'new_critical', 'diff', 'billing')),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  read_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notifications_user_id_read_at_idx ON public.notifications (user_id, read_at);
CREATE TRIGGER notifications_set_updated_at
  BEFORE UPDATE ON public.notifications
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- support_tickets — in-app support; false-positive disputes attach
-- here and link to the scan (scan_id nullable — a ticket need not
-- relate to a scan).
-- ------------------------------------------------------------------
CREATE TABLE public.support_tickets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  subject text NOT NULL CHECK (length(btrim(subject)) > 0),
  status text NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
  priority text NOT NULL DEFAULT 'medium'
    CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  scan_id uuid REFERENCES public.scans (id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX support_tickets_user_id_idx ON public.support_tickets (user_id);
CREATE INDEX support_tickets_scan_id_idx ON public.support_tickets (scan_id);
CREATE TRIGGER support_tickets_set_updated_at
  BEFORE UPDATE ON public.support_tickets
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------------
-- targets.team_id — post-MVP, nullable, NO foreign key (see header).
-- ------------------------------------------------------------------
ALTER TABLE public.targets ADD COLUMN team_id uuid;
CREATE INDEX targets_team_id_idx ON public.targets (team_id);

-- ==================================================================
-- Helper functions for team membership checks (RLS-safe).
-- Defined AFTER the teams/team_members tables (a SQL function body
-- must reference tables that already exist at creation time).
-- SECURITY DEFINER so they can read teams/team_members without
-- re-entering RLS; STABLE; they return booleans only, never rows.
-- ==================================================================
CREATE OR REPLACE FUNCTION public.is_team_owner(p_team_id uuid, p_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.teams
    WHERE id = p_team_id AND owner_id = p_user_id
  );
$$;

CREATE OR REPLACE FUNCTION public.is_team_member(p_team_id uuid, p_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.team_members
    WHERE team_id = p_team_id AND user_id = p_user_id
  );
$$;

-- ==================================================================
-- ROW LEVEL SECURITY
-- ==================================================================
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;

-- subscriptions: owner-only via owner_id
CREATE POLICY subscriptions_select_own ON public.subscriptions FOR SELECT
  USING (owner_id = auth.uid());
CREATE POLICY subscriptions_insert_own ON public.subscriptions FOR INSERT
  WITH CHECK (owner_id = auth.uid());
CREATE POLICY subscriptions_update_own ON public.subscriptions FOR UPDATE
  USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid());
CREATE POLICY subscriptions_delete_own ON public.subscriptions FOR DELETE
  USING (owner_id = auth.uid());

-- teams: the owner manages the team; members can read it.
-- (INSERT/UPDATE/DELETE are owner-only — there is no "create a team
-- for someone else" path in the MVP.)
CREATE POLICY teams_select_member ON public.teams FOR SELECT
  USING (owner_id = auth.uid() OR public.is_team_member(id, auth.uid()));
CREATE POLICY teams_insert_own ON public.teams FOR INSERT
  WITH CHECK (owner_id = auth.uid());
CREATE POLICY teams_update_own ON public.teams FOR UPDATE
  USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid());
CREATE POLICY teams_delete_own ON public.teams FOR DELETE
  USING (owner_id = auth.uid());

-- team_members: a member can SELECT rows for teams they belong to
-- (via the SECURITY DEFINER helper — a direct self-join would recurse
-- under RLS); only the team owner can INSERT / UPDATE / DELETE rows.
CREATE POLICY team_members_select_member ON public.team_members FOR SELECT
  USING (
    public.is_team_owner(team_id, auth.uid())
    OR public.is_team_member(team_id, auth.uid())
  );
CREATE POLICY team_members_insert_owner ON public.team_members FOR INSERT
  WITH CHECK (public.is_team_owner(team_id, auth.uid()));
CREATE POLICY team_members_update_owner ON public.team_members FOR UPDATE
  USING (public.is_team_owner(team_id, auth.uid()))
  WITH CHECK (public.is_team_owner(team_id, auth.uid()));
CREATE POLICY team_members_delete_owner ON public.team_members FOR DELETE
  USING (public.is_team_owner(team_id, auth.uid()));

-- api_keys: owner-only via owner_id
CREATE POLICY api_keys_select_own ON public.api_keys FOR SELECT
  USING (owner_id = auth.uid());
CREATE POLICY api_keys_insert_own ON public.api_keys FOR INSERT
  WITH CHECK (owner_id = auth.uid());
CREATE POLICY api_keys_update_own ON public.api_keys FOR UPDATE
  USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid());
CREATE POLICY api_keys_delete_own ON public.api_keys FOR DELETE
  USING (owner_id = auth.uid());

-- notifications: owner-only via user_id
CREATE POLICY notifications_select_own ON public.notifications FOR SELECT
  USING (user_id = auth.uid());
CREATE POLICY notifications_insert_own ON public.notifications FOR INSERT
  WITH CHECK (user_id = auth.uid());
CREATE POLICY notifications_update_own ON public.notifications FOR UPDATE
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY notifications_delete_own ON public.notifications FOR DELETE
  USING (user_id = auth.uid());

-- support_tickets: owner-only via user_id
CREATE POLICY support_tickets_select_own ON public.support_tickets FOR SELECT
  USING (user_id = auth.uid());
CREATE POLICY support_tickets_insert_own ON public.support_tickets FOR INSERT
  WITH CHECK (user_id = auth.uid());
CREATE POLICY support_tickets_update_own ON public.support_tickets FOR UPDATE
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY support_tickets_delete_own ON public.support_tickets FOR DELETE
  USING (user_id = auth.uid());

COMMIT;
