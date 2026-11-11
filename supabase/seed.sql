-- WebSurfaceHQ — Seed data (TWO tenants, deterministic UUIDs)
-- ============================================================
-- Purpose: cross-tenant test data. Tenant A must never see tenant
-- B's rows (and vice versa) — the proof is the cross-tenant check in
-- supabase/seed.md (user A changing an id in the URL gets a 404 for
-- user B's data, system-design.md §5).
--
-- DETERMINISTIC UUIDs (documented here so the test can reference them):
--   Tenant A user id: 11111111-1111-4111-8111-111111111111
--   Tenant B user id: 22222222-2222-4222-8222-222222222222
--   Tenant A rows use ids a0000000-0000-4000-8000-0000000000xx
--   Tenant B rows use ids b0000000-0000-4000-8000-0000000000xx
--   (xx: 01 target, 02 scan, 03/04 assets, 05/06 findings,
--    07 scan_job, 08 audit_log, 09 subscription, 0a notification,
--    0b api_key, 0c support_ticket, 0d attack_path, 0e team,
--    0f team_member)
--
-- What each tenant owns:
--   Tenant A — target example-a.com (verified, DNS), 1 done scan,
--     2 assets (subdomain + port), 2 findings (1 critical confirmed
--     + reachable, 1 medium auto-closed not_reachable), 1 attack
--     path chaining them, 1 scan_job, 1 audit_log, 1 free
--     subscription, 1 notification, 1 api_key, 1 support ticket,
--     1 team (A as owner).
--   Tenant B — target example-b.com (verified, file), 1 done scan,
--     2 assets, 2 findings (1 high confirmed, 1 low info), 1 attack
--     path, 1 scan_job, 1 audit_log, 1 starter subscription,
--     1 notification, 1 api_key, 1 support ticket. No team.
--
-- !!! READ BEFORE APPLYING !!!
-- Supabase Auth users CANNOT be created by SQL. The two auth users
-- MUST be created first via the Supabase dashboard (Authentication
-- > Users > Add user) or the Auth Admin API, with EXACTLY the UUIDs
-- above — otherwise every INSERT below fails on the auth.users FK.
-- Until the Supabase project exists this seed is UNAPPLIED; do not
-- invent a project URL or keys to "apply" it. See supabase/seed.md.
--
-- Apply as a role that bypasses RLS (postgres / service_role via
-- psql), AFTER `supabase db push` (0001 -> 0002 -> 0003):
--   psql "$DATABASE_URL" -f supabase/seed.sql
-- Inserts are ON CONFLICT (id) DO NOTHING, so re-running the seed is
-- safe. Verification-token / API-key hashes below are the real
-- SHA-256 hex of the documented seed secrets. The RAW secret values
-- are deliberately NOT printed anywhere in this repo (L9 review fix):
-- only the hashes below are recorded, so a reader of the seed can
-- verify a hash without learning a usable token or key:
--   tenant A token hash: see the INSERT VALUES below (canonical copy)
--   tenant A api key hash: see the INSERT VALUES below (canonical copy)
--   tenant B token hash: see the INSERT VALUES below (canonical copy)
--   tenant B api key hash: see the INSERT VALUES below (canonical copy)

BEGIN;

-- ------------------------------------------------------------------
-- Tenant A (user 11111111-1111-4111-8111-111111111111)
-- ------------------------------------------------------------------
INSERT INTO public.targets (id, user_id, domain, verification_token_hash, verification_method, verification_status, verified_at, verified_by_user_id, verification_expires_at)
VALUES ('a0000000-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'example-a.com',
  '53bc23399c6f109e6aa1bddccc5050da0bb6b52196dfe02818694789f1a9d630', 'dns', 'verified',
  '2026-11-11 10:00:00+00', '11111111-1111-4111-8111-111111111111', '2026-11-18 10:00:00+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.scans (id, target_id, user_id, status, config, progress, started_at, finished_at)
VALUES ('a0000000-0000-4000-8000-000000000002', 'a0000000-0000-4000-8000-000000000001',
  '11111111-1111-4111-8111-111111111111', 'done',
  '{"depth": "standard", "nuclei_tags": ["cve", "misconfig", "exposure"], "max_urls": 500}'::jsonb,
  100, '2026-11-11 10:05:00+00', '2026-11-11 10:19:00+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.assets (id, user_id, scan_id, type, value, details, hash)
VALUES
  ('a0000000-0000-4000-8000-000000000003', '11111111-1111-4111-8111-111111111111',
   'a0000000-0000-4000-8000-000000000002', 'subdomain', 'api.example-a.com',
   '{"ip": "93.184.216.34"}'::jsonb, 'asset-a-subdomain-api'),
  ('a0000000-0000-4000-8000-000000000004', '11111111-1111-4111-8111-111111111111',
   'a0000000-0000-4000-8000-000000000002', 'port', '443',
   '{"service": "https", "host": "api.example-a.com"}'::jsonb, 'asset-a-port-443')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.findings (id, user_id, scan_id, target_id, template_id, title, severity, cvss, epss, kev, cve, url, evidence, ai_verdict, ai_confidence, ai_reason, status, reachable, reachability_evidence, fix_snippet)
VALUES
  ('a0000000-0000-4000-8000-000000000005', '11111111-1111-4111-8111-111111111111',
   'a0000000-0000-4000-8000-000000000002', 'a0000000-0000-4000-8000-000000000001',
   'http/exposed-panels/admin', 'Exposed admin panel', 'critical', 9.8, 0.9400, true,
   'CVE-2024-0001', 'https://api.example-a.com/admin', 'HTTP 200 on /admin, login form served',
   'confirmed', 92, 'Login form reachable on a public host with no IP allow-list.', 'confirmed',
   'true', '{"probed_url": "https://api.example-a.com/admin", "http_status": 200}'::jsonb,
   'Restrict /admin by IP allow-list or put it behind your IdP SSO.'),
  ('a0000000-0000-4000-8000-000000000006', '11111111-1111-4111-8111-111111111111',
   'a0000000-0000-4000-8000-000000000002', 'a0000000-0000-4000-8000-000000000001',
   'http/missing-security-headers', 'Missing security headers', 'medium', 5.3, 0.1200, false,
   NULL, 'https://example-a.com/', 'No content-security-policy header on 200 response',
   'likely_fp', 81, 'Header missing but no exploitable sink observed.', 'not_reachable',
   'false', '{"probed_url": "https://example-a.com/", "http_status": 404}'::jsonb, NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.attack_paths (id, scan_id, entry_finding_id, pivot_finding_ids, target_asset, target_data, severing_fix)
VALUES ('a0000000-0000-4000-8000-00000000000d', 'a0000000-0000-4000-8000-000000000002',
  'a0000000-0000-4000-8000-000000000005', ARRAY['a0000000-0000-4000-8000-000000000006'::uuid],
  'api.example-a.com/admin', 'customer data via admin panel',
  'Restrict /admin by IP allow-list or SSO — severs the entry point.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.scan_jobs (id, user_id, scan_id, stage, status, attempt, celery_task_id, started_at, finished_at)
VALUES ('a0000000-0000-4000-8000-000000000007', '11111111-1111-4111-8111-111111111111',
  'a0000000-0000-4000-8000-000000000002', 'nuclei_scan', 'done', 1,
  'a0000000-0000-4000-8000-000000000002:nuclei_scan:asset-a-port-443',
  '2026-11-11 10:12:00+00', '2026-11-11 10:16:00+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.audit_logs (id, user_id, action, target_domain, metadata)
VALUES ('a0000000-0000-4000-8000-000000000008', '11111111-1111-4111-8111-111111111111',
  'scan.created', 'example-a.com', '{"scan_id": "a0000000-0000-4000-8000-000000000002", "depth": "standard"}'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.subscriptions (id, owner_id, plan, status, gateway, gateway_customer_id, gateway_subscription_id, current_period_end, amount_paise)
VALUES ('a0000000-0000-4000-8000-000000000009', '11111111-1111-4111-8111-111111111111',
  'free', 'active', NULL, NULL, NULL, '2026-12-11 10:00:00+00', 0)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.notifications (id, user_id, type, payload)
VALUES ('a0000000-0000-4000-8000-00000000000a', '11111111-1111-4111-8111-111111111111',
  'scan_done', '{"scan_id": "a0000000-0000-4000-8000-000000000002", "findings": 2, "critical": 1}'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.api_keys (id, owner_id, key_hash, prefix, scopes)
VALUES ('a0000000-0000-4000-8000-00000000000b', '11111111-1111-4111-8111-111111111111',
  'fa2553798ad2f1bb0f8d55e30e84136914d6a75a3abdcfdacc65e1f98156b1a2', 'wsh_live_a000', '["scans:read"]'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.support_tickets (id, user_id, subject, status, priority, scan_id)
VALUES ('a0000000-0000-4000-8000-00000000000c', '11111111-1111-4111-8111-111111111111',
  'Is the admin-panel finding a false positive?', 'open', 'high', 'a0000000-0000-4000-8000-000000000002')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.teams (id, name, owner_id, white_label)
VALUES ('a0000000-0000-4000-8000-00000000000e', 'Example A Agency', '11111111-1111-4111-8111-111111111111',
  '{"brand_colour": "#0f172a"}'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.team_members (id, team_id, user_id, role)
VALUES ('a0000000-0000-4000-8000-00000000000f', 'a0000000-0000-4000-8000-00000000000e',
  '11111111-1111-4111-8111-111111111111', 'owner')
ON CONFLICT (id) DO NOTHING;

-- ------------------------------------------------------------------
-- Tenant B (user 22222222-2222-4222-8222-222222222222)
-- ------------------------------------------------------------------
INSERT INTO public.targets (id, user_id, domain, verification_token_hash, verification_method, verification_status, verified_at, verified_by_user_id, verification_expires_at)
VALUES ('b0000000-0000-4000-8000-000000000001', '22222222-2222-4222-8222-222222222222', 'example-b.com',
  '270e6f10d186d9ad242b380e206072429c52bd4226d984e758248147e448aeed', 'file', 'verified',
  '2026-11-11 11:00:00+00', '22222222-2222-4222-8222-222222222222', '2026-11-18 11:00:00+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.scans (id, target_id, user_id, status, config, progress, started_at, finished_at)
VALUES ('b0000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-000000000001',
  '22222222-2222-4222-8222-222222222222', 'done',
  '{"depth": "quick", "nuclei_tags": ["cve"], "max_urls": 100}'::jsonb,
  100, '2026-11-11 11:05:00+00', '2026-11-11 11:09:00+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.assets (id, user_id, scan_id, type, value, details, hash)
VALUES
  ('b0000000-0000-4000-8000-000000000003', '22222222-2222-4222-8222-222222222222',
   'b0000000-0000-4000-8000-000000000002', 'subdomain', 'shop.example-b.com',
   '{"ip": "93.184.216.35"}'::jsonb, 'asset-b-subdomain-shop'),
  ('b0000000-0000-4000-8000-000000000004', '22222222-2222-4222-8222-222222222222',
   'b0000000-0000-4000-8000-000000000002', 'tech', 'WordPress 6.6',
   '{"host": "shop.example-b.com"}'::jsonb, 'asset-b-tech-wp')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.findings (id, user_id, scan_id, target_id, template_id, title, severity, cvss, epss, kev, cve, url, evidence, ai_verdict, ai_confidence, ai_reason, status, reachable, reachability_evidence, fix_snippet)
VALUES
  ('b0000000-0000-4000-8000-000000000005', '22222222-2222-4222-8222-222222222222',
   'b0000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-000000000001',
   'http/exposed-env', 'Exposed .env file', 'high', 7.5, 0.6100, true,
   'CVE-2024-0002', 'https://shop.example-b.com/.env', 'HTTP 200 on /.env, first bytes match KEY= pattern',
   'confirmed', 95, 'Live .env served with secret-looking keys.', 'confirmed',
   'true', '{"probed_url": "https://shop.example-b.com/.env", "http_status": 200}'::jsonb,
   'Block dotfiles in your web server config and rotate every secret in the file.'),
  ('b0000000-0000-4000-8000-000000000006', '22222222-2222-4222-8222-222222222222',
   'b0000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-000000000001',
   'http/robots-txt', 'robots.txt discloses paths', 'low', 2.1, 0.0100, false,
   NULL, 'https://example-b.com/robots.txt', 'robots.txt lists /wp-admin/',
   'needs_manual', 55, 'Disclosure only; exploitability unclear.', 'new',
   'unknown', NULL, NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.attack_paths (id, scan_id, entry_finding_id, pivot_finding_ids, target_asset, target_data, severing_fix)
VALUES ('b0000000-0000-4000-8000-00000000000d', 'b0000000-0000-4000-8000-000000000002',
  'b0000000-0000-4000-8000-000000000005', ARRAY[]::uuid[],
  'shop.example-b.com/.env', 'app secrets, then database credentials',
  'Block dotfiles and rotate the exposed secrets — severs the entry point.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.scan_jobs (id, user_id, scan_id, stage, status, attempt, celery_task_id, started_at, finished_at)
VALUES ('b0000000-0000-4000-8000-000000000007', '22222222-2222-4222-8222-222222222222',
  'b0000000-0000-4000-8000-000000000002', 'nuclei_scan', 'done', 1,
  'b0000000-0000-4000-8000-000000000002:nuclei_scan:asset-b-tech-wp',
  '2026-11-11 11:06:00+00', '2026-11-11 11:08:00+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.audit_logs (id, user_id, action, target_domain, metadata)
VALUES ('b0000000-0000-4000-8000-000000000008', '22222222-2222-4222-8222-222222222222',
  'scan.created', 'example-b.com', '{"scan_id": "b0000000-0000-4000-8000-000000000002", "depth": "quick"}'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.subscriptions (id, owner_id, plan, status, gateway, gateway_customer_id, gateway_subscription_id, current_period_end, amount_paise)
VALUES ('b0000000-0000-4000-8000-000000000009', '22222222-2222-4222-8222-222222222222',
  'starter', 'active', 'razorpay', 'cust_seed_b', 'sub_seed_b', '2026-12-11 11:00:00+00', 49900)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.notifications (id, user_id, type, payload)
VALUES ('b0000000-0000-4000-8000-00000000000a', '22222222-2222-4222-8222-222222222222',
  'new_critical', '{"scan_id": "b0000000-0000-4000-8000-000000000002", "finding_id": "b0000000-0000-4000-8000-000000000005"}'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.api_keys (id, owner_id, key_hash, prefix, scopes)
VALUES ('b0000000-0000-4000-8000-00000000000b', '22222222-2222-4222-8222-222222222222',
  '7d507171339642b6e07244a464257ce76d22e0bac355dcc20a5447b32667d03e', 'wsh_live_b000', '["scans:read", "findings:read"]'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.support_tickets (id, user_id, subject, status, priority, scan_id)
VALUES ('b0000000-0000-4000-8000-00000000000c', '22222222-2222-4222-8222-222222222222',
  'Billing question about my Starter plan', 'open', 'low', NULL)
ON CONFLICT (id) DO NOTHING;

COMMIT;
