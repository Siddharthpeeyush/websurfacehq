# WebSurfaceHQ — Seed data

Seed for the **cross-tenant test**: two tenants whose rows must never
be visible to each other. The seed itself is data, not schema — it is
**not** applied by `supabase db push`.

## What it contains

| Tenant | User id | Owns |
|---|---|---|
| **A** | `11111111-1111-4111-8111-111111111111` | Target `example-a.com` (verified, DNS), 1 done scan, 2 assets, 2 findings (1 critical confirmed + reachable, 1 medium auto-closed `not_reachable`), 1 attack path, 1 scan job, 1 audit log, 1 free subscription, 1 notification, 1 API key, 1 support ticket, 1 team (A as owner) |
| **B** | `22222222-2222-4222-8222-222222222222` | Target `example-b.com` (verified, file), 1 done scan, 2 assets, 2 findings (1 high confirmed, 1 low info), 1 attack path, 1 scan job, 1 audit log, 1 Starter subscription (Rs 499 = 49900 paise), 1 notification, 1 API key, 1 support ticket. No team. |

Row ids are deterministic: tenant A rows are
`a0000000-0000-4000-8000-0000000000xx`, tenant B rows
`b0000000-0000-4000-8000-0000000000xx` (see the header comment in
`seed.sql` for the `xx` mapping). The verification-token and API-key
columns hold **SHA-256 hashes only**. The two verification-token raw
values are literal test strings documented in
`apps/api/app/db/memory.py` (test-only fixtures, never real tokens);
the two API-key raw values are NOT recorded anywhere in the repo.
Only the hashes are stored, in the INSERT VALUES below.

## Step 1 — Create the two auth users FIRST

Supabase Auth users **cannot be created by SQL**. Create them before
applying the seed, with **exactly** these UUIDs, or every insert fails
on the `auth.users` foreign key:

- **Dashboard:** Authentication → Users → Add user → set the user id
  to `11111111-1111-4111-8111-111111111111` (tenant A) and
  `22222222-2222-4222-8222-222222222222` (tenant B). Use throwaway
  seed emails (e.g. `seed-a@example.invalid`, `seed-b@example.invalid`).
- **Or Auth Admin API:** `POST /auth/v1/admin/users` with the same
  ids in the request body (service-role key required).

## Step 2 — Apply migrations, then the seed

```bash
supabase db push            # 0001 -> 0002 -> 0003, in order
psql "$DATABASE_URL" -f supabase/seed.sql
```

`$DATABASE_URL` is the project's Postgres connection string (from the
Supabase dashboard → Project Settings → Database). Apply as a role
that bypasses RLS (the direct Postgres connection / service role) —
a normal authenticated user cannot insert another tenant's rows.
Re-running the seed is safe: every insert is
`ON CONFLICT (id) DO NOTHING`.

## Step 3 — Expected cross-tenant check

Sign in as tenant A and confirm:

1. `GET /targets` returns only `example-a.com`; B's target id
   `b0000000-0000-4000-8000-000000000001` returns **404** (never 403 —
   no existence oracle, system-design.md §6).
2. Same for B's scan `b0000000-0000-4000-8000-000000000002`, finding
   `b0000000-0000-4000-8000-000000000005`, and attack path
   `b0000000-0000-4000-8000-00000000000d`.
3. Tenant A's own rows all return 200, including the attack path
   (which has no `user_id` of its own — tenancy flows through its scan).
4. Repeat mirrored as tenant B.

**Status: APPLIED live 11 Nov 2026** — migrations 0001–0004 + seed
applied via the dashboard SQL editor; all 13 tables exist; row counts
verified (targets 2, scans 2, assets 4, findings 4, scan_jobs 2,
audit_logs 2, subscriptions 2, teams 1, team_members 1, api_keys 2,
notifications 2, support_tickets 2, attack_paths 2).
