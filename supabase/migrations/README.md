# Supabase Migrations

**Status:** Week 1 — **six migrations exist** (`0001_core.sql`,
`0002_billing_teams.sql`, `0003_part7.sql`, `0004_review_fixes.sql`,
`0005_grants.sql`, `0006_policy_cleanup.sql`). Migrations 0001–0004 +
the seed are already applied live (dashboard SQL editor, 11 Nov 2026);
`0005_grants.sql` + `0006_policy_cleanup.sql` are new and are applied
on their own — do NOT re-apply 0001–0004 (see "Applying 0005" below).

> Naming note: this repo uses short sequential names (`0001_core.sql`,
> …) instead of the `YYYYMMDDHHMMSS_…` timestamp convention originally
> sketched in Phase 0. Apply order is the numeric prefix, oldest first.
> Never rename a file after it has been applied anywhere.

## Migration list (apply in this order)

| File | Contents |
|---|---|
| `0001_core.sql` | Core tables from blueprint §1.4: `targets`, `scans`, `assets`, `findings`, `scan_jobs`, `audit_logs`. RLS on all six. Indexes per Appendix B. Helper `public.set_updated_at()` + triggers. |
| `0002_billing_teams.sql` | Billing/teams tables from blueprint §8.2: `subscriptions`, `teams`, `team_members`, `api_keys`, `notifications`, `support_tickets`. `targets` gains nullable `team_id` (plain column + index, no FK). RLS on all six. `is_team_owner()` / `is_team_member()` SECURITY DEFINER helpers for team policies. |
| `0003_part7.sql` | Part 7 additions (blueprint §9): `attack_paths` table + `findings.reachable`, `findings.reachability_evidence`, `findings.fix_verified_at`, `findings.fix_snippet`. RLS on `attack_paths` via its scan. |
| `0004_review_fixes.sql` | Week 1 independent-review fixes (11 Nov 2026): `scan_jobs.idempotency_key` column + index (H3); verification-field UPDATE + INSERT triggers + verified-retarget trigger (H4); subscriptions/api_keys user-read-only + server-created tables (scans, findings, scan_jobs, assets, audit_logs, attack_paths) not user-writable (H4); partial unique index for one active scan per user (M4) and one live target per user (M3, round-2). Round-3 (11 Nov 2026): INSERT trigger also blocks `verification_expires_at` / `verification_method`; `attack_paths` added to the server-table REVOKEs. |
| `0005_grants.sql` | Base GRANTs (live-proof fix F2, 11 Nov 2026): 0001–0004 contained NO grant at all, so tables created in the SQL editor as `postgres` gave every role 42501 "permission denied". Grants full DML to `service_role` on all 13 tables; full DML to `authenticated` only on the five user-writable tables (targets, teams, team_members, notifications, support_tickets); SELECT-only to `authenticated` on the other eight; nothing to `anon`; then re-asserts all eight 0004 REVOKEs AFTER the grants (0004's REVOKEs were no-ops against missing grants). See "Grants (0005)" below and the header comment in the file. |
| `0006_policy_cleanup.sql` | Policy cleanup (review fix F-L1, 11 Nov 2026): drops the 16 write RLS policies (INSERT/UPDATE/DELETE) on the six server-created tables — scans, findings, scan_jobs, assets, audit_logs (INSERT only; it never had UPDATE/DELETE policies), attack_paths — whose user-write policies survived 0004 even though their writes were revoked. The "policies stay as a second layer" claim was vacuous (no other role exists that the policies would protect: service_role bypasses RLS, postgres owns the tables, anon matches no owner policy), and a future broad re-grant without re-asserted REVOKEs would have re-opened forged writes through them. All SELECT policies are kept. No GRANT/REVOKE changes. See the header comment in the file and "Policy cleanup (0006)" below. |

Seed data lives **outside** this directory: `supabase/seed.sql` +
`supabase/seed.md` (two tenants, deterministic UUIDs, cross-tenant
test). The seed is data, not a migration — it is **not** applied by
`supabase db push`.

## How migrations work

- Every schema change is a **version-controlled migration file** in this directory.
  Never edit the database by hand in the Supabase dashboard — a hand edit is a schema
  change with no review, no rollback, and no record, and it will diverge production
  from the repo.
- **One logical change per file. Never rename a file after it has been applied anywhere.**
- **Apply order:** files apply in numeric order, oldest first. A migration that has
  been applied to any environment (dev / staging / prod) is **immutable** — fix a
  mistake with a *new* migration, never by editing the old file.
- **Separate databases:** staging and production are different Supabase projects with
  different keys. A migration is tested on staging before it touches production.

## Applying 0005 + 0006 (live project already has 0001–0004 + seed)

The project **websurfacehq** exists and 0001 → 0002 → 0003 → 0004 +
`seed.sql` were applied live via the dashboard SQL editor on
11 Nov 2026. Apply **only `0005_grants.sql` then
`0006_policy_cleanup.sql`**, in that order, in the dashboard SQL
editor, as `postgres` (the same path as the earlier migrations).
Do NOT re-apply 0001–0004: they are already applied, and re-running
them would fail (tables/indexes/triggers already exist). `0005` is
safe to apply on top: GRANT/REVOKE are idempotent, and its REVOKE
block runs after its GRANT block in the same file, so the final
state is correct whether or not 0004's REVOKEs ever took effect
(see the header comment in `0005_grants.sql` for the apply-order
reasoning). `0006` is safe to apply after it: DROP POLICY IF EXISTS
is idempotent and touches no grants. After applying both, re-run the
live proof — the API health check's database component and the
store's SELECT on `targets` must stop returning 42501.

## How to apply (BLOCKED — no project yet)

1. Owner creates the Supabase project in the dashboard (Auth enabled,
   email + Google). Record the project ref/URL in the repo's
   `.env.example`-driven config — never hard-code keys in a migration.
2. Link the CLI once: `supabase link --project-ref <ref>` (owner's ref).
3. Apply, staging first, then production:
   ```bash
   supabase db push            # applies 0001 -> 0002 -> 0003 -> 0004 -> 0005 -> 0006 in order
   ```
   Automatic migrations run *before* new code goes live in CD (playbook rule).
4. Seed (optional, for the cross-tenant test — see `supabase/seed.md`):
   create the two auth users with the exact UUIDs in `seed.sql` first,
   then `psql "$DATABASE_URL" -f supabase/seed.sql`.

**Validation done without a project:** the three migrations + seed
were applied to an ephemeral local Postgres (see "Validation" below).
That proves the SQL is sound; it does **not** prove the Supabase
project, Auth users, or `supabase db push` path — those stay blocked
on the project existing.

## Documented deviations from the blueprint

Two deliberate deviations from blueprint §1.4, required by the plan's
own rules. Both are also noted in the header comment of `0001_core.sql`.

- **D1 — `user_id` on findings, assets, scan_jobs.** Blueprint §1.4
  lists `user_id` only on targets and scans. The plan rule is "every
  tenant-owned table carries `user_id`" (system-design.md §6; this
  README's rule 1), so the three child tables carry a denormalized
  `user_id uuid NOT NULL` (FK to `auth.users`). It is what RLS
  policies and tenant-scoped queries filter on — a finding/asset/job
  is enforceable without joining its scan. The API must set it from
  the authenticated user on every insert, exactly as it sets the
  scan's `user_id`.
- **D2 — no plaintext verification token stored.** Blueprint §1.4/§0.1
  lists `verification_token text` on targets. Targets instead store
  `verification_token_hash text` (SHA-256 hex). The raw token is
  returned to the user once at creation and is never stored;
  verification compares hashes. The same rule applies to
  `api_keys.key_hash` (§8.2 already specifies hash-only). **No
  plaintext token/key column exists anywhere in this schema** — a
  grep for `verification_token ` (plaintext) or `api_key text` must
  return nothing.

Other additions vs §1.4 (documented, not deviations): targets gain
`verification_expires_at` (7-day token TTL, §0.1), `verified_at`,
`verified_by_user_id`, `deleted_at`; scans gain `deleted_at`;
`findings.status` gains `'not_reachable'` (Part 7 §9.2);
`findings.ai_verdict` is CHECK-enforced
(`confirmed|likely_fp|needs_manual`); `scans.status` is
CHECK-enforced (`queued|recon|crawling|scanning|triaging|done|failed|
cancelled`); `attack_paths` deliberately has **no** `user_id` column —
its tenancy flows through its scan (see RLS summary).

## Rules

1. **Every tenant-owned table carries `user_id`** (UUID, foreign key to `auth.users`),
   plus `id` (UUID PK) and `created_at` / `updated_at` timestamps.
   Exception, by design: `attack_paths` has no `user_id` — it is owned
   through its `scan_id` (see RLS summary). `audit_logs` is append-only
   and has `created_at` only (no `updated_at`).
2. **RLS is enabled on every table**, with a policy per role/action. A table without an
   RLS policy is a bug — the migration review checklist requires the policy in the same
   file as the table.
3. **Indexes for every foreign key** and every column filtered or sorted by
   (`targets(user_id, domain)`, `scans(target_id, status)`, `assets(scan_id, type)`,
   `findings(scan_id, severity)`, `scan_jobs(scan_id, stage)`).
4. **Constraints in the database**, not just app code: `NOT NULL`, `UNIQUE`, `CHECK`
   (e.g. `severity IN ('critical','high','medium','low','info')`,
   `status` enums, unique `(user_id, domain)` on targets).
5. **Money as integer paise/cents**, never float (`subscriptions.amount_paise`).
6. **Soft deletes** where users might want recovery (targets, scans); hard delete on
   explicit user request (account deletion removes everything immediately).
7. **Test a backup restore** into a separate database at least once before launch.

## RLS summary

- **Owner-only, everywhere.** Every table's SELECT/INSERT/UPDATE/
  DELETE policies filter on its own `user_id` column (`owner_id` for
  `subscriptions`, `teams`, `api_keys`) = `auth.uid()`. Cross-tenant
  access must surface as 404 in the API, never 403 (no existence
  oracle).
- **`audit_logs` is append-only:** INSERT (own) + SELECT (own) only —
  deliberately **no** UPDATE or DELETE policy, so audit history
  cannot be altered or erased through RLS.
- **`attack_paths` via its scan:** all four policies use
  `EXISTS (SELECT 1 FROM scans WHERE scans.id = attack_paths.scan_id
  AND scans.user_id = auth.uid())`. No separate owner column to drift
  out of sync with the scan.
- **`team_members`:** a member can SELECT rows for teams they belong
  to; only the team owner can INSERT/UPDATE/DELETE members. The
  checks go through SECURITY DEFINER helpers
  (`is_team_owner()` / `is_team_member()`) because a policy that
  queries its own table would recurse under RLS; the helpers return
  booleans only, never rows. `teams` SELECT is owner-or-member;
  INSERT/UPDATE/DELETE are owner-only.
- **Soft-deleted targets/scans:** SELECT policies add
  `deleted_at IS NULL`. A plain `UPDATE deleted_at = …` does **not**
  work under this RLS — Postgres rejects an UPDATE whose new row
  would stop satisfying the SELECT policy, and a soft-deleted row is
  invisible to an UPDATE's row scan, so it could never be restored
  that way either (proven by the validation run, which caught the
  direct UPDATE failing). Soft-delete / restore therefore go through
  SECURITY DEFINER helpers in `0001_core.sql`
  (`soft_delete_target`, `restore_target`, `soft_delete_scan`,
  `restore_scan`): they bypass RLS, check ownership with
  `auth.uid()` themselves, and return FALSE — not an error naming
  the row — when the id is missing or belongs to another tenant.
  Those helpers are for the DIRECT / user-JWT path (dashboard, SQL).
  The API's service-role store does NOT use them — service_role
  bypasses RLS, and the helpers check `auth.uid()`, which is NULL for
  service-role requests (see `app/db/supabase_store.py`
  `delete_target`). If the store ever switches to per-user JWTs,
  delete MUST switch to these helpers. Hard DELETE of a live
  (non-deleted) row works directly under the owner's own RLS.
- **Direct-PostgREST hardening (0004):** the anon key is public by
  design, so RLS alone cannot stop a user from writing
  security-critical fields on their OWN rows. `0004_review_fixes.sql`
  blocks changes to the verification fields
  (`verification_status`, `verification_token_hash`,
  `verification_expires_at`, `verified_at`, `verified_by_user_id`)
  with a BEFORE UPDATE trigger (`targets_prevent_verification_tamper`)
  for every role except service_role and postgres (postgres = the SQL
  editor admin-fix path; it owns the database and can drop the trigger
  anyway, so exempting it changes no real boundary), blocks a domain
  change on a verified target with a second trigger
  (`targets_prevent_verified_retarget`, same exemptions), and makes
  `subscriptions` + `api_keys` user-read-only (their user-write
  policies are dropped; INSERT/UPDATE/DELETE revoked from
  `authenticated`). A BEFORE INSERT trigger
  (`targets_require_unverified_insert` — a fresh target must start
  `pending` with no verification evidence: status, hash, verified_at,
  verified_by_user_id, AND `verification_expires_at` /
  `verification_method` — round-3 closed the two fields the first
  version missed) closes the INSERT bypass
  the round-2 re-review proved (a pre-verified target inserted via
  PostgREST). The server-created tables (`scans`, `findings`,
  `scan_jobs`, `assets`, `audit_logs`, `attack_paths`) are not user-writable at all
  (INSERT/UPDATE/DELETE revoked from `authenticated` — no direct scan
  inserts, no PATCH of own scan status / finding AI fields, no forged
  audit entries, no forged/deleted attack paths — `attack_paths` added
  in round-3; it was missed in the first pass). Only the API (service_role) or webhooks may write
  those rows. A column-level REVOKE was considered for the verification
  fields and rejected: in Postgres a table-level UPDATE grant (which
  `authenticated` holds by default) implies UPDATE on every column, so
  a column REVOKE is a no-op — the trigger is the enforcement.
- **One live target per user (0004, round-2):** partial unique index
  `targets_one_live_per_user (user_id) WHERE deleted_at IS NULL`
  enforces the Free 1-domain cap atomically (the router's count check
  races); the store maps the violation to `TargetCapError` → 429.
  NOTE: the index's predicate does not block recreate-after-delete,
  but `UNIQUE(user_id, domain)` (0001) still blocks re-adding the SAME
  domain after a soft-delete — pre-existing, tracked follow-up.

## Grants (0005)

Base privileges, per table and role (`0005_grants.sql`). RLS
policies decide *which rows* a role may touch; grants decide
*whether it may touch the table at all* — Postgres checks the
grant first, so a missing grant fails with 42501 before any
policy is evaluated. That is exactly what the live proof hit:
0001–0004 had no GRANTs, so every role got 42501 on every table.

| Table | service_role | authenticated | anon |
|---|---|---|---|
| targets | SELECT, INSERT, UPDATE, DELETE | SELECT, INSERT, UPDATE, DELETE | — |
| teams | SELECT, INSERT, UPDATE, DELETE | SELECT, INSERT, UPDATE, DELETE | — |
| team_members | SELECT, INSERT, UPDATE, DELETE | SELECT, INSERT, UPDATE, DELETE | — |
| notifications | SELECT, INSERT, UPDATE, DELETE | SELECT, INSERT, UPDATE, DELETE | — |
| support_tickets | SELECT, INSERT, UPDATE, DELETE | SELECT, INSERT, UPDATE, DELETE | — |
| scans | SELECT, INSERT, UPDATE, DELETE | SELECT only | — |
| findings | SELECT, INSERT, UPDATE, DELETE | SELECT only | — |
| scan_jobs | SELECT, INSERT, UPDATE, DELETE | SELECT only | — |
| assets | SELECT, INSERT, UPDATE, DELETE | SELECT only | — |
| audit_logs | SELECT, INSERT, UPDATE, DELETE | SELECT only | — |
| attack_paths | SELECT, INSERT, UPDATE, DELETE | SELECT only | — |
| subscriptions | SELECT, INSERT, UPDATE, DELETE | SELECT only | — |
| api_keys | SELECT, INSERT, UPDATE, DELETE | SELECT only | — |

Notes:

- `authenticated` gets full DML only where the RLS policies
  allow user writes. The eight SELECT-only tables are the
  server-created rows (0004 (c2)) and the user-read-only billing
  tables (0004 (c)); their INSERT/UPDATE/DELETE are revoked from
  `authenticated` — re-asserted in 0005 after its GRANTs.
- `anon` gets nothing: no anon SELECT policy exists in 0001–0003
  (every policy requires `auth.uid()` = the row owner), so there
  is nothing to grant. The validator asserts anon holds no
  privilege on all 13 tables.
- Schema USAGE on `public` is NOT granted in any migration: it is
  granted to PUBLIC by default in Postgres and Supabase, and the
  live 42501 hints asked for table grants, never schema USAGE. The
  validator asserts USAGE holds for all three roles on a fresh
  database; if that ever fails, add the USAGE grant to 0005 (see
  its header comment).
- Verification fields on `targets` are guarded by the 0004
  triggers, not by grants — a column-level REVOKE is a no-op
  against a table-level UPDATE grant.

## Tables (Week 1 — from blueprint §1.4, §8.2, and Part 7)

Core: `targets`, `scans`, `assets`, `findings`, `scan_jobs`, `audit_logs`.
Billing/teams: `subscriptions`, `teams`, `team_members`,
`api_keys`, `notifications`, `support_tickets`.
Part 7 additions: `attack_paths` table, plus `findings.reachable`,
`findings.reachability_evidence`, `findings.fix_verified_at`, `findings.fix_snippet`.

## Seed data (Week 1)

Seed realistic data for **two separate tenants** and prove user A cannot fetch
user B's data by changing an id in the URL (cross-tenant test → 404). Seed files live
outside this directory (`supabase/seed.sql`, documented in
`supabase/seed.md`) — they are data, not schema. **Status: applied
live 11 Nov 2026** (migrations 0001–0004 + seed via the dashboard
SQL editor; row counts verified — see `supabase/seed.sql` header).

## Validation

Validator: `supabase/validate_migrations.py` (durable — the Week 1
83-check run was an ephemeral script that no longer exists, so this
one is checked in). Run it with a scratch venv; it is NOT part of
the API and adds no dependency to it:

```bash
python -m venv /tmp/wshq-validate-venv
/tmp/wshq-validate-venv/bin/pip install pgserver "psycopg[binary]"
/tmp/wshq-validate-venv/bin/python supabase/validate_migrations.py
```

Method (fixed 11 Nov 2026 — the H4 methodology finding): the
validator starts an ephemeral local Postgres (pgserver), creates
ONLY the stubs Supabase itself provides (roles `anon` /
`authenticated` / `service_role` — `service_role` with BYPASSRLS,
as in real Supabase — plus the `auth` schema with `auth.users` and
an `auth.uid()` stub reading the `app.test_uid` session setting),
then applies 0001 → 0002 → 0003 → 0004 → 0005 → 0006 + seed in order,
with **NO pre-grant of any kind** — the only grants in the
database are the ones the migrations issue. It then asserts, per
table x role x privilege with `has_table_privilege`, that grants
are PRESENT where the design requires them (0005) AND the 0004
REVOKEs hold, and proves the same behaviourally: real
INSERT/UPDATE/DELETE attempts as `authenticated` fail with 42501
on the eight read-only tables and succeed on the five
user-writable ones, `authenticated` SELECTs return the owner's own
seed rows, `service_role` does full DML, the H4 triggers still
fire, cross-tenant reads return zero rows, soft-delete/restore
work, and the M3/M4 partial unique indexes still reject. It also
asserts the 0006 policy cleanup (G16): the six server-created
tables keep ONLY their SELECT policy (16 write policies dropped,
audit_logs INSERT-only), and the 0006 file drops exactly those 16
and no SELECT policy.

Why no pre-grant: the old validator pre-granted full DML to
`authenticated` before applying 0004, so it proved the REVOKEs
hold GIVEN grants — but it was blind to MISSING grants, and the
live proof then failed exactly there (zero GRANTs in 0001–0004,
42501 for every role on every table). A validator that CONSTRUCTS
the expected privilege state cannot prove a GRANT exists. This one
constructs nothing about privileges: if a migration forgets a
grant, a check fails. Control run: with 0005 + 0006 removed from
the apply list (`--exclude 0005_grants.sql 0006_policy_cleanup.sql`,
the pre-fix state) the validator reports **152/278, 126 failed** —
the harness catches the live bug (missing grants + surviving write
policies). With 0005 + 0006, latest run (11 Nov 2026): **278/278
checks pass, 0 failed**.

What this does NOT prove: the live Supabase project, Auth users,
`supabase db push`, or the PostgREST/JWT path — those need the
real project (the parent's live re-run after applying 0005). It
proves the SQL: the migrations, applied in order to a fresh
database, produce exactly the privilege state the RLS design
assumes.

The earlier 83/83 run (11 Nov 2026, round-3 fixes, pre-grant
methodology) is superseded by the 278/278 run above — same RLS /
trigger / index coverage, plus the grant-presence proof it lacked
and the 0006 policy-cleanup proof.

## Policy cleanup (0006)

`0006_policy_cleanup.sql` drops the write RLS policies on the six
server-created tables (scans, findings, scan_jobs, assets,
audit_logs, attack_paths): 16 policies in total — INSERT/UPDATE/
DELETE on five tables, INSERT only on `audit_logs` (it never had
UPDATE/DELETE policies). Every SELECT policy is kept, so users
still read their own rows. The REVOKE is now the single barrier
for `authenticated` writes on those tables, matching subscriptions
+ api_keys (whose write policies 0004 dropped in the same change
that revoked them). The validator's G16 group asserts exactly one
policy (SELECT) remains per table on a fresh DB.
