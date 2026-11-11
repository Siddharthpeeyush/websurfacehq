# Supabase Migrations

**Status:** Week 1 — **four migrations exist** (`0001_core.sql`,
`0002_billing_teams.sql`, `0003_part7.sql`, `0004_review_fixes.sql`).
They are **not yet applied anywhere**: no Supabase project exists yet,
and applying is **BLOCKED** until the owner creates the project in the
Supabase dashboard (see "How to apply" below). Do not invent a project
URL, project ref, or keys to "apply" them.

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

## How to apply (BLOCKED — no project yet)

1. Owner creates the Supabase project in the dashboard (Auth enabled,
   email + Google). Record the project ref/URL in the repo's
   `.env.example`-driven config — never hard-code keys in a migration.
2. Link the CLI once: `supabase link --project-ref <ref>` (owner's ref).
3. Apply, staging first, then production:
   ```bash
   supabase db push            # applies 0001 -> 0002 -> 0003 -> 0004 in order
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
`supabase/seed.md`) — they are data, not schema. **Status: unapplied**
(the project exists now — websurfacehq, Singapore — but this VM has no
DB password / access token, so the parent applies the migrations + seed
via the dashboard SQL editor; the two auth users must be created first,
with the exact UUIDs in `seed.sql`).

## Validation

Validation method and result are recorded in the Week 1 schema report
(the parent agent holds it). In short: the migrations + seed were
applied to an ephemeral local Postgres (pgserver in a scratch venv,
auth schema stubbed with `auth.users` + `auth.uid()`), in order
0001 → 0002 → 0003 → 0004 → seed, and RLS was verified with two roles
(one per seed tenant). The 0004 validation additionally proves the
`idempotency_key` column, the one-active-scan index, the verification
REVOKEs, and the verified-retarget trigger. Latest run (11 Nov 2026,
after the round-3 fixes): **83/83 checks pass**, including 8
`has_table_privilege` checks proving the REVOKEs hold against full
DML pre-granted to `authenticated` (Supabase defaults) before 0004
applies — the validator previously constructed the SELECT-only state
itself, so it could not prove the REVOKEs; it can now. If that local run was not
possible, the report says so explicitly and live-apply stays blocked
on the project.
