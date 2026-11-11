# Supabase Migrations

**Status:** Phase 0 — **no migrations exist yet.** This directory is intentionally empty
apart from this README. The first migration lands in Week 1 with the Supabase schema.
Do not create a migration file to "fill" the directory in Phase 0.

## How migrations work

- Every schema change is a **version-controlled migration file** in this directory.
  Never edit the database by hand in the Supabase dashboard — a hand edit is a schema
  change with no review, no rollback, and no record, and it will diverge production
  from the repo.
- **Naming convention:** `YYYYMMDDHHMMSS_short_description.sql` — UTC timestamp prefix
  (so files sort in apply order) + a short snake_case description, e.g.
  `20261112090000_create_targets_scans.sql`, `20261113100000_add_attack_paths.sql`.
  One logical change per file. Never rename a file after it has been applied anywhere.
- **Apply order:** files apply in timestamp order, oldest first. A migration that has
  been applied to any environment (dev / staging / prod) is **immutable** — fix a
  mistake with a *new* migration, never by editing the old file.
- **How to apply:** Supabase CLI (`supabase db push`) against the target project, or
  the project's documented apply step in CI. Staging first, verify, then production.
  Automatic migrations run *before* new code goes live in CD (playbook rule).
- **Separate databases:** staging and production are different Supabase projects with
  different keys. A migration is tested on staging before it touches production.

## Rules

1. **Every tenant-owned table carries `user_id`** (UUID, foreign key to `auth.users`),
   plus `id` (UUID PK) and `created_at` / `updated_at` timestamps.
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

## Planned tables (Week 1 — from blueprint §1.4, §8.2, and Part 7)

Core: `targets`, `scans`, `assets`, `findings`, `scan_jobs`, `audit_logs`.
Billing/teams (Week 4 / Month 2): `subscriptions`, `teams`, `team_members`,
`api_keys`, `notifications`, `support_tickets`.
Part 7 additions: `attack_paths` table, plus `findings.reachable`,
`findings.reachability_evidence`, `findings.fix_verified_at`, `findings.fix_snippet`.

## Seed data (Week 1)

Seed realistic data for **at least two separate tenants** and prove user A cannot fetch
user B's data by changing an id in the URL (cross-tenant test → 404). Seed files live
outside this directory (they are data, not schema) and are documented when they land.
