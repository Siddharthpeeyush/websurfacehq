# ADR-0003: Supabase for Auth, Postgres, and Storage (with RLS)

**Status:** Accepted (11 Nov 2026, Phase 0)
**Deciders:** Owner + build agent. Locked in `ENGINEERING-PLAN.md` §0 and §2 rule 2.

## Context

This is a security company. Authentication is the highest-stakes code in the product:
a bug in auth leaks every tenant's scan reports — including secrets found in their
JavaScript bundles. The playbook is explicit: use a proven auth provider, never hand-roll
password hashing or session logic. The product also needs Postgres with row-level tenancy
and private file storage for screenshots, raw JSONL, and PDF reports, all on a $0 budget.
Supabase gives all three (Auth + Postgres + Storage) on one free tier.

## Decision

- **Auth:** Supabase Auth only — email + password and Google OAuth. No custom password
  hashing, no SMS OTP, no hand-rolled sessions. JWT verified on every API request.
- **Database:** Supabase Postgres. Every tenant-owned table carries `user_id`. **RLS is
  enabled on all tables** — tenancy is enforced in the database, not just in app code.
- **Storage:** Supabase Storage, private buckets by default, tenant-scoped paths
  (`user_id/scan_id/...`), downloads only via short-lived signed URLs after an auth
  check. Files are validated (type/size) server-side before an upload URL is issued;
  only the file key + metadata are stored in the database.
- **Migrations:** schema changes only via version-controlled migration files in
  `supabase/migrations/` — never hand-edited in the Supabase dashboard.
- **Enforcement in depth:** RLS policies + tenant-scoped application queries
  (`WHERE user_id = :user_id` on every query) + the central `can()` check on every
  endpoint. Any one layer failing must still not leak data.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Hand-rolled Postgres + custom JWT auth | Explicitly forbidden by the playbook and the plan ("Auth never hand-rolled"). A solo founder cannot out-audit Supabase Auth; a single auth bug is a company-ending event for a security product |
| Firebase (Auth + Firestore + Storage) | Firestore's document model fits the scan/asset/finding relational shape poorly (joins, diff hashing, RLS-equivalent rules are harder to prove); the team already uses Supabase successfully on Opiinio, and Postgres + RLS is the stronger tenancy story |
| Clerk / Auth0 for auth + separate Postgres | Two vendors, two bills, and Auth0's free tier caps users; Supabase bundles auth + DB + storage on one free tier with one set of keys to rotate |
| SQLite / local Postgres for MVP | No hosted auth, no storage, no RLS story, and a migration to hosted Postgres later is exactly the rework Phase 0 exists to avoid |

## Consequences

- **Positive:** proven auth from day one; tenancy provable by test (user A changing an id
  in the URL gets 404 for user B's data); one free tier for DB + auth + storage; backups
  and point-in-time recovery come with the platform (restore still tested before launch).
- **Negative:** vendor lock-in to Supabase's Auth + RLS idioms; free tier caps (500 MB
  DB, 1 GB storage, 50k users) will be hit in year one at the load estimated in
  `docs/system-design.md` §9 — the first paid step is Supabase Pro ($25/mo), planned
  and budgeted, not a surprise.
- **Neutral / to watch:** the Supabase project does **not exist yet** in Phase 0 — the
  owner creates it when asked (dashboard step). No migration file exists yet; Week 1
  creates the first migration for `targets`, `scans`, `scan_jobs`, and the Part 6/7
  tables (`attack_paths`, `findings.reachable`, `findings.reachability_evidence`,
  `findings.fix_verified_at`, `findings.fix_snippet`).
