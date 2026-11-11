# Runbook — Rollback

> **Phase 0 banner (review fix):** no production deploy exists yet, and
> `/health` is liveness-only until Week 1 (it returns `200 {"status": "ok"}`
> with no component fields). The "Verify" step below that reads component
> fields applies only after the Week 1 health shape lands; until then verify
> with `GET /live` → 200 plus the deployed version/build id.

**Severity:** SEV1 when rolling back a production deploy; SEV2 for staging.
**Owner:** Siddharth Peeyush (single owner in MVP).

## Meaning

A deploy introduced a regression (broken auth, wrong scan results, 5xx spike, data
corruption risk) and the fix is to return to the last known-good version rather than
forward-fixing under pressure. Rollback is a *planned* operation, not an admission of
failure — the Phase 0 exit gate requires that it is documented before launch.

## Impact check (do first, ~2 minutes)

1. Confirm the regression: check Sentry (new errors since deploy time) and UptimeRobot
   (`/health` status). Note the deploy time and the previous good version (git SHA).
2. Assess blast radius: is it the frontend only, the API only, the worker only, or all
   three? Check each `/health` / `/live` endpoint separately.
3. Check whether any data was corrupted: look for failed scans, duplicate findings, or
   DLQ entries created since the deploy. If data corruption is suspected, **do not
   roll back the database** — see "Database" below.

## Likely causes

- A bad frontend deploy (broken bundle, wrong env var).
- A bad API deploy (broken handler, bad migration, wrong env var).
- A bad worker deploy (broken Celery task, bad scanner-agent version).
- A migration that changed a column/constraint the old code does not understand.

## Step-by-step fixes

### Frontend (Vercel)
1. Vercel dashboard → project → Deployments → find the previous production deployment
   → "Promote to Production" (instant rollback, no rebuild).
2. Verify: load the homepage + login page; confirm the version footer / build id matches
   the previous deploy.
3. If the bad deploy was caused by a bad env var, fix the env var in Vercel *before*
   re-deploying — promoting the old build with the bad env var reintroduces the bug.

### API / worker (Render)
1. Render dashboard → service → "Rollback" to the previous deploy (or re-deploy the
   previous git SHA from the GitHub repo).
2. API and worker are separate Render services — roll back **only the service that
   regressed**. Rolling back a healthy worker with the API wastes a running scan.
3. Verify: `GET /health` returns 200 (Phase 0: `{"status": "ok"}` liveness-only;
   from Week 1, 200 with all components `ok`); `GET /live` returns 200;
   check Sentry for new errors stopping.
4. In-flight scans: Celery tasks are idempotent (`scan_id:stage:target_hash`), so a
   worker rollback resumes scans from the last completed stage. Do **not** purge queues
   on rollback — that deletes users' scans.

### Database (migrations) — read carefully
1. **Never roll back a migration by hand-editing the database.** Migrations run
   forward only; a rollback is a *new* migration that reverses the change.
2. If the bad deploy included a migration that is backwards-incompatible with the old
   code, the correct order is: (a) deploy a forward-fix migration, or (b) if the
   migration only *added* a nullable column/table, rolling back the code alone is safe
   (old code ignores the new column). If the migration *dropped/renamed* a column the
   old code needs, you cannot roll back the code without a forward-fix migration —
   write the forward fix, do not improvise.
3. If data was corrupted by the bad deploy, restore from the Supabase backup into a
   **separate** database first, verify the data, then promote — never restore directly
   over production without verification.

## Escalation

- If rollback does not restore health within 15 minutes, or data corruption is
  confirmed: treat as SEV1, pause the Celery queues (stop new scans from starting),
  post a status note, and investigate before re-deploying anything.
- If the regression is a security issue (cross-tenant leak, SSRF bypass, secret in a
  log): follow the incident plan (contain → notify → postmortem), not just this runbook.
- Post-incident: write a postmortem within 7 days with one preventive fix (e.g. a
  missing test, a missing alert, a migration policy change).
