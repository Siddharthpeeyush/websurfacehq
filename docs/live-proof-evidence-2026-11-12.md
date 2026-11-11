# WebSurfaceHQ Week 1 — Live API Re-Proof Evidence Log (redacted record)

**Date:** 12 November 2026, 00:34–00:44 IST (19:04–19:14 UTC).
**API:** http://127.0.0.1:8000, started from `~/workspace/websurfacehq/apps/api`.
**Supabase project:** websurfacehq (ref `dpwfshafzyxyfoktsggo`, Singapore, Nano).
**Local repo state:** working tree behind remote; no git command in this run
modified the tree or touched the remote (read-only `status`/`log` only).
**Outcome:** the F1/F2/F3 fixes are all proven live (see verdicts). The run is
NOT a clean pass on the task's literal wording: check 1's overall `/health`
status is `degraded` (Redis unreachable — pre-existing Week 1 state, database
itself `ok`); check 2 signup-201 is UNPROVEN-BY-RATE-LIMIT (GoTrue 429, second
run in a row); check 7 totals differ from seed-only counts by exactly the
rows this run's own checks 4 and 6 created (see §7).

## Audit note

Audited line by line before writing: no key, secret, token, or password value
appears anywhere below. JWTs are truncated to their first 10 chars + `...`.
Test passwords are recorded only as `<throwaway-16>` placeholders and are not
stored here. The target-creation response's `verification_token` and
`verification_instructions` (which carry the raw token) were stripped from
every logged response. What does appear — and is NOT secret — is the Supabase
project ref, the public JWKS key id (`kid`), the test users' UUIDs and
throwaway `@websurfacehq.com` addresses, and the seed's deterministic UUIDs.
The full unredacted session scratch (helper script, server log, per-check
probe outputs) is in `/tmp/live-proof2/` on the VM, NOT committed to this repo.
`.env` files verified ignored: `git check-ignore -v apps/api/.env` →
`.gitignore:12:.env*`.

## How each count was obtained

Every row count below comes from PostgREST (`/rest/v1/<table>?select=id&limit=1`
with `Prefer: count=exact`, read off the `Content-Range` total) using the
**service_role** key read from the gitignored `apps/api/.env` in code — never
from the dashboard SQL editor as `postgres` (the first proof's mistake: that
path bypasses RLS and grants). API-side reads are additionally shown where a
check exercised them (`GET /api/v1/targets/`, `/health` database ping).

## Verdicts

| Check | Verdict | Note |
|---|---|---|
| 0 Step 0 cleanup | PASS | 2 stray rows deleted, counts back to seed before checks |
| 1 server vs live Supabase | PARTIAL | `/live` 200; database component `ok`; overall status `degraded` — Redis unreachable (pre-existing, no broker in Week 1) |
| 2 signup via API 201 | UNPROVEN-BY-RATE-LIMIT | one real attempt → 429 from GoTrue upstream; Admin-API fallback used; NOT retried in a loop |
| 3 login + `/me` (F3) | PASS | 3/3 users login 200, `/me` 200 on real ES256 tokens; one transient first-attempt 401 for proof2c, mechanism proven (§3a) |
| 4 cross-tenant isolation | PASS | all cross-tenant reads 404 (never 401/403/42501); own reads 200 |
| 5 H4 trigger/REVOKE layer | PASS | forgery → trigger 400 P0001; server-table writes → 42501 REVOKE denial with SELECT grants proven present (§5 note) |
| 6 M3 1-domain cap | PASS | 1st target 201, 2nd 429 `QUOTA_EXCEEDED`, `Retry-After: 3600` |
| 7 seed counts | DIFFERS — explained | 11/13 tables exactly seed; targets 3 (2 seed + 1 M3 artifact), audit_logs 9 (2 seed + 7 rows this run wrote); all seed rows intact, seed-filtered counts exact |
| 8 server stop | PASS | PID 21538 shut down, port 8000 free, curl exit 7 |

---

## 0. Step 0 — restore seed state (before any check)

Pre-existing stray rows from the cancelled 00:27–00:30 IST attempt, confirmed
present via PostgREST as service_role, then deleted via PostgREST as
service_role (`DELETE /rest/v1/<table>?id=eq.<uuid>`, both 200 with the deleted
row echoed back):

- Target `154d1321-1c35-4717-939d-7fd2fab7d53d` — user `44fe42d2-...`
  (proof2a), domain `test-a.websurfacehq.com`, `verified_at` null,
  created `2026-11-11T19:00:33Z`. DELETED.
- Audit log `c1625e99-1dcb-4900-966d-c81ab7a56fc9` — user `44fe42d2-...`
  (proof2a), action `target.create`, target `test-a.websurfacehq.com`,
  created `2026-11-11T19:00:34Z`. DELETED.

Before/after counts (PostgREST as service_role): targets 3 → 2,
audit_logs 3 → 2. Re-fetch of both IDs after deletion returned `200 []`.
Seed targets re-fetched intact: `example-a.com`
(`a0000000-0000-4000-8000-000000000001`, tenant
`11111111-1111-4111-8111-111111111111`) and `example-b.com`
(`b0000000-0000-4000-8000-000000000001`, tenant
`22222222-2222-4222-8222-222222222222`). No Auth user deleted; no seed row
touched.

## 1. Server runs against live Supabase

Pre-flight (booleans only, via `app.core.config.settings` in the venv):
`supabase_configured = True`; supabase_url / anon key / service_role key all
set; no `supabase_jwt_secret` attribute exists (HS256 fully removed).

Port check before start: `ss -ltn | grep 8000` → nothing (port 8000 free,
as the parent verified at 00:30 IST).

Launch (canonical command, from `apps/api`):

```
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Server log confirms the F1 sanitizer ran at launch:
`sanitized bracketed entries from NO_PROXY/no_proxy at launch`, removed
`[::1]`, `[fd8b:4f84:7d32:99::1]`, `[fd8b:4f84:7d32:99::2]`. Store selected:
`store selected: supabase`.

- `GET /live` → `200 {"status":"alive"}`.
- `GET /health` → `200`:
  `{"status":"degraded","components":{"database":{"status":"ok","detail":"supabase reachable"},"redis":{"status":"unreachable","detail":"redis ping failed: ConnectionError"},"queue":{"status":"not_configured","detail":"celery worker not wired yet (Week 1)"}}}`
  Server log shows the health ping as a live PostgREST call:
  `GET https://dpwfshafzyxyfoktsggo.supabase.co/rest/v1/targets?select=id&limit=1 "HTTP/1.1 200 OK"`.

Verdict: PARTIAL as literally specified. The database component is `ok`
(F2 fix proven — the SupabaseStore ping succeeds against live Supabase), but
the overall status is `degraded`, not `ok`, because Redis is unreachable.
No Redis broker exists in Week 1 (queue `not_configured`); this is the same
Redis state as the first proof and is not a Supabase/DB finding. The task's
required overall `"ok"` is therefore not met; the database half of the check
is met.

## 2. Signup via the API

Note on the first attempt: my first `POST /api/v1/auth/signup` never reached
the server — the helper client routed the loopback call through the egress
proxy (`trust_env=False` + explicit proxy for all hosts), and it timed out
after 30 s with `httpx.ReadTimeout`. The server log shows no signup request
for it, and Admin-API listing confirmed `proof2c@websurfacehq.com` did not
exist afterwards. The helper was fixed (direct, proxy-free client for
`127.0.0.1`; proxy client kept only for `*.supabase.co`), and the attempt
below is the one real API signup attempt of this run.

- `POST /api/v1/auth/signup {"email":"proof2c@websurfacehq.com","password":"<throwaway-16>"}` → `429 {"code":"RATE_LIMITED","message":"Too many attempts. Try again later.","details":null}`.
- Server log proves the 429 came from upstream GoTrue, not our limiter:
  `POST https://dpwfshafzyxyfoktsggo.supabase.co/auth/v1/signup "HTTP/1.1 429 Too Many Requests"`, then `POST /api/v1/auth/signup 429` (duration 1471 ms).

This is the project's email-send rate limit, still exhausted — the first
proof hit the same 429 at 23:18 IST on 11 Nov, and the cancelled attempt's
activity at 00:30 IST evidently re-exhausted (or the window is longer than
an hour). Per the task, NOT retried in a loop.

Fallback (Admin API, service_role, `email_confirm=true`):
- `POST https://dpwfshafzyxyfoktsggo.supabase.co/auth/v1/admin/users`
  `{"email":"proof2c@websurfacehq.com",...}` → `200`,
  `id=c27fa99f-c5be-4aef-b205-fb87c1e76e55`,
  `email_confirmed_at=2026-11-11T19:10:37Z`.

Verdict: signup-201 via the API is UNPROVEN-BY-RATE-LIMIT (not failed — the
endpoint answered, GoTrue refused with 429; the 502 root cause from the first
proof is still unproven because no signup got past the rate limit).

## 3. Login against real Supabase + `/me` (F3 proof)

Known throwaway passwords were set for the two first-proof users via the
Admin API first (`PUT /auth/v1/admin/users/<id> {"password":"<throwaway-16>"}` →
200 for both live-a `c2a09eef-...` and live-b `af1cb806-...`).

- `POST /api/v1/auth/login {"email":"live-a@websurfacehq.com",...}` → `200`,
  keys `["access_token","expires_in","token_type","user"]`,
  `user={"id":"c2a09eef-469e-426a-abcc-7f4ad3f4979b","email":"live-a@websurfacehq.com"}`,
  `token_type="bearer"`, `expires_in=3600`, token prefix `eyJhbGciOi...`.
- Same for live-b → `200`, `user={"id":"af1cb806-c548-49ce-8502-7182903fc0b7",...}`,
  `expires_in=3600`.
- Same for proof2c → `200`, `user={"id":"c27fa99f-c5be-4aef-b205-fb87c1e76e55",...}`,
  `expires_in=3600`.
- Token headers (decoded WITHOUT signature verification): all three
  `alg=ES256`, `kid=6b08cdc7-1192-414f-a101-bd42d800a1f2`, `typ=JWT` — the
  live project still signs ES256 with the same key id as the first proof.
  Payloads: `iss=https://dpwfshafzyxyfoktsggo.supabase.co/auth/v1`,
  `aud=authenticated`, `role=authenticated`, `sub` = the user's UUID.
- `GET /api/v1/auth/me` with live-a's token → `200 {"id":"c2a09eef-...","email":"live-a@websurfacehq.com"}`.
- `GET /api/v1/auth/me` with live-b's token → `200` (same shape).
- `GET /api/v1/auth/me` with proof2c's token → `200` on retry (see §3a).
- Negative controls: no token → `401 {"code":"UNAUTHORIZED","message":"Missing authorization header"}`;
  garbage token → `401 {"code":"UNAUTHORIZED","message":"Invalid or expired token"}`.

Server log shows the JWKS fetch that backs the F3 fix:
`GET https://dpwfshafzyxyfoktsggo.supabase.co/auth/v1/.well-known/jwks.json "HTTP/1.1 200 OK"`
during the first `/me` (1146 ms), then 1–2 ms cached verifications after.

Verdict: PASS — F3 is fixed live: real ES256 Bearer tokens verify via cached
JWKS and reach authenticated endpoints.

### 3a. Transient first-attempt 401 for proof2c (flake, mechanism proven)

proof2c's FIRST `GET /api/v1/auth/me` returned `401 {"code":"UNAUTHORIZED","message":"Invalid or expired token"}`
(1.31 ms server-side); the IDENTICAL token returned `200` on immediate
retry 7 s later, and again on recheck. No server ERROR/WARNING line was
logged for the 401.

Mechanism (verified by epoch arithmetic, not guessed): `app/auth/jwt.py`
calls `jwt.decode(...)` with default PyJWT options — `verify_iat` defaults
to True and no `leeway` is set — so a token whose `iat` is even 1 s ahead of
the API server's clock is rejected as immature. proof2c's token:
`iat=1794424248` = `2026-11-11T19:10:48Z`, but its login completed at
`19:10:47.611Z` and the `/me` call ran at `19:10:47.615Z` — the token was
issued 1 s in the future relative to this VM's clock (GoTrue's clock runs
~0.4–1 s ahead). live-a/live-b did not trip it: live-a's `iat=...244`
(`19:10:44Z`) was verified at ~`19:10:45.1Z` (after the JWKS fetch), and
live-b's `iat=...246` (`19:10:46Z`) equalled the then-current second.
A client that logs in and immediately calls an authenticated endpoint can
therefore get a spurious 401 for up to ~1 s; it self-heals. Flagged for the
reviewer — a small `leeway` in `jwt.decode` would remove it; no code was
changed in this run.

Side note: a 5-cycle login→`/me` retest loop tripped the API's own login rate
limiter (5 attempts / 15 min per IP + per email): cycle 0 login 200 with
immediate `/me` 200; cycles 1–4 login `429`. No further logins were attempted
after that; all remaining checks reused the three tokens obtained before the
limiter tripped (valid to ~20:10Z). The 401s in cycles 1–4 are meaningless
(empty token after a 429 login) and are not evidence about `/me`.

## 4. Cross-tenant isolation

All calls via the API with real user JWTs. `t1` = live-a's target
`bada596c-6313-49e8-9a93-aea72207c183` (created in §6):

- B `GET /api/v1/targets/<t1>` → `404 {"code":"NOT_FOUND","message":"Resource not found"}`.
- A `GET /api/v1/targets/<t1>` → `200` (own target, `domain=proof-a1.websurfacehq.com`).
- B `GET /api/v1/targets/` → `200 {"data":[],"next_cursor":null,"has_more":false}` (B sees none of A's targets).
- A `GET /api/v1/targets/` → `200` with exactly its one target.
- B `GET /api/v1/scans/a0000000-0000-4000-8000-000000000002` (seed scan, tenant A) → `404`.
- A `GET /api/v1/scans/a0000000-...0002` (seed scan, tenant A — not A's own) → `404`.
- B `GET /api/v1/scans/a0000000-...0002/findings` → `404`.
- B `GET /api/v1/findings/a0000000-0000-4000-8000-000000000005` (seed finding, tenant A) → `404`.
- B `GET /api/v1/scans/b0000000-0000-4000-8000-000000000002` (seed scan, tenant B) → `404`.

Every denied read is a 404, never 401/403/42501. The API also wrote a
`cross_tenant_access_denied` audit row for each denied read (6 rows — see §7).

Verdict: PASS.

## 5. H4 protections at the RLS/trigger layer (direct PostgREST, user JWT)

All calls used `apikey: <anon>` + `Authorization: Bearer <live-a's JWT>`
against `https://dpwfshafzyxyfoktsggo.supabase.co/rest/v1/...` — NOT
service_role. Controls first (proving the JWT is valid and the grants exist):

- User-JWT `GET /rest/v1/targets?select=id,domain` → `200 [{"id":"bada596c-...","domain":"proof-a1.websurfacehq.com"}]` (own row only).
- User-JWT `GET /rest/v1/scans?select=id` → `200 []`.
- User-JWT `GET /rest/v1/subscriptions?select=id,plan` → `200 []`.

(a) Forge a verified target:
- `POST /rest/v1/targets {"user_id":"c2a09eef-...","domain":"forged-a.websurfacehq.com","verification_status":"verified","verified_at":"2026-11-12T00:00:00+00:00"}` → `400 {"code":"P0001","message":"a new target must start unverified (pending, no verification evidence)"}` — the INSERT trigger `targets_require_unverified_insert`, NOT a 42501.
- `PATCH /rest/v1/targets?id=eq.bada596c-... {"verification_status":"verified","verified_at":"2026-11-12T00:00:00+00:00"}` → `400 {"code":"P0001","message":"verification fields may only be changed by the verification flow"}` — the UPDATE trigger `targets_prevent_verification_tamper`, NOT a 42501.
- Post-check: `forged-a.websurfacehq.com` does not exist (`GET ...?domain=eq.forged-a.websurfacehq.com` → `200 []`); own target re-fetched still `verification_status=pending`, `verified_at=null`.

(b) Insert into a server-created table:
- `POST /rest/v1/scans {"target_id":"bada596c-...","user_id":"c2a09eef-...","status":"done","progress":100}` → `403 {"code":"42501","message":"permission denied for table scans","hint":"Grant the required privileges to the current role with: GRANT INSERT ON public.scans TO authenticated;"}`.

(c) Insert into a read-only table:
- `POST /rest/v1/subscriptions {"owner_id":"c2a09eef-...","plan":"pro","status":"active"}` → `403 {"code":"42501","message":"permission denied for table subscriptions","hint":"... GRANT INSERT ON public.subscriptions TO authenticated;"}`.
- `PATCH /rest/v1/subscriptions?owner_id=eq.c2a09eef-... {"plan":"pro"}` → `403 {"code":"42501","message":"permission denied for table subscriptions","hint":"... GRANT UPDATE ON public.subscriptions TO authenticated;"}`.

Verdict: PASS, with one deliberate reading note on (b)/(c). The task said the
denial "must NOT be a 42501 (that would mean the grants are still missing)".
That reading holds for (a) — and (a) is indeed trigger-denied, not 42501.
For (b)/(c) the 42501 IS the designed REVOKE-layer denial, and it is
distinguishable from the F2 "grants missing" signature: in the first proof
even SELECT as the user returned 42501; here the controls above show SELECT
as the user returns 200 on all three tables, i.e. the 0005 grants ARE present
(SELECT-only on the 8 server-created/read-only tables, per the 0005 grant
matrix, with the 0004 REVOKEs re-asserted after the GRANTs). The 42501 on
INSERT/UPDATE is Postgres refusing a write privilege the role deliberately
does not hold — the REVOKE working as designed — not a missing grant.
No row was created or modified by any probe.

## 6. M3 1-domain cap (Free plan)

As live-a (Free test user, no prior target):

- `POST /api/v1/targets/ {"domain":"proof-a1.websurfacehq.com"}` → `201`,
  `{"id":"bada596c-6313-49e8-9a93-aea72207c183","user_id":"c2a09eef-469e-426a-abcc-7f4ad3f4979b","domain":"proof-a1.websurfacehq.com","verification_status":"pending","verification_method":null,"verified_at":null,"created_at":"2026-11-11T19:12:13.485510Z","updated_at":"2026-11-11T19:12:13.485510Z"}`
  (`verification_token` / `verification_instructions` stripped from this log).
- `POST /api/v1/targets/ {"domain":"proof-a2.websurfacehq.com"}` → `429 {"code":"QUOTA_EXCEEDED","message":"Free plan allows 1 domain","details":{"limit":1,"period":"account"}}`, header `Retry-After: 3600`.

Verdict: PASS. (This 201 is the target that makes the §7 targets total 3,
and it wrote the one `target.create` audit row — see §7.)

## 7. Seed data readable via PostgREST as service_role

Row counts (PostgREST as service_role, `Prefer: count=exact` — see "How each
count was obtained"):

| Table | Total | Seed count | Delta vs seed |
|---|---|---|---|
| targets | 3 | 2 | +1 — the M3 target `bada596c-...` (§6) |
| scans | 2 | 2 | 0 |
| assets | 4 | 4 | 0 |
| findings | 4 | 4 | 0 |
| scan_jobs | 2 | 2 | 0 |
| audit_logs | 9 | 2 | +7 — 1 `target.create` (§6) + 6 `cross_tenant_access_denied` (§4) |
| subscriptions | 2 | 2 | 0 |
| teams | 1 | 1 | 0 |
| team_members | 1 | 1 | 0 |
| api_keys | 2 | 2 | 0 |
| notifications | 2 | 2 | 0 |
| support_tickets | 2 | 2 | 0 |
| attack_paths | 2 | 2 | 0 |

Seed-row integrity (filtered reads, PostgREST as service_role):
- Targets with `user_id` in the two seed tenants → exactly the 2 seed rows
  (`example-a.com`, `example-b.com`, IDs as in §0).
- Audit logs with `user_id` in the two seed tenants → exactly the 2 seed
  rows (`a0000000-...0008` / `b0000000-...0008`, both `scan.created`,
  `2026-11-11T17:08:46Z`).
- The 7 non-seed audit rows, all written by this run: `7343237c-...`
  (`target.create`, live-a, `proof-a1.websurfacehq.com`, `19:12:13Z`) and
  six `cross_tenant_access_denied` rows (`62742e4b-...`, `d129210c-...`,
  `6a69075f-...`, `0abd094b-...`, `088b41e6-...`, `0298d094-...`,
  `19:12:23–19:12:32Z`, five for live-b and one for live-a — one per denied
  read in §4). The API logging denied cross-tenant reads is its designed
  audit behaviour, not stray data.
- All targets listed: the 2 seed rows + `bada596c-...`
  (`proof-a1.websurfacehq.com`, live-a, `19:12:13Z`) — nothing else.

API-side readability is also shown by §1 (`/health` database ping = live
PostgREST `SELECT id ... LIMIT 1` on targets → 200) and §4 (target lists
return rows through the SupabaseStore).

Verdict: DIFFERS — explained. The totals are NOT the seed-only counts for
targets (3 vs 2) and audit_logs (9 vs 2), because checks 4 and 6 — which
the task orders — write exactly those rows. Every seed row is present and
untouched, the other 11 tables are exactly seed, and the delta is fully
attributed row-by-row above. Per the task's rule the differing totals are
reported as a failure of the literal "EXACTLY the seed counts" wording;
whether that fails the re-proof as a whole is for the parent to rule, since
no seed data is missing and the extra rows are the checks' own artifacts.

## 8. Server stop

- `pkill` by PID pattern was attempted first and self-matched the invoking
  shell (the known `pkill -f` cmdline gotcha); the server was then stopped
  and confirmed dead: log tail `Waiting for application shutdown /
  Application shutdown complete / Finished server process [21538]`.
- `ss -ltn | grep 8000` → nothing listening; `curl http://127.0.0.1:8000/live`
  → exit code 7 (connection refused); no `uvicorn` process remains.

Verdict: PASS. Port 8000 was free before the run and is free after it.

---

## Test artifacts created (for the closer — delete all of these)

Auth users (NOT deleted in this run, per task — the closer deletes them):
- `live-a@websurfacehq.com` — `c2a09eef-469e-426a-abcc-7f4ad3f4979b` (first proof, 11 Nov 17:41 UTC; password re-set in this run)
- `live-b@websurfacehq.com` — `af1cb806-c548-49ce-8502-7182903fc0b7` (first proof, 11 Nov 17:41 UTC; password re-set in this run)
- `proof2a@websurfacehq.com` — `44fe42d2-6b60-490a-885b-5b3f5e1845e6` (cancelled attempt, 11 Nov 19:00:04Z)
- `proof2b@websurfacehq.com` — `82d791b3-d232-4feb-bc28-e2084bb9b2b2` (cancelled attempt, 11 Nov 19:00:14Z)
- `proof2c@websurfacehq.com` — `c27fa99f-c5be-4aef-b205-fb87c1e76e55` (this run, Admin-API fallback, 11 Nov 19:10:37Z)

Database rows created by this run:
- Target `bada596c-6313-49e8-9a93-aea72207c183` — `proof-a1.websurfacehq.com`, user live-a, created `2026-11-11T19:12:13Z` (§6 M3 check).
- Audit log `7343237c-0b4b-40cd-857d-5b5fd37affcb` — `target.create`, live-a, `proof-a1.websurfacehq.com`, `19:12:13Z`.
- Audit logs `62742e4b-c558-43e4-a8cf-38485e985609`, `d129210c-091b-4003-847c-6a484618df5e`, `6a69075f-f7d9-4f63-89f3-142dc615a66b`, `0abd094b-db4b-4b92-845c-bbb6d78c8617`, `088b41e6-65f0-4825-9d23-53df417a95e3`, `0298d094-84d0-4d5a-8258-c0e4167c3cd3` — `cross_tenant_access_denied`, five for live-b and one for live-a, `19:12:23–19:12:32Z` (§4 probes).

Nothing else was created: no scan, finding, asset, subscription, team, or
api_key row; the H4 probes created/modified nothing (forged target absent,
own target still `pending`/`verified_at=null`).

## Step 0 cleanup (record)

Deleted before any check (see §0): target
`154d1321-1c35-4717-939d-7fd2fab7d53d` and audit log
`c1625e99-1dcb-4900-966d-c81ab7a56fc9`, both belonging to test user proof2a
from the cancelled attempt. Targets 3 → 2, audit_logs 3 → 2. No seed row
deleted. No Auth user deleted.

## Open items / flags for the parent

1. **Signup 502 root cause still unproven** (first proof's open item): the
   GoTrue email-send rate limit 429'd the only signup attempt again, so no
   signup has ever reached the GoTrue 400/validation path in either proof.
   The rate-limit window appears longer than an hour, or the cancelled
   attempt re-exhausted it at 00:30 IST.
2. **`/health` overall `degraded` on Redis** (§1): database `ok`, but overall
   status is `degraded` while no Redis broker exists. If the re-proof gate
   requires literal overall `"ok"`, this needs a Redis (or a health-rule
   change) — not a Supabase fix.
3. **Spurious 401 for ~1 s after login** (§3a): PyJWT `verify_iat` with zero
   leeway + GoTrue clock ~1 s ahead of this VM. Self-heals; a small leeway
   would remove it. Worth a reviewer decision, not a re-proof failure.
4. **Login rate limiter now tripped for this VM's IP** (5 attempts / 15 min):
   tripped at ~19:11Z by the §3a retest loop; no logins were attempted after.
   Any follow-up needing fresh logins should wait for the window or use
   fresh tokens.
5. **Check 7 literal wording vs check 6/4 artifacts** (§7): the task's
   "counts must be EXACTLY the seed counts" cannot hold simultaneously with
   the ordered M3 target creation and the API's denial-audit rows. All seed
   rows are intact; the delta is fully attributed. Parent to rule.
