# WebSurfaceHQ Week 1 — Live API Proof Evidence Log (redacted record)

**Date:** 11 November 2026 (IST).
**Source:** the live-proof agent's session log (`/tmp/live-proof/evidence.md`),
reproduced below verbatim after a line-by-line secrets audit (see "Audit note").
**Outcome of the run:** FAILED — three blockers: F1 (VM proxy env breaks httpx,
so the canonical server launch fails every Supabase call), F2 (zero GRANTs on
app tables, so no DB-backed endpoint works), F3 (live project signs tokens with
ES256; the API only accepts HS256, so no authenticated endpoint works).

## What this log proves

- Login via the API works against live Supabase Auth (both test users, 200).
- The migrations + seed are present in the live database (row counts verified
  via the dashboard SQL editor as `postgres` — see the caveat below).
- No GRANTs exist on the app tables: every REST read returns 403/42501, for
  anon, authenticated, and service_role alike.
- The H4 forgery/escalation probes all failed — but only at the GRANT layer
  (42501), before any RLS policy, trigger, or REVOKE was evaluated.

## What it does NOT prove

- API readability of the seed rows: the counts were verified via the dashboard
  SQL editor as `postgres`, which bypasses RLS and grants. They were NOT
  verifiable via REST/API, and counts do not prove API readability.
- Cross-tenant isolation live (blocked — all target calls 401, F3).
- The H4 triggers / 0004 REVOKEs live (unproven, not disproven — never reached).
- The M3 free-tier cap live (blocked — 401, F3).
- A healthy `/health` (database component "error", overall "degraded", F2).

## Audit note

Audited line by line before committing: no JWT, key, secret, token, or
password value appears anywhere below. Tokens are redacted to their first
8 chars + `<redacted>` (the only `eyJ…` strings below are the standard
JWT-header prefix `eyJhbGci<redacted>`, in the two login lines); test
passwords are recorded only as
`<throwaway>` placeholders and are not stored here. What does appear — and
is NOT secret — is the Supabase project ref, the public JWKS key id (`kid`),
the two test users' UUIDs and throwaway `@websurfacehq.com` addresses, and
the seed's deterministic UUIDs. The full unredacted session log is NOT
committed to this repo.

---

# WebSurfaceHQ Week 1 — Live API Proof Evidence Log
Date: 2026-11-11 IST. API: http://127.0.0.1:8000. Supabase project: websurfacehq (ref dpwfshafzyxyfoktsggo, Singapore, Nano).
All tokens redacted to first 8 chars + `<redacted>`. Test passwords are NOT recorded anywhere in this log or the report.
No repo file was edited, no migration re-applied, no seed re-run, no seed row touched.

## 0. Pre-flight
- `settings.supabase_configured` = True; supabase_url / anon key / service_role key / JWT secret all set (booleans only).
- Server started per task: `cd ~/workspace/websurfacehq/apps/api && .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000` (first process PID 2218; killed, restarted PID 2597 — see §0a).
- Initial GET /health -> 200, body:
  `{"status":"degraded","components":{"database":{"status":"error","detail":"supabase ping failed: InvalidURL"},"redis":{"status":"unreachable","detail":"redis ping failed: ConnectionError"},"queue":{"status":"not_configured","detail":"celery worker not wired yet (Week 1)"}}}`

## 0a. Finding F1 — VM proxy env breaks httpx (blocks ALL Supabase calls from the server)
- Signup with the task's command returned 500 `{"code":"INTERNAL_ERROR","message":"Internal server error"}`.
- Server log traceback root cause: `httpx.InvalidURL: Invalid port: ':1]'`, raised in `supabase.create_client` -> gotrue `SyncClient(...)` -> `URLPattern(key)`.
- Mechanism verified in isolation: `httpx.Client()` raises the same InvalidURL with the VM's stock env; the VM's `no_proxy`/`NO_PROXY` contains bracketed IPv6 entries (`[::1]`, `[fd8b:4f84:7d32:99::1]`, `[fd8b:4f84:7d32:99::2]`). httpx `get_environment_proxies()` turns `[::1]` into mount key `all://*[::1]`, which fails URL parsing. (Repo AGENTS.md already records "this VM's proxy env breaks httpx URL parsing" for the scanner only; the Supabase client paths have no such hardening.)
- Proof of the fix: with sanitized `NO_PROXY`/`no_proxy` (same entries, brackets removed; `https_proxy` etc. untouched) `httpx.Client()` constructs fine and `GET https://dpwfshafzyxyfoktsggo.supabase.co/auth/v1/settings` returns 401 `{"message":"No API key found in request",...}` — i.e. live Supabase is reachable through the proxy.
- ACTION TAKEN (runtime env only, no repo change): killed first server (PID 2218, port confirmed closed), restarted with sanitized NO_PROXY/no_proxy (PID 2597). All steps below ran on PID 2597. The canonical command as given FAILS every Supabase-backed call on this VM.

## 0b. Finding F2 — no GRANTs on app tables (store cannot read/write anything)
- With sanitized env, GET /health still "degraded": database `{"status":"error","detail":"supabase ping failed"}` (no exception type = `ping()` returned False, not a raise).
- Direct probe (supabase-py, anon key): `c.table('targets').select('id').limit(1)` -> APIError `{'message': 'permission denied for table targets', 'code': '42501', 'hint': 'Grant the required privileges to the current role with: GRANT SELECT ON public.targets TO anon;'}`.
- Direct probe (supabase-py, service_role key — the key `SupabaseStore` uses, `app/db/supabase_store.py:84`): same query -> APIError 42501, hint `GRANT SELECT ON public.targets TO service_role;`.
- Direct REST (httpx): service_role GET /rest/v1/targets -> 403 42501 (same hint); service_role GET /rest/v1/subscriptions -> 403 42501; anon GET /rest/v1/targets -> 401 42501.
- Repo check: `grep -n "^GRANT\|GRANT .* ON" supabase/migrations/*.sql` returns NOTHING — the migrations (0001–0004) contain zero GRANT statements. Tables were created via the dashboard SQL editor as `postgres` with no grants to service_role/anon/authenticated. RLS is enabled (0001:231+) and policies exist, but policies are irrelevant without base GRANTs.
- Consequence: the API's `SupabaseStore` (service_role PostgREST client) cannot SELECT/INSERT/UPDATE/DELETE any app table. Every DB-backed endpoint fails even after auth succeeds.

## 1. AUTH FLOW LIVE — PARTIAL FAIL
### 1a. Signup via API — FAIL (two independent failures)
- `POST /api/v1/auth/signup {"email":"live-a@example.invalid","password":"<16-char throwaway>"}` -> 422
  `{"code":"VALIDATION_ERROR","message":"Request validation failed","details":[{"type":"value_error","loc":["body","email"],"msg":"value is not a valid email address: The part after the @-sign is a special-use or reserved name that cannot be used with email."}]}` — pydantic email-validator rejects the `.invalid` TLD. Same 422 for live-b@example.invalid.
  ADAPTATION (documented): used the project's own domain instead — live-a@websurfacehq.com / live-b@websurfacehq.com (no real mailbox; throwaway test accounts).
- `POST /api/v1/auth/signup {"email":"live-a@websurfacehq.com",...}` -> 500 `{"code":"INTERNAL_ERROR","message":"Internal server error"}` (Finding F1, pre-sanitization).
- After env sanitization, same signup -> 502 `{"code":"BAD_GATEWAY","message":"Authentication service unavailable"}` for BOTH users. Server log: `supabase sign_up failed, status: 400` (provider maps any non-429/non-duplicate AuthApiError to 502; the upstream GoTrue 400 message is not logged by the provider). Exact GoTrue 400 body NOT captured.
- Follow-up direct probe `POST https://dpwfshafzyxyfoktsggo.supabase.co/auth/v1/signup` (different password, fresh attempt) -> 429 `{"code":429,"error_code":"over_email_send_rate_limit","msg":"email rate limit exceeded"}` — the project's email-send rate limit was already exhausted after the two API signup attempts.
- Signup via the API therefore NEVER succeeded in this run (no 201 observed).

### 1b. Fallback: Auth Admin API (service_role, email_confirm=true) — PASS
- `POST https://dpwfshafzyxyfoktsggo.supabase.co/auth/v1/admin/users` headers `apikey` + `Authorization: Bearer <service_role, redacted>`, body `{"email":"live-a@websurfacehq.com","password":"<throwaway>","email_confirm":true,"user_metadata":{}}` -> 200, `id=c2a09eef-469e-426a-abcc-7f4ad3f4979b`, `email=live-a@websurfacehq.com`, `email_confirmed_at=2026-11-11T17:41:36.379741722Z`.
- Same for live-b -> 200, `id=af1cb806-c548-49ce-8502-7182903fc0b7`, `email=live-b@websurfacehq.com`, `email_confirmed_at=2026-11-11T17:41:37.266383109Z`.

### 1c. Login via API — PASS
- `POST /api/v1/auth/login {"email":"live-a@websurfacehq.com","password":"<throwaway>"}` -> 200, keys `["access_token","token_type","expires_in","user"]`, `user={"id":"c2a09eef-469e-426a-abcc-7f4ad3f4979b","email":"live-a@websurfacehq.com"}`, `token_type="bearer"`, `expires_in=3600`, access_token prefix `eyJhbGci<redacted>`.
- Same for live-b -> 200, `user={"id":"af1cb806-c548-49ce-8502-7182903fc0b7","email":"live-b@websurfacehq.com"}`, `expires_in=3600`, access_token prefix `eyJhbGci<redacted>`.
- (Earlier pre-creation login attempt for live-a correctly returned 401 `{"code":"UNAUTHORIZED","message":"Invalid email or password"}` — user did not exist yet.)

### 1d. GET /me — FAIL (Finding F3: ES256 vs HS256)
- `GET /api/v1/auth/me` with A's login token -> 401 `{"code":"UNAUTHORIZED","message":"Invalid or expired token","details":null}`. Same for B's token. Garbage token -> 401 (same body). No token -> 401 `{"code":"UNAUTHORIZED","message":"Missing authorization header","details":null}`.
- Token inspection (header/payload decoded WITHOUT signature verification): header `{"alg":"ES256","kid":"6b08cdc7-1192-414f-a101-bd42d800a1f2","typ":"JWT"}`; payload `iss=https://dpwfshafzyxyfoktsggo.supabase.co/auth/v1`, `aud=authenticated`, `role=authenticated`, `sub=c2a09eef-469e-426a-abcc-7f4ad3f4979b`, `email=live-a@websurfacehq.com`, `exp`/`iat` valid (3600s). All claims are exactly what the verifier expects.
- Root cause proven: `app/auth/jwt.py verify_token` calls `jwt.decode(token, key, algorithms=["HS256"], ...)`. Replaying the decode in the venv: `InvalidAlgorithmError: The specified alg value is not allowed`. The live project signs tokens with ES256 (new Supabase default asymmetric keys); the API only accepts HS256. Consequence: EVERY Bearer-authenticated endpoint rejects real GoTrue tokens.
- Step 1 verdict: PARTIAL FAIL — users creatable (admin API) and login works, but no authenticated API call succeeds.

## 2. CROSS-TENANT ISOLATION LIVE — BLOCKED (cannot authenticate; see F3)
- `POST /api/v1/targets/ {"domain":"live-a.example.com"}` as A -> 401 `{"code":"UNAUTHORIZED","message":"Invalid or expired token"}`.
- `POST /api/v1/targets/ {"domain":"live-b.example.com"}` as B -> 401 (same body).
- `GET /api/v1/targets/` as A -> 401 (same body).
- No target was created (no TA/TB ids exist). Cross-tenant GETs and list scoping could not be exercised. Even with auth fixed, Finding F2 (service_role 42501) would make the store calls fail.

## 3. H4 PROTECTIONS LIVE (PostgREST direct, anon key + A's JWT) — ATTACKS BLOCKED, but at the GRANT layer, NOT via the intended triggers/REVOKEs
All calls used headers `apikey: <anon>` + `Authorization: Bearer <A's JWT, redacted>`. Random (nonexistent) row ids used so no real row could be touched.
- (c1) `GET /rest/v1/subscriptions?select=id,plan&owner_id=eq.c2a09eef-469e-426a-abcc-7f4ad3f4979b` -> 403 `{"code":"42501","details":null,"hint":"Grant the required privileges to the current role with: GRANT SELECT ON public.subscriptions TO authenticated;","message":"permission denied for table subscriptions"}` — A's subscription row id could NOT be read.
- (a) `PATCH /rest/v1/targets?id=eq.<random-uuid>` body `{"verification_status":"verified"}` -> 403 `{"code":"42501","hint":"Grant the required privileges to the current role with: GRANT SELECT, UPDATE ON public.targets TO authenticated;","message":"permission denied for table targets"}`.
- (b) `POST /rest/v1/targets` body `{"user_id":"c2a09eef-469e-426a-abcc-7f4ad3f4979b","domain":"forged.example.com","verification_status":"verified","verified_at":"2026-11-11T10:00:00+00Z"}` -> 403 `{"code":"42501","hint":"Grant the required privileges to the current role with: GRANT SELECT, INSERT ON public.targets TO authenticated;","message":"permission denied for table targets"}`.
- (c2) `PATCH /rest/v1/subscriptions?id=eq.<random-uuid>` body `{"plan":"pro"}` -> 403 `{"code":"42501","hint":"Grant the required privileges to the current role with: GRANT SELECT, UPDATE ON public.subscriptions TO authenticated;","message":"permission denied for table subscriptions"}`.
- Verdict: all three forgery/escalation attempts FAIL (no write succeeded) — but the denial is Postgres 42501 "no GRANT at all", which fires before any RLS policy, trigger, or REVOKE is evaluated. The H4 triggers and the 0004 REVOKEs are therefore UNPROVEN live (not disproven): they were never reached. No row was created or modified by any probe.

## 4. M3 CAP LIVE — BLOCKED (cannot authenticate; see F3)
- `POST /api/v1/targets/ {"domain":"second-a.example.com"}` as A -> 401 `{"code":"UNAUTHORIZED","message":"Invalid or expired token"}`. The 429 QUOTA_EXCEEDED path could not be exercised. (Even with auth fixed, F2 would break the store call.)

## 5. HEALTH LIVE — FAIL (database component)
- Final `GET /health` -> 200, body:
  `{"status":"degraded","components":{"database":{"status":"error","detail":"supabase ping failed"},"redis":{"status":"unreachable","detail":"redis ping failed: ConnectionError"},"queue":{"status":"not_configured","detail":"celery worker not wired yet (Week 1)"}}}`
- Expected `database.status "ok"` / detail "supabase reachable" NOT observed. Cause: F2 (service_role SELECT on targets -> 42501, so `SupabaseStore.ping()` returns False). Redis "unreachable" ALSO degrades the overall status to "degraded" — per `app/core/health.py:80-87` (`overall_status` returns "degraded" when any component is "error" or "unreachable"; only "not_configured" is exempt) — so the queue's "not_configured" is the only component here that does not degrade "ok". (An earlier draft of this line claimed Redis unreachable "does not by itself degrade ok" — wrong, corrected 11 Nov 2026, review fix F-L8.)
- `GET /live` -> 200 `{"status":"alive"}`.

## 6. CLEANUP
- Nothing to delete: no test target was ever created (all creates returned 401). `GET /api/v1/targets/` for both users returns 401, so "empty list" could not be confirmed via the API; no rows were created by this run (all PostgREST probes failed at the permission layer; no INSERT ever succeeded).
- The two test Auth users REMAIN in the live project (per task): live-a@websurfacehq.com (c2a09eef-469e-426a-abcc-7f4ad3f4979b), live-b@websurfacehq.com (af1cb806-c548-49ce-8502-7182903fc0b7). Both email-confirmed, throwaway passwords (not recorded).
- No seed row was read, modified, or deleted. No migration or seed re-run. No repo file edited.

## Server shutdown
- uvicorn server process PID 2599 killed by PID at end of run (2597 was the nohup shell wrapper); port 8000 confirmed closed via curl (connection refused) and `ss` (nothing listening). (First server PID 2218/2216 killed the same way earlier.)

## Summary of verdicts
| Step | Verdict | Note |
|---|---|---|
| 0 pre-flight / health baseline | FAIL (observed) | F1 (httpx/proxy) + F2 (grants) |
| 1 auth flow | PARTIAL FAIL | signup API 502 (GoTrue 400) + email rate limit 429; admin-API fallback PASS; login PASS; /me FAIL (F3 ES256/HS256) |
| 2 cross-tenant isolation | BLOCKED | all target calls 401 (F3); store also broken (F2) |
| 3 H4 protections | BLOCKED-AS-INTENDED / UNPROVEN | all 3 attacks fail 403/42501, but at GRANT layer, not trigger/REVOKE |
| 4 M3 cap | BLOCKED | second-target call 401 (F3) |
| 5 health | FAIL | database "error", overall "degraded" (F2) |
| 6 cleanup | DONE (nothing to delete) | test Auth users left in place per task |

## Blockers to fix before a re-run can pass (in dependency order)
1. F2 — add GRANTs: `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO service_role;` (and the matching grants anon/authenticated need per the RLS design, e.g. SELECT/INSERT/UPDATE/DELETE on user tables TO authenticated, SELECT where appropriate TO anon) — or apply a grants migration. Without this NOTHING DB-backed works live.
2. F3 — API must verify ES256 tokens (fetch Supabase JWKS from `<url>/auth/v1/.well-known/jwks.json`, verify by `kid`) or the project must be switched back to HS256 legacy signing. Without this NO authenticated endpoint works live.
3. F1 — server process must not inherit bracketed-IPv6 `no_proxy` (sanitize env at launch, or set `trust_env=False` on the httpx clients supabase-py builds). VM-only, but it made the canonical launch command fail every Supabase call.
4. Signup 502 — determine the GoTrue 400 cause once the email rate limit resets (and note the email-send rate limit is already exhausted on this project — further signup attempts will 429 until the window resets).
