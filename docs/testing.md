# WebSurfaceHQ — Testing Strategy

**Status:** Phase 0 (scaffold / docs only). 11 API tests exist and pass
(`apps/api/tests/` — health, headers, request-id, log redaction); integration
tests against a real database and the web test suite land in Week 1.
This strategy binds Weeks 1–4. A phase is not done until its tests are green in CI;
a test that is failing or skipped is never reported as done.

## 1. Test levels

| Level | What | Where | Runs in |
|---|---|---|---|
| Unit | Service logic in isolation: SSRF guard, redaction, risk scoring (severity × exposure × exploitability → P0–P3), tool-output parsers (Nuclei JSONL, httpx JSON, katana URLs), triage heuristic filter, diff hashing | `apps/api/tests/unit/` | CI, every push |
| Integration | Every API endpoint against a **real** test database (Supabase Postgres / Postgres test container), real RLS policies, real JWT verification | `apps/api/tests/integration/` | CI, every push |
| End-to-end | Signup → add target → verify → create scan → findings → report download; plan upgrade (when billing lands); teammate invite (post-MVP) | `apps/web` e2e suite (Playwright) against staging | CI on PRs touching flows + pre-release |
| Load | k6/Locust: 5 concurrent scans on staging; p50/p95/p99 per stage; degradation point | Staging, Week 4 | Pre-launch |

**Coverage target:** 80% on `apps/api/app/core/` + `app/services/` + tool parsers.
Coverage is a floor, not a goal — a high-coverage suite that would still pass if the
feature were broken is a failed suite (see §5).

## 2. Mock only external APIs — never the database or auth

- **Mocked:** Gemini/Groq LLM calls (recorded fixtures), NVD/KEV/EPSS feeds (recorded
  fixtures), crt.sh, external HTTP fetches in unit tests.
- **Never mocked:** Postgres (integration tests run against a real database with real RLS),
  Supabase Auth JWT verification, the `can()` permission check, Redis rate limiting
  (use a real Redis in CI — Upstash free or a local Redis service).
- **Recorded fixtures:** tool outputs are captured once from real runs (Nuclei JSONL,
  httpx JSON, naabu output) and stored as fixtures; parsers are tested against those
  fixtures, not against live tools in CI.
- **Deliberately vulnerable local site:** integration tests run the full pipeline against
  a local intentionally-vulnerable test target (owned by the project, never a third
  party's site) so recon + vuln stages are exercised end to end in CI.

## 3. The 401/403/404 matrix (every endpoint, no exceptions)

For **every** endpoint, these cases are tested:

| Case | Expected |
|---|---|
| No auth header | 401 `UNAUTHORIZED` |
| Invalid / expired JWT | 401 `UNAUTHORIZED` |
| Authenticated, own resource | 200/201/202 as specified |
| Authenticated, another tenant's resource (id swapped in URL) | **404 `NOT_FOUND`** — never 403, never the other tenant's data |
| Authenticated, wrong role (post-MVP team roles only) | 403 `FORBIDDEN` |
| Authenticated, nonexistent id | 404 `NOT_FOUND` (indistinguishable from the cross-tenant case) |
| Valid auth, invalid body | 422 `VALIDATION_ERROR` with per-field errors |

The Week 1 exit gate requires this matrix green on every endpoint. Cross-tenant proof
(user A cannot fetch user B's scan by changing an id in the URL) is demonstrated with
seed data for **two separate tenants**.

## 4. Security tests (test-first for security bugs)

- **SSRF blocklist:** unit tests for `169.254.169.254`, `localhost`, `10/8`,
  `172.16/12`, `192.168/16`, `127/8`, `*.local`, `*.internal`,
  `metadata.google.internal`, and the DNS-rebinding case (resolve twice, second
  resolution flips to a private IP → blocked). IPv6 private ranges (`fc00::/7`,
  `fe80::/10`) are tested too — the blueprint lists IPv4 only; see threat-model §3.4.
- **Injection:** parameterized-query tests; Nuclei template-id allow-list tests
  (a non-allow-listed template id is rejected, never passed to a shell).
- **XSS:** finding-evidence escaping tests — evidence containing `<script>` renders
  escaped in the HTML report and the frontend.
- **Redaction:** tests asserting that a secret-shaped value (e.g. `AKIA…`, `sk_live_…`)
  never appears unredacted in a report fixture, a log line, or an API response.
- **Verification gate:** a scan on an unverified target is rejected (409) at the API
  *and* at the worker (a Celery task handed an unverified target refuses to run).
- **Self-scan:** before launch, run the scanner on itself (websurfacehq.com / staging)
  and fix every Critical/High found.

## 5. Bug-fix rule (test-first, always)

1. Write a **failing test that reproduces the bug** and show it failing.
2. Fix the code.
3. Show the test passing **and the full suite still green**.

**Never edit a test to make it pass.** If a test reveals a bug, stop and report the bug —
do not change the test. If a test is wrong, that is itself a change requiring review:
the test change is proposed, justified, and reviewed separately from the fix.

## 6. Test-quality review (before every release)

Report, with a prioritised fix list:
- Tests that would still pass if the feature were broken (e.g. asserting only on mocks,
  asserting a 200 without asserting the body).
- Tests that only assert on mocks.
- Skipped tests (a skipped test is a missing test — it is listed, never hidden).
- Flaky tests (a flaky test is quarantined and fixed, never re-run-until-green).
- Important paths with no coverage (every endpoint's matrix, every pipeline stage's
  failure path, every redaction path).

## 7. What is NOT tested in Phase 0

Nothing — there is no code. The first tests land in Week 1 with the Supabase schema
(RLS + cross-tenant proof) and the FastAPI skeleton. The e2e suite lands with the
frontend shell. Load tests land in Week 4 on staging.
