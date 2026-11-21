# ADR-0010: Admin Foundation — platform roles, audit, staff MFA, two-door scheme (20 Nov 2026)

**Status:** Accepted (build complete in the working tree, 20 Nov 2026;
independent security review APPROVED — see §8; live proof still open — see
§7). NOT YET PUSHED. The work sits uncommitted on branch `week-2-recon`
(the whole tree is uncommitted against the ancient local HEAD, by the
snapshot-push design — see §9); the push must create branch
`admin-foundation` + PR, never push straight to main.

## Context

The admin panel + Founder screen design was LOCKED 14 Nov 2026 and the
full admin + auth design LOCKED FOR DEVELOPMENT 15 Nov 2026 00:12 IST
(`~/workspace/websurfacehq-brand/DESIGN-LOCK.md`): platform roles
Owner/Admin/Support, append-only audit, staff MFA, step-up MFA for
Founder, two-door URL scheme with a secret staff-address prefix,
Owner-managed staff accounts, role-first staff login, 12h/60min staff
sessions. This ADR records the foundation landing as real code + API
(the 9 screens' full UI is Weeks 3–4 work, not this phase). Plan:
`docs/admin-foundation-plan.md`. Live-proof script:
`docs/admin-foundation-live-proof.md`.

## Decision

1. **Platform roles Owner/Admin/Support, separate from team roles.**
   Migration `supabase/migrations/0007_admin_foundation.sql` adds
   `staff_roles`, `staff_invites`, `staff_sessions`, and the
   `admin_settings` table (prefix version), plus append-only audit
   triggers + REVOKEs (Week 1 pattern). Roles are enforced server-side
   via the central `can()` on EVERY admin route/action; the frontend
   only hides actions. Single-Owner invariant enforced by a partial
   unique index. Migration validator: **428/428** on a fresh DB
   (was 390/390, then 398/398 after schema hardening).
2. **Append-only audit log.** Every admin action writes one immutable
   row (actor, action, target, before/after, IP, timestamp) via
   `app/services/audit.py`. No update/delete path for audit rows
   (triggers + REVOKEs). Failed staff logins ARE audited: known account
   → real actor id; unknown email → deterministic UUIDv5 actor derived
   from the email hash, never plaintext email (red-team F4 fix).
   Production limit, honestly recorded: `audit_logs.user_id` is
   `NOT NULL REFERENCES auth.users(id)`, so the synthetic actor fails
   the FK on the Supabase path and is swallowed by the best-effort
   helper — unknown-email failures are log lines only in prod, while
   known-account (brute-force-relevant) failures persist. Lifting this
   needs a schema change (nullable actor or dedicated failed-login
   table) — Week 3 hardening item.
3. **MFA for staff (TOTP via Supabase Auth MFA).** Enforced for all
   staff sessions; setup during invite onboarding; re-enrollment is an
   Owner power only. `app/auth/mfa.py` (GoTrue MFA REST via the
   proxy-safe helper), `app/auth/sessions.py` (12h absolute / 60min
   idle / prefix-version). Enroll returns 409 `MFA_ALREADY_ENROLLED`
   when a factor is set; Owner-only re-enroll requires verifying the
   existing factor first (review #1 C1 fix, re-proven by the red team).
   Per-account MFA buckets 5/15 min; `/mfa/enroll` also carries the
   per-IP bucket (red-team F5 fix).
4. **Step-up MFA for the Founder screen behind a flag defaulting ON.**
   `STAFF_STEP_UP_MFA=true` (default ON — the owner's decision is
   still open; ON is the recommended default). One-line toggle; when
   on, opening Founder requires a fresh MFA check once per session
   (sudo-style: `{password, code}`). Wrong-password at step-up returns
   the byte-identical generic 401 as login (red-team F8 fix).
5. **Two-door URL scheme + secret staff-address prefix.** Customer
   door `websurfacehq.com` (`/login`, `/dashboard`, `/signup`) — no
   `/admin` paths exist there (plain 404). Staff door
   `admin.websurfacehq.com/<secret>/...` (128-bit prefix, generated at
   setup, server config only, never in repo/docs/chat). Everything
   outside the prefix on the staff subdomain answers a generic 404.
   No links/sitemap/noindex/no-referrer on staff pages. Supabase
   redirect allowlist uses the wildcard
   `https://admin.websurfacehq.com/**` so prefix rotation never breaks
   invites. Owner rotates the prefix from Settings (Founder-only,
   audit-logged; rotation signs all staff out — the version bump is
   read from the DB `admin_settings` table, `!=` comparison, and
   rotation explicitly revokes all live sessions via the single
   override-aware session-manager wiring point, red-team F6 fix).
   Honest limit, recorded with the design: a secret address is
   obscurity, not security — real protection stays passwords + MFA +
   rate limits + role checks.
6. **Owner-managed staff accounts.** Owner alone creates/suspends/
   deletes/re-roles staff (Settings → Roles, audit-logged). Invite
   links single-use, 72h expiry, 32-byte token, SHA-256 hash, atomic
   claim; staff set their OWN password + MFA (Owner never sees/sets
   passwords). Suspend/delete revokes sessions instantly, audit
   history kept. Force password reset, revoke sessions, MFA
   re-enrollment are Owner powers. Staff login is SIGN-IN ONLY (no
   self-registration); forgot-password (email) stays for recovery.
   First Owner account is created once at setup via documented
   dashboard SQL (staff accounts/invites are store-backed, never
   in-memory — review #1 C2 fix). Re-inviting an email invalidates
   prior pending invites; Owner can revoke a pending invite
   (`POST /admin/users/invites/{invite_id}/revoke`, 404 for
   consumed/expired/unknown, 403 non-Owner — red-team F3 fix).
   `force_password_reset` REALLY invalidates the password: it sets a
   fresh 32-byte random password via the GoTrue Admin API
   (`PUT /auth/v1/admin/users/{id}`, service-role key) BEFORE sending
   the reset email, then revokes sessions; audit records
   `password_invalidated: True` (red-team F2 fix — random password,
   not a ban, because a ban would block sign-in via the recovery link
   itself; the reset link remains the only way back in).
7. **Role-first staff login.** The login page asks the role first
   (Owner / Admin / Support cards, none pre-selected, button names the
   chosen role). The server verifies the account's REAL role and
   refuses a mismatch with the SAME generic error as a wrong password
   (messages AND timing — byte-identical 401s, verified by the red
   team across wrong-password / wrong-role / unknown / suspended /
   customer cases). Login returns an AAL1 token + `enroll_required`
   (no session before MFA); `/mfa/verify` takes `{code}` only.
   `enroll_required` differing by enrollment state is an ACCEPTED
   residual (red-team F7): exposure is limited to a password holder
   and the client needs the signal for its flow.
8. **Staff sessions.** Absolute lifetime 12h; idle 60 min → sign in
   again; TOTP at EVERY staff sign-in; no trusted-device bypass;
   session cookies scoped to the staff subdomain + secret prefix;
   prefix rotation invalidates all staff sessions. `iat` leeway fix
   (Week 1 open item 3, DONE in this phase): `leeway=5` in
   `jwt.decode` + regression test.
9. **No "login as user".** Read-only support view only (evidence
   redacted, every view logged). Support sees Support + Abuse screens
   only; Admin on `/founder` → 403; customer accounts at the staff
   door → same generic error as a wrong password. Owner self-action
   guard: suspend/delete/re-role of self → 409.
10. **Owner-only destructive actions with two-step confirm**
    (delete tenant, refunds, role grants, kill switches, maintenance
    mode). Second Owner invite → 409.
11. **Admin API scaffolding.** `/admin` routes for the 9 screens'
    data (users, scans/queue, billing, abuse, support, security,
    system/audit, settings, founder) — real endpoints backed by the
    store/RLS, honest 503s where no store method exists yet. No
    fake/demo data in any endpoint. Staff API is served ONLY under
    the secret prefix on the staff host — the API host gate is an
    allowlist: staff host + the API's own public host
    (`API_PUBLIC_HOST`, or the host parsed from `API_PUBLIC_URL`) +
    localhost-in-dev. The Host at the API is always the API origin
    (proxies and direct calls alike), so the primary doors are the
    web middleware + secret prefix + staff session and the API host
    gate is secondary (documented honestly in code). **Fail-fast
    (re-review #3 B1 fix):** staging/production startup raises unless
    `API_PUBLIC_HOST` or `API_PUBLIC_URL` is set — without either,
    every staff call would 404 silently.
12. **Timing-oracle discipline (H1).** The login dummy is time-based
    (loops 20k-iteration PBKDF2 blocks until a wall-clock target
    elapses), default target `STAFF_DUMMY_HASH_TARGET_MS=75` — measured
    against live GoTrue (median-of-diffs ~73 ms over N=10 × 3 runs;
    the old 600k-iteration ~310 ms dummy was ~3–4× too slow). After a
    failed sign-in the handler asks the provider whether an Auth user
    exists (`AuthProvider.user_exists`, GoTrue Admin list paged
    1000/page, max 5 pages, case-insensitive; any error → False, i.e.
    run the dummy): exists → bcrypt ran → dummy skipped; absent →
    dummy runs. Measured test-fake medians: unknown 92.25 ms vs
    wrong-password 84.61 ms (ratio 1.09×, gap 7.64 ms). Final H1
    sign-off still requires a post-0007 live re-probe of staff-login
    timing (unknown vs wrong-password) — see §7.
13. **`/openapi.json` must not leak the prefix (red-team F1 fix).**
    `openapi_url` is set only in development (`None` in
    staging/production), and all three staff routers carry
    `include_in_schema=False` in every environment. Verified:
    prod-mode `/openapi.json`, `/docs`, `/redoc` all 404 with the
    prefix absent; dev schema contains no staff paths and no prefix.

## Alternatives considered

- **Ban instead of random password for force-reset (F2):** rejected —
  a ban would block sign-in via the recovery link itself until
  unbanned; the random password is unguessable, never stored or
  returned, and the reset link remains the only way back with no
  extra unban step.
- **`NEXT_PUBLIC_API_URL` carrying the prefix (NEW1):** rejected — it
  would bake the secret into the JS bundle. The web instead calls
  same-origin `/api/staff/*`; the middleware rewrites prefixed page
  URLs and proxies API calls with the prefix added server-side from
  env at request time, never logged. Verified: the prefix appears
  only in the server edge chunk, never in `.next/static/*`.
- **Ratio bound on the ~2 ms timing tests (B2):** removed — at ~2 ms
  medians the 1.5× ratio is scheduling noise (~1 failure in 11
  runs). The absolute gap (< 50 ms) + byte-identical-body asserts
  remain, as do the ratio bounds on the ~85–100 ms dummy tests where
  1.5× is meaningful.
- **Failing fast on `API_PUBLIC_HOST`/`API_PUBLIC_URL` (B1):**
  chosen over documentation alone — the sibling `STAFF_URL_PREFIX`
  already fail-fasts for the identical silent-outage failure mode.

## Consequences

- Staff auth is store-backed end to end (roles, invites, factor ids,
  sessions, prefix version in `admin_settings`); a restart wipes
  nothing the app created.
- The operator MUST set `API_PUBLIC_HOST` or `API_PUBLIC_URL` in
  staging/production (fail-fast) and `STAFF_URL_PREFIX` (fail-fast);
  the web side needs `STAFF_API_URL` + `STAFF_URL_PREFIX` server-side
  (a missing web-side setting still fails silently in prod — consider
  a web-side prod check at deploy time; re-review #3 N7).
- Known gaps carried into live proof / Week 3 (all documented in
  `docs/admin-foundation-live-proof.md` §4): N1 bearer UUIDs in
  localStorage (real fix HttpOnly cookies + CSRF, Week 3 hardening);
  F9 session-theft blast radius (no IP/UA binding; staff logout
  revokes only the staff session row, not GoTrue AAL1/AAL2 tokens);
  N-NEW4 password-only MFA enrollment on a never-enrolled account
  (inherent design residual, conscious decision); F4 production FK
  limit (above); `user_exists` 5,000-user paging cap (fail-safe
  direction); F7 `enroll_required` accepted residual (above);
  force-reset partial failure (disable succeeds, reset email fails)
  leaves no audit row — Owner sees the 502 synchronously and retries.
- Signup-201 close-out is STILL OPEN: one attempt 20 Nov
  (`wshq-signup-20261120-<random>@example.com` → 502; GoTrue 400
  `email_address_invalid` — GoTrue rejects `@example.com`). No test
  user created, no retry per the one-attempt rule. Next attempt needs
  a deliverable-domain address (e.g. a real Gmail) — parent/
  coordinator decision, not to be taken unilaterally.
- QR code for MFA setup is an OPEN dependency decision: manual entry
  works; adding a client-side `qrcode` library (no network, no seed
  leak) needs approval before adding (playbook rule).
- Step-up MFA for the Founder screen: STILL OPEN (owner decision);
  implemented behind `STAFF_STEP_UP_MFA` defaulting ON.

## Review history (this phase)

- **Independent security review #1: NOT APPROVED** — C1 CRITICAL (MFA
  bypassable via self re-enrollment), C2 CRITICAL (staff accounts/
  invites in-memory only, no first-Owner bootstrap), C3 HIGH (prefix
  rotation evaporated on restart), H1 HIGH (login timing oracle),
  H2 HIGH (onboarding dead-ends), H3 HIGH (`/admin/*` identity
  registry-only), M1 (blocking Medium, audit neither atomic nor
  accurate), M2 (blocking Medium, no per-account MFA rate limit), M3
  (blocking Medium, staff API on customer host), plus N1–N10.
  Fix pass #1 fixed all of them (pytest 476, validator 428/428).
- **Re-review #2: NOT APPROVED** — all fix-pass-#1 items verified
  FIXED except H1 (partial) + NEW1 HIGH (staff web flow cannot work
  in production with a real secret prefix). Fix pass #2 fixed both
  (web: server-side proxy/rewrites; API: 75 ms time-based dummy +
  double-count fix + host-gate allowlist + NEW1 real-mount test +
  N-NEW2/N-NEW5). Pytest 482.
- **Re-review #3: NOT APPROVED** — NEW1 + H1 verified FIXED; withheld
  on B1 Medium (no prod fail-fast for `API_PUBLIC_HOST` /
  `API_PUBLIC_URL`) and B2 Medium (role-spoof timing ratio bound is
  noise, ~1 failure in 11). Confirmation review APPROVED B1/B2/N1
  (live-proof doc §5.4 corrected — it had instructed the wrong var).
  Pytest 483.
- **Red-team attacker pass: 100 attempts, 84 BLOCKED, 14 PARTIAL,
  2 VULNERABLE** — F1 Medium (`/openapi.json` leaked the prefix in
  every environment incl. production), F2 Medium
  (`force_password_reset` did not invalidate the password), F3–F6
  Low (duplicate invites/no revocation; failed logins unaudited;
  `/mfa/enroll` no per-IP bucket; rotation revoke bypassed the
  override-aware manager), F7–F9 Low observations. Verdict: not yet
  safe to proceed — fix F1 first.
- **Red-team fix round + confirmation review: APPROVED.** All eight
  fixes verified independently, both negative controls reproduced
  (F1 openapi gate, F6 rotation wiring). The restructured
  `test_force_reset_and_mfa_reenroll_revoke_sessions` was read in
  full: coverage PRESERVED — the only assertion removed was the one
  asserting the vulnerable behaviour itself (now inverted to 401);
  the MFA re-enroll half keeps every original assertion against a
  second seeded admin. Pytest **492 passed**. Gates (exact CI
  commands, re-run by the confirmer): ruff check pass, ruff format
  --check 79 files, mypy . 77 source files clean, full pytest 492
  passed, web lint/typecheck/build green.

## §7 — Live proof (OPEN — parent step, blocks the PR)

Migration 0007 is NOT applied live yet. Live staff login currently
500s with PostgREST `PGRST205` (`staff_roles` missing) — routing is
proven live, the login outcome is not. The parent applies 0007 via
the dashboard SQL editor (verbatim SQL in
`docs/admin-foundation-live-proof.md` §1), then proves live against
Supabase `dpwfshafzyxyfoktsggo`: staff invite → setup → login with
role → MFA → Founder access as Owner / 403 as Admin /
support-queue-only as Support; audit rows written; prefix rotation
invalidates sessions; H1 live re-probe of staff-login timing
(unknown vs wrong-password) for final H1 sign-off. The PR must NOT
be opened before live proof passes.

## §8 — Files

Source (`apps/api/app/`): `core/config.py` (fail-fasts incl. B1,
`STAFF_DUMMY_HASH_TARGET_MS=75`, `API_PUBLIC_HOST`),
`core/staff_prefix.py` (host-gate allowlist, prefix guard),
`main.py` (prefix-only staff mounts, openapi gating, F1),
`auth/mfa.py`, `auth/sessions.py`, `auth/provider.py`
(`user_exists`, `disable_password`), `auth/jwt.py` (`leeway=5`),
`services/audit.py`, `services/invites.py`
(`is_well_formed_invite_token`, revoke helpers),
`services/staff.py` (staff accounts, force-reset, re-invite
invalidation), `routers/staff_auth.py` (role-first login, time-based
dummy, MFA, step-up), `routers/admin.py` (incl. invite-revoke),
`routers/admin_ops.py` (rotate-prefix wiring), `db/store.py`,
`db/memory.py`, `db/supabase_store.py` (revoke methods).
Migration: `supabase/migrations/0007_admin_foundation.sql`.
Web: `apps/web/src/app/staff-login/page.tsx`,
`staff-invite/page.tsx`, `staff-mfa-setup/page.tsx`,
`src/lib/staff-api.ts` (same-origin `/api/staff/*`),
`src/middleware.ts` (host gating, prefix rewrites + proxy).
Tests: 492 passed (incl. 401/403/404 + role-confusion + invite
reuse/expiry + session expiry/idle + rotation matrices).

## §9 — Push note (coordinator, 20 Nov 2026)

The local git history is behind remote by design (snapshot pushes);
the working tree is current but entirely uncommitted on branch
`week-2-recon` — there is NO `admin-foundation` branch yet, and a
clean per-file `git diff` vs HEAD cannot be produced. The push must:
(1) create branch `admin-foundation` from the working tree,
(2) push via `push-files` (NEVER `.github/workflows/ci.yml` — the
GitHub App lacks the Workflows permission, it 403s), (3) verify every
pushed file by remote blob SHA vs local `git hash-object`, (4) update
the sync record
(`~/workspace/websurfacehq.muse-github-snapshot-sync.json`) only for
files whose writes succeeded, (5) open the PR with gate results,
review status, and honest gaps in the description. Do NOT push
straight to main.
