# ADR-0007: Verify Supabase JWTs with ES256 via JWKS — HS256 removed (11 Nov 2026)

**Status:** Accepted (owner decision 23:19 IST, 11 Nov 2026 — ES256 with JWKS; do NOT revert the project to legacy HS256).

**Supersedes:** ADR-0006 §3 ("JWTs are verified in the API with PyJWT + SUPABASE_JWT_SECRET").

## Context

The live Supabase project (websurfacehq, ref `dpwfshafzyxyfoktsggo`) signs
access tokens with **ES256** (asymmetric, EC P-256) under the new JWT
Signing Keys. The live JWKS (`<supabase_url>/auth/v1/.well-known/jwks.json`,
public by design) carries exactly one key: `kty: EC`, `crv: P-256`,
`alg: ES256`, `kid: 6b08cdc7-…` — verified live 11 Nov 2026. Live tokens
carry header `{"alg": "ES256", "kid": "6b08cdc7-…", "typ": "JWT"}` and
payload `iss: <supabase_url>/auth/v1`, `aud: "authenticated"`,
`role: "authenticated"`, `sub`, `email`, `exp`/`iat` (3600 s).

The API's `app/auth/jwt.py` verified **HS256 only**
(`algorithms=["HS256"]`, key = `settings.supabase_jwt_secret`). Every real
Bearer token therefore 401'd (`InvalidAlgorithmError` on replay) — finding
F3 of the Week 1 live proof (`/tmp/live-proof/evidence.md` §1d): login
worked, but no authenticated endpoint (`/me`, `/targets`, …) accepted a
real GoTrue token.

## Decision

1. **Verify ES256 only, against the project's public JWKS.**
   `app/auth/jwt.py` fetches the JWKS from
   `{supabase_url}/auth/v1/.well-known/jwks.json`, selects the key by the
   token header's `kid`, and verifies with PyJWT
   (`algorithms=["ES256"]`, key built via
   `jwt.algorithms.ECAlgorithm.from_jwk`). Only `kty: EC`, `crv: P-256`
   keys are indexed; a JWK whose `alg` is present and not `ES256` is
   skipped. Claim checks: `iss` is REQUIRED and must equal
   `<supabase_url>/auth/v1` when a project URL is configured; `aud` is
   REQUIRED and must contain `"authenticated"`; `role` is checked only
   when present (it is redundant with `aud` — same `"authenticated"`
   value from the same issuer); `exp` + `sub` required, UUID `sub`,
   non-empty `email`.
2. **HS256 is removed entirely — no fallback, no shared secret.**
   `SUPABASE_JWT_SECRET` / `settings.supabase_jwt_secret` are deleted
   from `app/core/config.py` and `.env.example`. The verifier rejects any
   non-ES256 `alg` on the header alone, before any key lookup, so an
   HS256 token can never verify even if a legacy secret still exists
   somewhere. The field is removed, not kept accepted-but-ignored:
   nothing else in the codebase read it (verified by grep — only
   `config.py`, `jwt.py`, and two test files referenced it).
3. **`supabase_configured` no longer requires a JWT secret.**
   It is now URL + anon key + service-role key only. Auth needs the URL
   (which locates the JWKS), not a shared secret. The staging/production
   fail-fast check in `config.py` drops `SUPABASE_JWT_SECRET` from its
   required list.
4. **JWKS caching with TTL + refresh on unknown `kid`, stale fallback
   bounded at 24 hours.**
   In-memory cache, TTL 1 hour. A fresh-cache hit needs no fetch. Any
   other case — stale cache, or a `kid` the cache has never seen (the
   rotation case) — fetches once and re-checks, so a key rotated in the
   dashboard verifies immediately and never bricks auth. A failed fetch
   falls back to the previously cached keys ONLY while the cache is at
   most 24 hours old (`_JWKS_STALE_MAX_SECONDS` in `app/auth/jwt.py`);
   an older cache is refused and the token 401s. A rotated-away key can
   therefore never verify a token more than 24 hours after rotation
   during a fetch outage — and in practice the bound is far tighter,
   because a token's own `exp` (Supabase: 3600 s) bounds any token a
   stale key can verify, so the practical risk is negligible.
   The fetch uses the shared proxy-safe helper
   `proxy_safe_httpx_client()` from `apps/api/app/core/http.py` (the
   same helper `provider.sign_out` uses): it builds an
   `httpx.Client(trust_env=False)` and re-applies the operator's
   explicit proxy and CA bundle when configured — a bare
   `httpx.get(..., trust_env=False)` would drop the egress proxy and
   the CA on this VM and could never reach Supabase live (verified
   11 Nov 2026). (An earlier draft of this ADR described the fetch as
   `httpx.get(..., trust_env=False)` and claimed a rotated-away key
   was accepted "for up to one TTL" — both were wrong: the code always
   used the shared helper, and the old fallback had no staleness check
   at all. Corrected 11 Nov 2026, review fix F-L3.)
5. **New dependency: `cryptography==50.0.2`.**
   PyJWT's ES256 support needs the `cryptography` backend, which PyJWT
   ships only as an optional extra and which was not installed. Pinned
   in `requirements.txt`; reason recorded in `DEPENDENCIES.md`.

## Alternatives considered

- **Revert the project to legacy HS256 signing.** Rejected by the owner
  (23:19 IST decision) and by the security case: the legacy JWT secret
  is a single shared symmetric secret — anyone holding it can mint
  arbitrary tokens, and the live-proof round had just demonstrated the
  exposure risk of shared secrets. ES256 keeps the private key in
  Supabase; the API only ever holds public keys.
- **Keep HS256 as a fallback alongside ES256.** Rejected: a fallback
  would reopen exactly the hole the legacy secret's exposure proved —
  an attacker with the old secret could mint valid tokens forever, and
  the verifier could not tell a fallback token from a legitimate one.
  One verification path, one algorithm.
- **Verify tokens by calling Supabase (`getUser`) on every request.**
  Rejected: a network round-trip per authenticated request, plus a hard
  dependency on GoTrue availability for every endpoint. JWKS verification
  is local after one cached fetch and is the standard pattern.
- **Keep `SUPABASE_JWT_SECRET` accepted-but-ignored for compat.**
  Rejected: nothing reads it, and a lingering secret field invites a
  future "just use it as a fallback" regression. Deleting it makes the
  decision structural, not conventional. Operational note (verified
  11 Nov 2026): a leftover `SUPABASE_JWT_SECRET` line in a local `.env`
  or Render env vars does NOT break startup — pydantic-settings ignores
  unknown env vars despite `extra="forbid"` (that only rejects extra
  constructor kwargs). Delete the line anyway, in `apps/api/.env` and
  on Render, so nobody mistakes it for a live credential or reuses it
  as a verification fallback later.
- **Serve stale JWKS indefinitely on fetch failure vs fail closed.**
  Chosen: serve the cached keys on a failed fetch ONLY while the cache
  is at most 24 hours old (availability), fail closed beyond that and
  when the `kid` is absent from every key set we hold (security). A
  stale public key still verifies signatures; the only risk is a
  rotated-away key being accepted for up to 24 hours after a rotation
  performed during a fetch outage — accepted, since Supabase rotation
  is a manual dashboard action, old keys remain valid during rotation
  anyway, and any token the stale key could verify expires within
  3600 s of issue, so the practical risk is negligible. The bound is
  pinned by tests (`test_auth.py`: within-24h fallback verifies,
  beyond-24h fallback 401s).

## Consequences

- Live GoTrue tokens verify: `/me` and every protected endpoint accept
  real Bearer tokens again (live re-proof is the parent's follow-up).
- Tests mint real ES256 tokens with a test-only EC P-256 keypair and a
  stubbed JWKS fetch (`tests/test_auth.py`); the live public key material
  is never pasted into tests or code. Coverage added: valid ES256 passes;
  wrong kid / missing kid / HS256 token / alg=none token / expired / bad
  signature all 401; missing or wrong `iss` / `aud` 401 (both REQUIRED);
  missing `role` still verifies, wrong `role` 401s; unknown kid triggers
  exactly one JWKS refresh and still 401s when absent; a rotated kid
  verifies after refresh; a non-ES256 JWKS entry is filtered by
  `_index_jwks`; stale-cache fallback on fetch failure verifies within
  24 hours and 401s beyond it.
- `cryptography` joins the audit surface (`pip-audit` in CI covers it
  as a direct dependency now).
- ADR-0006 §3 is superseded; its wording ("HS256, exp + sub required,
  iss/aud/role checked") is otherwise preserved by this decision.
