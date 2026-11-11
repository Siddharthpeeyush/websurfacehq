# WebSurfaceHQ — API Conventions

**Status:** Phase 0 (scaffold / docs only). These conventions bind every endpoint built
in Weeks 1–4. An endpoint that violates them fails review, even if it works.

## 1. Naming

- **Base path:** `/api/v1/...` for all product endpoints. Health is outside versioning:
  `GET /health` (full component check) and `GET /live` (lightweight, for load balancers).
- **Resources:** plural nouns, kebab-case for multi-word resources:
  `/api/v1/targets`, `/api/v1/targets/{id}/verify`, `/api/v1/scans`,
  `/api/v1/scans/{id}/findings`, `/api/v1/findings/{id}/feedback`,
  `/api/v1/scans/{id}/report.pdf`, `/api/v1/billing/checkout`,
  `/api/v1/webhooks/razorpay`, `/api/v1/webhooks/lemonsqueezy`.
- **No verbs in paths** except where the action has no REST equivalent (`/verify`,
  `/cancel`, `/feedback`, `/checkout`, `/portal`). Prefer `POST /scans/{id}/cancel`
  over `POST /cancel-scan`.
- **JSON field names:** `snake_case` everywhere (matches Postgres columns and Pydantic
  models). Dates are ISO 8601 UTC strings (`2026-11-11T14:30:00Z`). UUIDs as strings.
- **IDs in URLs:** UUIDs only. Never sequential integer ids (no enumeration oracle).

## 2. One error format

Every error — 4xx and 5xx, API and webhook — uses exactly this shape. No other shape.

```json
{
  "code": "TARGET_NOT_VERIFIED",
  "message": "This target has not been verified yet. Complete DNS or file verification before creating a scan.",
  "details": { "target_id": "…", "verification_status": "pending" }
}
```

- `code`: stable `UPPER_SNAKE_CASE` machine code. Clients branch on `code`, never on
  `message`.
- `message`: one human-readable sentence. Safe to show to the user. Never contains a
  stack trace, a SQL fragment, a secret, or an internal path.
- `details`: optional object with safe, structured context (ids, field names, limits).
  Never contains secrets, tokens, or another tenant's data.
- **Canonical codes** (extend only by adding to this table, never ad hoc):

| Code | HTTP | Meaning |
|---|---|---|
| `UNAUTHORIZED` | 401 | No valid JWT / API key |
| `FORBIDDEN` | 403 | Authenticated but wrong role (post-MVP teams only; see permissions.md) |
| `NOT_FOUND` | 404 | Resource does not exist **or belongs to another tenant** (deliberately indistinguishable) |
| `VALIDATION_ERROR` | 422 | Input failed Pydantic validation; `details.fields` lists per-field errors |
| `TARGET_NOT_VERIFIED` | 409 | Scan requested on an unverified target |
| `QUOTA_EXCEEDED` | 429 | Plan quota hit (scans/day, active scans, requests/scan) |
| `RATE_LIMITED` | 429 | Too many requests; `Retry-After` header is always set |
| `SCAN_CONFLICT` | 409 | e.g. cancelling a scan that is already done |
| `VERIFICATION_EXPIRED` | 410 | Verification token past its 7-day expiry |
| `INTERNAL_ERROR` | 500 | Catch-all. Message is generic; detail goes to Sentry, never to the client |

## 3. Input validation at the boundary

- Every request body is a Pydantic model, validated **before** any business logic,
  authz-adjacent state check, or DB write. Invalid input → 422 `VALIDATION_ERROR`
  with per-field errors in `details.fields`.
- Rules: domain fields validated as hostnames (regex + max 253 chars, no URL schemes,
  no userinfo, no ports — a target is a domain, not a URL); enums enforced
  (`depth: quick | standard | deep`); ids must be UUIDs; strings length-capped;
  numbers range-checked (e.g. `max_urls` 1–500).
- **Never trust the frontend:** client-side validation mirrors server rules for UX
  only; the server re-validates everything.
- File uploads (verification file is fetched by the worker, not uploaded — but any
  future upload): type + size validated server-side before an upload URL is issued.

## 4. Cursor pagination (all list endpoints, no exceptions)

- **No offset pagination.** Every list endpoint takes `?cursor=<opaque>&limit=<n>`
  (default `limit=20`, max `100`) and returns:

```json
{
  "data": [ … ],
  "next_cursor": "eyJ…",      // null when there are no more pages
  "has_more": true
}
```

- Cursors are opaque, server-generated (base64 of the sort key + id), and never expose
  internal ids or offsets. Sorting is stable (created_at desc, id tiebreak) so a page
  never repeats or skips a row when new rows arrive.
- Lists are always tenant-scoped (`WHERE user_id = :user_id`) and ordered; unbounded
  lists are a bug — every list endpoint paginates.

## 5. Auth + tenant context in every handler

- Every handler (except the public auth endpoints and `/health` / `/live`) does, in order:
  1. Verify the Supabase JWT (or API key, post-MVP) → 401 if missing/invalid/expired.
  2. Load the resource (if the route has an id) with a tenant-scoped query.
  3. Call `can(user, action, resource)` → 401 / 404 per `docs/permissions.md`.
  4. Validate input (Pydantic) — validation errors are 422 and must not leak whether
     the resource exists (validate shape first, then load; a 422 on a nonexistent id is
     fine, a 404 that reveals existence is not — the handler loads tenant-scoped, so a
     foreign id simply loads nothing → 404).
  5. Run business logic in `services/`, never in the handler.
- The authenticated `user_id` is attached to the request context, the structured log
  lines (`request_id`, `user_id`), and the Sentry scope.
- **Response header:** every response carries `X-Request-Id` (same value as the log
  lines), so a user can quote it in a support ticket.

## 6. Status-code rules

| Situation | Status |
|---|---|
| Success, resource created | 201 (with the created resource in the body) |
| Success, read / update / delete | 200 (delete returns 200 with the deleted id, or 204 with no body — pick 200 + body for consistency) |
| Async accepted (scan queued) | 202 (scan object with status `queued`) |
| No valid auth | 401 `UNAUTHORIZED` |
| Wrong role (post-MVP) | 403 `FORBIDDEN` |
| Not found **or another tenant's** | 404 `NOT_FOUND` |
| State conflict (unverified target, cancel a finished scan) | 409 (specific code) |
| Validation failed | 422 `VALIDATION_ERROR` |
| Quota / rate limit | 429 + `Retry-After` header (seconds) |
| Unexpected server error | 500 `INTERNAL_ERROR`, generic message |

Never return 200 with an error body. Never return a stack trace. Never use 403 to mean
"not yours" — that is 404 (see §5 and `docs/permissions.md`).

## 7. Money as integer paise/cents

- All money is stored and transmitted as **integer minor units** (paise for INR,
  cents for USD) — never floats, never decimals in JSON. `amount_paise: 149900` means
  Rs 1,499.00. Display formatting (₹1,499.00) happens only in the frontend.
- Plan limits are read from the `subscriptions` row, so a plan change is a data change,
  not a deploy. Payment webhooks are the source of truth for subscription state;
  handlers verify signatures, store processed event IDs, and are idempotent
  (replay twice = no change).

## 8. Versioning and backwards compatibility

- Breaking changes require a new version (`/api/v2/...`); `/api/v1` is never broken
  in place. Additive changes (new optional fields, new endpoints) are fine within v1.
- The frontend pins the version it was built against; the API never serves an
  unversioned product path.
