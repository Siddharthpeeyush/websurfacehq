# WebSurfaceHQ — Permissions

**Status:** Phase 0 — this document records the **contract only**. The central `can()`
check and the permissions matrix are implemented in **Week 1**, not in Phase 0.
There is no code behind this document yet; nothing here is enforced by anything.
Saying so explicitly is the point: do not mistake this page for an implementation.

## 1. Roles (MVP)

MVP has exactly **one user role: the account owner**. Every account is a single-user
tenant. There is no admin role, no viewer role, and no team in the MVP.

| Role | Scope | Notes |
|---|---|---|
| `owner` | Own account + own resources only | The only MVP role. Can do everything listed as "owner" below, on their own resources only, never on another tenant's |
| `viewer` | Read-only on shared resources | **Post-MVP** (Month 2–3, team seats). Not implemented, not in the schema beyond a nullable `team_id` on targets |
| `admin` (team) | Manage team members + resources | **Post-MVP**. Not implemented |
| `platform_admin` (internal) | Abuse handling, support | Not a product role and never a row in the users table. Abuse is handled via the Supabase dashboard + audit logs, never via an in-app admin panel in MVP |

## 2. Permissions matrix (MVP)

"Own" means a resource whose `user_id` equals the caller's id (or whose target's
`user_id` does, for scans/findings/reports). Cross-tenant access always returns **404**,
never 403 — the API must not reveal whether another tenant's resource exists.

| Action | Owner (own resource) | Owner (another tenant's) | Anonymous |
|---|---|---|---|
| Sign up / log in / reset password | — (public) | — | Allowed (rate-limited 5/15 min) |
| View / update own profile | Yes | n/a | No (401) |
| Create target | Yes | n/a | No (401) |
| List / view own targets | Yes | 404 | No (401) |
| Verify own target | Yes | 404 | No (401) |
| Delete own target | Yes | 404 | No (401) |
| Create scan (on own verified target) | Yes | 404 | No (401) |
| Create scan on unverified target | **No — blocked** (409 `TARGET_NOT_VERIFIED`) | 404 | No (401) |
| List / view own scans | Yes | 404 | No (401) |
| Cancel own scan | Yes (queued/running only) | 404 | No (401) |
| List / view own findings | Yes | 404 | No (401) |
| Mark own finding false_positive / confirmed | Yes | 404 | No (401) |
| Download own report (HTML/PDF) | Yes (short-lived signed URL) | 404 | No (401) |
| Share own report (link) | Yes (Week 4) | 404 | Link holder: read-only, token-scoped |
| View subscription / billing | Yes (own) | 404 | No (401) |
| Create / revoke own API key | **Post-MVP (Pro)** | 404 | No (401) |
| Use public API with API key | **Post-MVP (Pro)** | 404 | No (401) |
| Delete own account + all data | Yes | n/a | No (401) |
| Any action on another tenant's data | — | **404** | No (401) |

## 3. The central `can(user, action, resource)` contract (Week 1)

One function, used by **every** endpoint. No endpoint invents its own authorization logic.

```python
# apps/api/app/auth/permissions.py  (Week 1 — DOES NOT EXIST YET in Phase 0)
def can(user: User, action: str, resource: Resource | None) -> bool:
    """
    Single source of truth for authorization.
    - user: the authenticated Supabase user (or None for anonymous).
    - action: e.g. "target.read", "scan.create", "finding.update", "report.download".
    - resource: the loaded row (target / scan / finding / report) or None
      for collection-level actions (e.g. "target.create").
    Rules:
    1. Anonymous (user is None) -> False for everything except the public
       auth endpoints (which do not call can()).
    2. Resource is None (collection action) -> True iff the action is allowed
       for the caller's role (MVP: owner can create targets/scans on own account).
    3. Resource present -> True iff resource.user_id == user.id (or, post-MVP,
       the user is a team member with the right team role) AND the action is
       allowed for the role AND any state precondition holds
       (e.g. scan.create requires target.verification_status == "verified").
    4. Never raise here; return False. The handler maps False -> 401 (no user)
       or 404 (wrong tenant / not found — deliberately indistinguishable).
    """
```

**Contract rules (non-negotiable):**

1. **Every endpoint calls `can()`** — including `GET` endpoints and report downloads.
   The frontend only hides buttons; the server decides.
2. **Tenant check first, state check second:** a user asking for another tenant's scan
   gets 404 even if that scan is also unverified — never leak state across tenants.
3. **404, not 403, for cross-tenant access.** 403 is reserved for an authenticated user
   who is in the right tenant but lacks the role (post-MVP team roles only). In MVP,
   a logged-in user should almost never see 403 — they see 404 for anything that is
   not theirs.
4. **RLS is the second layer, not a substitute:** `can()` runs in the API; RLS policies
   enforce the same rule in Postgres. A bug in one must not leak data through the other.
5. **State preconditions live in `can()` too:** `scan.create` on an unverified target is
   denied here (409 `TARGET_NOT_VERIFIED` at the handler, after `can()` returns False
   for the state reason — the handler distinguishes "not yours" (404) from "yours but
   not verified" (409)).
6. **Audit:** every denied cross-tenant attempt is logged (user id, action, resource
   type, resource id hash — never the resource contents) to `audit_logs`.

## 4. Action names (canonical list for Week 1)

```
auth.*            (public endpoints; do not call can())
target.create     target.read   target.list   target.verify   target.delete
scan.create       scan.read     scan.list     scan.cancel
finding.read      finding.list  finding.feedback
report.read       report.share
billing.read      billing.checkout            (Week 4 / Month 2)
apikey.create     apikey.read   apikey.delete (post-MVP, Pro)
account.delete    account.export
```

## 5. What is NOT in Phase 0 (explicit)

- The `can()` function does not exist; no endpoint exists to call it.
- No RLS policies exist (no Supabase project yet).
- Team roles, invites, ownership transfer, and the "last owner cannot leave" rule are
  post-MVP designs, recorded here only so Week 1 does not paint them into a corner
  (hence nullable `team_id` on targets).
- The 401/403/404 matrix test (every endpoint: unauthenticated → 401, unauthorized →
  403 where applicable, other tenant → 404) is a Week 1 exit-gate test, not a Phase 0 test.
