"""The central ``can(user, action, resource)`` authorization contract.

Implements ``docs/permissions.md`` §3 exactly:

1. Anonymous (``user`` is ``None``) -> ``False`` for everything. The public
   auth endpoints do not call ``can()``.
2. Collection action (``resource`` is ``None``) -> ``True`` iff the action
   is a collection-level action allowed for the caller's role. A
   resource-level action with no resource (e.g. a nonexistent id that
   loaded nothing) -> ``False``.
3. Resource present -> ``True`` iff the resource belongs to the caller
   (``resource.user_id == user.id``) AND the action is allowed for the
   role AND any state precondition holds (``scan.create`` requires the
   target's ``verification_status == "verified"``; ``scan.cancel``
   requires a non-terminal scan status when a status is present).
4. Never raises; returns ``False``. The handler maps ``False`` -> 401 (no
   user) or 404 (wrong tenant / not found — deliberately
   indistinguishable). Cross-tenant denials are audited (user id, action,
   resource type, resource id **hash** — never contents) via the store's
   audit log; the store import is lazy because the store is built in
   parallel, and a missing/unavailable store never breaks authorization
   (the denial is still logged locally).
5. Admin (staff-door) actions (``admin.*``) are decided by the PLATFORM
   role — Owner / Admin / Support — passed as the ``platform_role``
   keyword argument. The platform role is resolved server-side from
   ``staff_roles`` (never from the client); ``can()`` trusts only the
   value its caller passes, so the trust boundary sits at the caller
   (Child C's staff auth). An admin action with no platform role (a
   customer calling an admin endpoint) is always denied, and the
   customer ``user.role`` is irrelevant to admin actions — the platform
   role is the sole authority there. Admin actions ignore ``resource``:
   staff are not tenants, so there is no tenancy check; the role check
   alone decides.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any, Protocol

from app.auth.jwt import User
from app.core.logging import logger

# Platform (staff) roles: Owner / Admin / Support. These live in the
# staff_roles table and are resolved server-side; they are a separate
# namespace from the customer "owner" role on User — a staff "owner"
# and a customer "owner" are different things that happen to share a
# string. can() never reads the platform role from the User object
# (User carries no staff role); the caller passes it explicitly.
PLATFORM_ROLES: frozenset[str] = frozenset({"owner", "admin", "support"})

# Admin (staff-door) actions, by the least-privilege platform role that
# may perform them. DESIGN-LOCK.md (frozen 15 Nov 2026): Support sees
# the Support + Abuse screens only; Admin on /founder -> 403; every
# staff-account mutation (create/suspend/delete/re-role/revoke
# sessions/force reset/MFA re-enroll) is Owner-only; Founder is
# Owner-only (+ step-up MFA when the flag is on — the MFA check is a
# session concern, not a can() concern).
ADMIN_OWNER_ONLY_ACTIONS: frozenset[str] = frozenset(
    {
        "admin.users.invite",
        "admin.users.suspend",
        "admin.users.delete",
        "admin.users.role",
        "admin.users.revoke_sessions",
        "admin.users.force_reset",
        "admin.users.mfa_re_enroll",
        "admin.settings.write",
        "admin.settings.rotate_prefix",
        "admin.founder.read",
    }
)

ADMIN_OWNER_ADMIN_ACTIONS: frozenset[str] = frozenset(
    {
        "admin.users.read",
        "admin.scans.read",
        "admin.scans.queue.read",
        "admin.billing.read",
        "admin.security.read",
        "admin.audit.read",
        "admin.settings.read",
    }
)

ADMIN_ALL_STAFF_ACTIONS: frozenset[str] = frozenset(
    {
        "admin.me.read",
        "admin.support.read",
        "admin.abuse.read",
    }
)

ADMIN_ACTIONS: frozenset[str] = frozenset(
    ADMIN_OWNER_ONLY_ACTIONS | ADMIN_OWNER_ADMIN_ACTIONS | ADMIN_ALL_STAFF_ACTIONS
)

# Collection-level actions: no resource row exists to own, so the role
# check alone decides. MVP has one role (owner); every action here is
# owner-allowed.
COLLECTION_ACTIONS: frozenset[str] = frozenset(
    {
        "target.create",
        "target.list",
        "scan.list",
        "finding.list",
    }
)

# Resource-level actions an owner may perform on their OWN resources.
# "finding.list" appears here as well as in COLLECTION_ACTIONS: listing
# findings is collection-level in general, but the findings router calls
# it resource-scoped (list the findings OF one scan), so both shapes must
# be allowed for an owner on their own scan.
OWNER_RESOURCE_ACTIONS: frozenset[str] = frozenset(
    {
        "target.read",
        "target.verify",
        "target.delete",
        "scan.create",
        "scan.read",
        "scan.cancel",
        "finding.read",
        "finding.list",
        "finding.feedback",
        "report.read",
        "report.share",
        "billing.read",
        "billing.checkout",
        "account.delete",
        "account.export",
    }
)


class Resource(Protocol):
    """Structural type for a tenant-owned row (target / scan / finding)."""

    user_id: uuid.UUID


def _hash_resource_id(resource: Resource) -> str | None:
    """SHA-256 of the resource id, for audit logs (never the raw id)."""
    resource_id: Any = getattr(resource, "id", None)
    if resource_id is None:
        return None
    return hashlib.sha256(str(resource_id).encode("utf-8")).hexdigest()


def _audit_cross_tenant(user: User, action: str, resource: Resource) -> None:
    """Log a denied cross-tenant attempt: store audit log + local log line.

    Best-effort only — an unavailable store must never break the denial
    itself, and this function never raises.
    """
    metadata: dict[str, Any] = {
        "resource_type": type(resource).__name__,
        "resource_id_hash": _hash_resource_id(resource),
        "denied": True,
        "reason": "cross_tenant",
    }
    try:
        # Lazy import: the store (app.db) is built in parallel to
        # this module; importing it here keeps this module importable
        # before the store lands.
        from app.db import get_store

        get_store().log_audit(
            user_id=user.id,
            action=action,
            target_domain=None,
            metadata=metadata,
        )
    except Exception:  # noqa: BLE001 - audit must never break authorization
        logging.getLogger("websurfacehq").warning(
            "audit log unavailable for denied cross-tenant attempt",
            extra={"user_id": str(user.id), "action": action, **metadata},
        )
    logger.warning(
        "denied cross-tenant attempt",
        extra={"user_id": str(user.id), "action": action, **metadata},
    )


def _can_admin(action: str, platform_role: str | None) -> bool:
    """Platform-role decision for ``admin.*`` actions. No tenancy check:
    staff are not tenants, and the resource (if any) is ignored — the
    role alone decides. ``platform_role`` must be the server-resolved
    role from staff_roles; anything else (None, an unknown string, a
    client-supplied value the caller failed to resolve) denies.
    """
    if platform_role not in PLATFORM_ROLES:
        return False
    if action in ADMIN_OWNER_ONLY_ACTIONS:
        return platform_role == "owner"
    if action in ADMIN_OWNER_ADMIN_ACTIONS:
        return platform_role in ("owner", "admin")
    if action in ADMIN_ALL_STAFF_ACTIONS:
        return True
    return False


def _can(
    user: User | None,
    action: str,
    resource: Resource | None,
    platform_role: str | None = None,
) -> bool:
    # Rule 1: anonymous -> False for everything.
    if user is None:
        return False
    # Rule 5: admin actions are decided by the platform role alone,
    # before the customer role check — a staff session's customer
    # "owner" role must never widen or narrow an admin decision, and
    # a customer (platform_role None) can never pass an admin action.
    if action.startswith("admin."):
        return _can_admin(action, platform_role)
    # MVP has exactly one role; any other role string is denied by default
    # (future team roles are added here, never by widening this branch).
    if user.role != "owner":
        return False

    # Rule 2: collection action -> role check only.
    if resource is None:
        return action in COLLECTION_ACTIONS

    # Rule 3, tenant check FIRST: another tenant's resource is denied even
    # if it would also fail a state check — never leak state across tenants.
    if str(resource.user_id) != str(user.id):
        _audit_cross_tenant(user, action, resource)
        return False

    # Own resource, but the action must be allowed for the role.
    if action not in OWNER_RESOURCE_ACTIONS:
        return False

    # Rule 3, state preconditions (own resource only — see above).
    # Only scan.create has a state precondition in can() (the target must
    # be verified); the handler maps that denial to 409 TARGET_NOT_VERIFIED
    # after the tenancy check. Other state conflicts are NOT authorization
    # denials and do NOT live here: cancelling a finished scan is a 409
    # SCAN_CONFLICT raised by the store/handler, so can() allows
    # scan.cancel on any own scan regardless of status.
    if action == "scan.create":
        # The resource for scan.create is the TARGET being scanned.
        return getattr(resource, "verification_status", None) == "verified"
    return True


def can(
    user: User | None,
    action: str,
    resource: Resource | None = None,
    *,
    platform_role: str | None = None,
) -> bool:
    """Single source of truth for authorization. Never raises.

    Returns ``False`` on any error (fail closed) as well as on denial.

    ``platform_role`` is the server-resolved staff role (``"owner"`` |
    ``"admin"`` | ``"support"``) for ``admin.*`` actions; callers MUST
    resolve it from ``staff_roles`` themselves — never pass a value
    that came from the client. It is ignored for customer actions.
    """
    try:
        return _can(user, action, resource, platform_role)
    except Exception:  # noqa: BLE001 - can() must never raise
        logger.exception("can() failed; denying access")
        return False
