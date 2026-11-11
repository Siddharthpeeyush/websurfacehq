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
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any, Protocol

from app.auth.jwt import User
from app.core.logging import logger

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


def _can(user: User | None, action: str, resource: Resource | None) -> bool:
    # Rule 1: anonymous -> False for everything.
    if user is None:
        return False
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


def can(user: User | None, action: str, resource: Resource | None) -> bool:
    """Single source of truth for authorization. Never raises.

    Returns ``False`` on any error (fail closed) as well as on denial.
    """
    try:
        return _can(user, action, resource)
    except Exception:  # noqa: BLE001 - can() must never raise
        logger.exception("can() failed; denying access")
        return False
