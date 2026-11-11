"""Shared router dependencies.

Auth comes from Builder B's ``app.auth`` (landed): ``get_current_user``
(Supabase JWT verification, 401 when absent/invalid) and the central
``can(user, action, resource)`` live there — this module re-exports them
so routers import from one place. Nothing here reimplements auth.

One rule routers must follow because ``can()`` folds STATE preconditions
in (docs/permissions.md §3.5, ``app/auth/permissions.py``): when a handler
must distinguish "not yours" (404) from "yours but wrong state" (409),
it checks tenancy with a READ action that carries no state precondition
(e.g. ``target.read`` / ``scan.read``) and then checks state explicitly.
Calling ``can(user, "scan.create", unverified_target)`` directly would
return False and look like a 404 — the verified check below it would
never run. The scan handlers in this package follow that pattern.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.auth.deps import get_current_user
from app.auth.jwt import User
from app.auth.permissions import can
from app.core.errors import ApiError
from app.db import get_store
from app.db.store import Store

__all__ = ["User", "can", "get_current_user", "get_store_dep", "require_can", "require_resource"]


def get_store_dep() -> Store:
    """FastAPI dependency returning the active store (see app.db)."""
    return get_store()


def require_can(
    user: User,
    action: str,
    resource: Any | None,
    *,
    store: Store,
    resource_id: UUID | None = None,
) -> None:
    """Enforce :func:`can`; on denial raise 404 NOT_FOUND (never 403 for
    cross-tenant access — the API must not reveal whether another
    tenant's resource exists). Denied cross-tenant attempts are
    audit-logged inside ``can()`` itself, so this helper logs nothing."""
    if can(user, action, resource):
        return
    raise ApiError(404, "NOT_FOUND", "Resource not found")


def require_resource(
    user: User,
    action: str,
    resource: Any | None,
    *,
    store: Store,
    resource_id: UUID | None = None,
) -> Any:
    """Load-then-authorize helper: None resource -> 404; present but not
    permitted -> 404 via require_can. Returns the resource.

    Cross-tenant probing IS audited (M8 review fix): when the tenant-scoped
    load returns None, the store is asked (audit-only, no row returned)
    whether the id exists under another tenant. A foreign id is logged as
    ``cross_tenant_access_denied`` (resource id hashed, never raw) and
    still answers 404 — the audit trail exists without an existence oracle.
    A nonexistent id logs nothing.
    """
    if resource is None:
        if resource_id is not None:
            _audit_cross_tenant_probe(user, action, resource_id, store)
        raise ApiError(404, "NOT_FOUND", "Resource not found")
    require_can(user, action, resource, store=store, resource_id=resource_id)
    return resource


def _audit_cross_tenant_probe(user: User, action: str, resource_id: UUID, store: Store) -> None:
    """Log a cross-tenant probe when the id belongs to another tenant.

    Best-effort: any failure here must never break the 404 answer.
    """
    from app.db.store import hash_resource_id

    kind = action.split(".")[0]
    try:
        owner = store.get_owner(kind, resource_id)
    except Exception:  # noqa: BLE001 - audit must never break the endpoint
        return
    if owner is None or owner == user.id:
        return
    try:
        store.log_audit(
            user.id,
            "cross_tenant_access_denied",
            None,
            {
                "action": action,
                "resource": kind,
                "resource_id_hash": hash_resource_id(resource_id),
            },
        )
    except Exception:  # noqa: BLE001 - audit must never break the endpoint
        return
