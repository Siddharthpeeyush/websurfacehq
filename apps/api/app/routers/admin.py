"""Admin API — ``/admin`` (Child D, admin-foundation build, plan §3).

Every route requires a valid staff SESSION (``get_current_staff`` ->
401 when unauthenticated, 403 when the session's user has no active
staff account) plus the CENTRAL ``can()`` on every action
(``require_staff`` -> 403) — ``can(user, action, None,
platform_role=staff.role)`` with Child A's action names
(``admin.me.read``, ``admin.users.read``, ...). No JWT is accepted
on ``/admin/*``: the bearer is the staff-session UUID (Child C's
``get_staff_session`` -> Child B's ``SessionManager.validate``).
Frontend only hides actions; the server is the source of truth.
Every admin action writes an audit row via Child A's audit service
(``app.services.audit.write``). No endpoint returns fake/demo data;
lists use cursor pagination; errors use the one standard
``{"code", "message", "details"}`` shape.

Staff accounts live in the STORE (migration 0007's ``staff_roles``
table on the Supabase path, ``InMemoryStore`` in tests/dev) via
``app.services.staff`` (C2 fix, 20 Nov 2026) — the provisional
in-memory registry is gone; the DB is the source of truth. Staff
identity is resolved server-side from that store, never from the
client.
Self-action guards: the Owner cannot suspend, delete, or re-role
themself (router-level 409 ``SELF_ACTION_NOT_ALLOWED``; the service's
OwnerProtectedError is the backstop) — ``can()`` alone does not stop
it, and it would break the exactly-one-Owner invariant.

The staff door is prefix-gated: ``main.py`` mounts the staff routers
under ``/<secret-prefix>/`` with Child C's ``require_staff_prefix``
guard (``app.core.staff_prefix``) — a request to the staff host
outside the prefix answers the generic 404. With an empty prefix
(local dev) enforcement is off and the routers mount at root.

Honest gaps remaining in THIS tree (20 Nov 2026):

- Cross-tenant admin lists (``GET /admin/scans``,
  ``GET /admin/billing``, ``GET /admin/support/tickets``,
  ``GET /admin/abuse``) have no store backing yet — the Store protocol
  has no ``list_all_*`` methods — so they answer 503
  ``STAFF_DATA_UNAVAILABLE`` (never an empty list pretending to be
  data). Abuse reports have no data model anywhere yet (no migration,
  no table). Tests supply a fake store implementing the methods.
- ``POST /admin/settings`` has no persistence layer (Child B owns the
  staff settings in config; no settings store exists) — validated, then
  503, never a fake 200.
- ``GET /admin/scans/queue`` reads REAL depths: Redis ``LLEN`` per
  Celery queue (recon/crawl/vuln) plus DLQ key/entry counts via SCAN.
  When Redis is unreachable every depth is ``null`` with status
  ``"unavailable"`` — never an invented 0.
- API keys do not exist yet (``/admin/security`` reports
  ``api_keys: []`` with ``api_keys_available: false``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, EmailStr

from app.auth.jwt import User
from app.auth.sessions import StaffSession
from app.core.errors import ApiError
from app.core.logging import logger
from app.db.store import Store, decode_cursor, encode_cursor
from app.routers.deps import can
from app.routers.staff_auth import get_staff_session
from app.services import audit as audit_service
from app.services import staff as staff_service
from app.services.invites import STAFF_ROLES
from app.services.staff import (
    DuplicateOwnerError,
    DuplicateStaffError,
    OwnerProtectedError,
    StaffAccount,
    StaffNotFoundError,
    StaffNotOwnerError,
    ensure_staff_account,
)

router = APIRouter(prefix="/admin", tags=["admin"])

QUEUE_NAMES: tuple[str, ...] = ("recon", "crawl", "vuln")


@dataclass(frozen=True)
class StaffUser:
    """An authenticated staff member (Owner / Admin / Support).

    ``account`` is the server-resolved staff row (Child C's service);
    ``user`` is a synthetic identity built from the session — the
    central ``can()`` requires a non-None user, and for ``admin.*``
    actions it decides by ``platform_role`` alone (permissions
    Rule 5), so the session, not a JWT, is the authentication.
    ``step_up_verified`` is True when THIS session passed a fresh
    MFA check (``POST /staff/auth/step-up/verify`` marks it).
    """

    id: UUID
    email: str
    role: str
    status: str
    user: User
    account: StaffAccount
    mfa_verified: bool
    step_up_verified: bool


def _field(row: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` off a store row (attribute or dict)."""
    if isinstance(row, dict):
        return row.get(name, default)
    return getattr(row, name, default)


def _staff_data_unavailable(method: str) -> ApiError:
    return ApiError(
        503,
        "STAFF_DATA_UNAVAILABLE",
        "Staff data is not available yet: the admin-foundation store "
        f"methods ({method}) have not landed (Child A).",
        details={"missing_store_method": method},
    )


def _optional_method(store: Store, name: str) -> Any:
    """Return an optional store method, or raise 503 when Child A's
    store support for it has not landed. Never silently degrade to an
    empty/fake result."""
    method = getattr(store, name, None)
    if method is None:
        raise _staff_data_unavailable(name)
    return method


def get_current_staff(session: StaffSession = Depends(get_staff_session)) -> StaffUser:
    """Resolve the live staff session to a staff identity.

    401 comes from ``get_staff_session`` (no/invalid/revoked/expired
    session — all one generic ``INVALID_SESSION``). A session whose
    user has no staff row, or a suspended staff row, is 403 (never
    401: the session verified, the account simply is not active
    staff). The role is resolved server-side from the STORE
    (``ensure_staff_account`` — the store-backed successor of the old
    registry read, H3 fix): one source of truth for "is this person
    staff", the same resolution the staff-auth router uses. Step-up
    state is the CALLER's own session (``step_up_verified_at``) — the
    Founder gate sees exactly the session that made the request.
    """
    account = ensure_staff_account(session.user_id)
    if account is None or account.status != "active":
        raise ApiError(403, "FORBIDDEN", "This account is not an active staff account")
    return StaffUser(
        id=session.user_id,
        email=account.email,
        role=str(account.role),
        status=account.status,
        user=User(id=session.user_id, email=account.email),
        account=account,
        mfa_verified=bool(account.mfa_enrolled),
        step_up_verified=session.step_up_verified_at is not None,
    )


def require_staff(staff: StaffUser, action: str) -> None:
    """Enforce the CENTRAL ``can()`` on an admin action. The platform
    role is the server-resolved staff role; a customer (no platform
    role) can never pass an admin action. Denial is 403 FORBIDDEN."""
    if not can(staff.user, action, None, platform_role=staff.role):
        raise ApiError(403, "FORBIDDEN", "This staff role may not perform this action")


def _audit(
    staff: StaffUser,
    action: str,
    target: UUID | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> None:
    """Write one append-only audit row via Child A's audit service.

    LOUD (M1 fix): an audit failure is NOT swallowed — it logs an
    ERROR and raises a 500 that tells the admin the action
    SUCCEEDED but was NOT audited, so a human follows up. The old
    best-effort swallow hid unaudited actions entirely.

    This helper is used ONLY for actions whose service does NOT
    already write an audit row (prefix rotation in admin_ops). Staff
    mutations (invite / suspend / delete / role / revoke / force-reset
    / MFA re-enroll) are audited ONCE by the service itself, with
    correct before/after — the router writes no second row for them
    (the old duplicate rows also read ``before`` from the same object
    the service had just mutated in place, so every one of them
    carried a false ``before``).
    """
    try:
        audit_service.write(
            actor=staff.id, action=action, target=target, before=before, after=after
        )
    except Exception as exc:  # noqa: BLE001 - the loud contract is the point
        logger.exception(
            "admin audit write failed; action performed but NOT audited",
            extra={"actor_id": str(staff.id), "action": action, "error_type": type(exc).__name__},
        )
        raise ApiError(
            500,
            "AUDIT_WRITE_FAILED",
            "The action succeeded but the audit record could not be "
            "written. Follow up: check the audit log and re-record "
            f"this action ({action}).",
        ) from exc


def _paginate_staff(
    rows: list[StaffAccount], cursor: str | None, limit: int
) -> tuple[list[StaffAccount], str | None]:
    """Cursor pagination over staff accounts (created_at desc, user_id
    desc — the store's opaque cursor convention). Raises ValueError on
    a malformed cursor (callers map it to 422)."""
    now = datetime.now(timezone.utc)
    ordered = sorted(rows, key=lambda r: (r.created_at or now, r.user_id), reverse=True)
    if cursor is not None:
        cursor_created_at, cursor_id = decode_cursor(cursor)
        ordered = [
            r for r in ordered if (r.created_at or now, r.user_id) < (cursor_created_at, cursor_id)
        ]
    page = ordered[:limit]
    next_cursor: str | None = None
    if len(ordered) > limit and page:
        last = page[-1]
        next_cursor = encode_cursor(last.created_at or now, last.user_id)
    return page, next_cursor


def _list_page(
    store: Store, method_name: str, cursor: str | None, limit: int, **filters: Any
) -> tuple[list[Any], str | None]:
    """Call an optional paginated store list method (503 when absent,
    422 on a malformed cursor — same mapping as the customer routers)."""
    method = _optional_method(store, method_name)
    try:
        items, next_cursor = method(cursor, limit, **filters)
    except ValueError as exc:
        raise ApiError(422, "VALIDATION_ERROR", "Invalid cursor") from exc
    return items, next_cursor


def _all_rows(store: Store, method_name: str, limit: int = 100) -> list[Any]:
    """Drain a paginated optional list method (summaries only). Capped
    at 100 pages so a runaway store cannot loop forever."""
    rows: list[Any] = []
    cursor: str | None = None
    for _ in range(100):
        page, cursor = _list_page(store, method_name, cursor, limit)
        rows.extend(page)
        if cursor is None:
            return rows
    raise ApiError(
        503,
        "STAFF_DATA_UNAVAILABLE",
        "Staff summary too large to compute in one request",
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class StaffUserResponse(BaseModel):
    id: UUID
    email: str
    role: str
    status: str
    mfa_verified: bool
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: Any) -> StaffUserResponse:
        user_id = _field(row, "user_id") or _field(row, "id")
        mfa_verified = _field(row, "mfa_enrolled")
        if mfa_verified is None:
            mfa_verified = _field(row, "mfa_verified", True)
        return cls(
            id=UUID(str(user_id)),
            email=str(_field(row, "email", "")),
            role=str(_field(row, "role", "")),
            status=str(_field(row, "status", "active")),
            mfa_verified=bool(mfa_verified),
            created_at=_field(row, "created_at"),
        )


class StaffListResponse(BaseModel):
    data: list[StaffUserResponse]
    next_cursor: str | None
    has_more: bool


class InviteRequest(BaseModel):
    email: EmailStr
    role: str

    def validated_role(self) -> str:
        role = self.role.strip().lower()
        if role not in STAFF_ROLES:
            raise ApiError(422, "VALIDATION_ERROR", "role must be owner, admin, or support")
        return role


class InviteResponse(BaseModel):
    id: UUID
    email: str
    role: str
    expires_at: datetime | None
    # Raw token, returned ONCE (same pattern as the target verification
    # token): the Owner forwards it as the single-use setup link. Only
    # the SHA-256 hash is stored.
    invite_token: str


class RoleChangeRequest(BaseModel):
    role: str

    def validated_role(self) -> str:
        role = self.role.strip().lower()
        if role not in STAFF_ROLES:
            raise ApiError(422, "VALIDATION_ERROR", "role must be owner, admin, or support")
        return role


class ConfirmRequest(BaseModel):
    """Two-step confirm for destructive Owner actions (delete staff,
    rotate prefix): the client sends confirm=true on the second tap."""

    confirm: bool = False


class ActionResultResponse(BaseModel):
    id: UUID
    status: str
    detail: str | None = None


class SessionsRevokedResponse(BaseModel):
    user_id: UUID
    sessions_revoked: int | None


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _load_staff_account(user_id: UUID) -> StaffAccount:
    """Load one staff account; a customer id or unknown id is 404 —
    never an existence oracle for non-staff accounts."""
    account = staff_service.get_staff_account(user_id)
    if account is None:
        raise ApiError(404, "NOT_FOUND", "Resource not found")
    return account


@router.get("/me", response_model=StaffUserResponse)
def get_me(staff: StaffUser = Depends(get_current_staff)) -> StaffUserResponse:
    require_staff(staff, "admin.me.read")
    return StaffUserResponse(
        id=staff.id,
        email=staff.email,
        role=staff.role,
        status=staff.status,
        mfa_verified=staff.mfa_verified,
        created_at=staff.account.created_at,
    )


@router.get("/users", response_model=StaffListResponse)
def list_users(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    staff: StaffUser = Depends(get_current_staff),
) -> StaffListResponse:
    require_staff(staff, "admin.users.read")
    try:
        page, next_cursor = _paginate_staff(staff_service.list_staff_accounts(), cursor, limit)
    except ValueError as exc:
        raise ApiError(422, "VALIDATION_ERROR", "Invalid cursor") from exc
    return StaffListResponse(
        data=[StaffUserResponse.from_row(row) for row in page],
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/users/{user_id}", response_model=StaffUserResponse)
def get_user(
    user_id: UUID,
    staff: StaffUser = Depends(get_current_staff),
) -> StaffUserResponse:
    require_staff(staff, "admin.users.read")
    return StaffUserResponse.from_row(_load_staff_account(user_id))


@router.post("/users/invite", status_code=201, response_model=InviteResponse)
def invite_user(
    body: InviteRequest,
    staff: StaffUser = Depends(get_current_staff),
) -> InviteResponse:
    require_staff(staff, "admin.users.invite")
    role = body.validated_role()
    email = body.email.strip().lower()
    try:
        invite, token = staff_service.create_staff_invite(staff.account, email, role)
    except StaffNotOwnerError as exc:
        raise ApiError(403, "FORBIDDEN", "Only the Owner can invite staff") from exc
    except DuplicateStaffError as exc:
        raise ApiError(
            409, "STAFF_ALREADY_EXISTS", "A staff account or invite already exists"
        ) from exc
    except DuplicateOwnerError as exc:
        raise ApiError(409, "SECOND_OWNER", "The platform has exactly one Owner") from exc
    # No router audit row here (M1 fix): the service writes the ONE
    # row (staff.invite_created) — a second admin.users.invite row
    # would double-count the action under a different name.
    return InviteResponse(
        id=invite.id,
        email=invite.email,
        role=str(invite.role),
        expires_at=invite.expires_at,
        invite_token=token,
    )


@router.post("/users/invites/{invite_id}/revoke", response_model=ActionResultResponse)
def revoke_invite(
    invite_id: UUID,
    staff: StaffUser = Depends(get_current_staff),
) -> ActionResultResponse:
    """Owner revokes a pending staff invite (F3 fix).

    The revoked token 404s at accept time from now on. Revoking a
    consumed/expired invite — or an unknown id — answers 404: it is
    already unusable, so there is nothing to distinguish. Non-Owner
    staff get 403 (``admin.users.invite`` is Owner-only).
    """
    require_staff(staff, "admin.users.invite")
    try:
        staff_service.revoke_staff_invite(staff.account, invite_id)
    except StaffNotOwnerError as exc:
        raise ApiError(403, "FORBIDDEN", "Only the Owner can revoke staff invites") from exc
    except StaffNotFoundError as exc:
        raise ApiError(404, "NOT_FOUND", "Resource not found") from exc
    # No router audit row (M1 fix): the service writes the ONE row
    # (staff.invite_revoked).
    return ActionResultResponse(id=invite_id, status="revoked")


@router.post("/users/{user_id}/suspend", response_model=StaffUserResponse)
def suspend_user(
    user_id: UUID,
    staff: StaffUser = Depends(get_current_staff),
) -> StaffUserResponse:
    require_staff(staff, "admin.users.suspend")
    # The Owner is the only role that can suspend — and the Owner may
    # never suspend themself (can() alone does not stop it; a
    # self-suspended Owner would break the exactly-one-Owner invariant
    # and lock every staff door). The service's OwnerProtectedError is
    # the backstop; this guard is the explicit refusal.
    if user_id == staff.id:
        raise ApiError(409, "SELF_ACTION_NOT_ALLOWED", "The Owner cannot suspend their own account")
    try:
        updated = staff_service.suspend_staff(staff.account, user_id)
    except StaffNotOwnerError as exc:
        raise ApiError(403, "FORBIDDEN", "Only the Owner can suspend staff") from exc
    except StaffNotFoundError as exc:
        raise ApiError(404, "NOT_FOUND", "Resource not found") from exc
    except OwnerProtectedError as exc:
        raise ApiError(409, "OWNER_PROTECTED", "The Owner account cannot be suspended") from exc
    # No router audit row (M1 fix): the service writes the ONE row
    # (staff.suspended, correct before/after).
    return StaffUserResponse.from_row(updated)


@router.post("/users/{user_id}/delete", response_model=ActionResultResponse)
def delete_user(
    user_id: UUID,
    body: ConfirmRequest,
    staff: StaffUser = Depends(get_current_staff),
) -> ActionResultResponse:
    require_staff(staff, "admin.users.delete")
    if not body.confirm:
        raise ApiError(
            422,
            "VALIDATION_ERROR",
            "Deleting a staff account requires confirm=true (two-step confirm)",
        )
    # Self-delete refusal: same exactly-one-Owner reasoning as suspend.
    if user_id == staff.id:
        raise ApiError(409, "SELF_ACTION_NOT_ALLOWED", "The Owner cannot delete their own account")
    try:
        staff_service.delete_staff(staff.account, user_id)
    except StaffNotOwnerError as exc:
        raise ApiError(403, "FORBIDDEN", "Only the Owner can delete staff") from exc
    except StaffNotFoundError as exc:
        raise ApiError(404, "NOT_FOUND", "Resource not found") from exc
    except OwnerProtectedError as exc:
        raise ApiError(409, "OWNER_PROTECTED", "The Owner account cannot be deleted") from exc
    # No router audit row (M1 fix): the service writes the ONE row
    # (staff.deleted, correct before).
    return ActionResultResponse(id=user_id, status="deleted")


@router.post("/users/{user_id}/role", response_model=StaffUserResponse)
def change_role(
    user_id: UUID,
    body: RoleChangeRequest,
    staff: StaffUser = Depends(get_current_staff),
) -> StaffUserResponse:
    require_staff(staff, "admin.users.role")
    role = body.validated_role()
    # Self-demotion refusal: the Owner may never change their own role
    # (demoting the last Owner would break the exactly-one-Owner
    # invariant). The service's OwnerProtectedError is the backstop.
    if user_id == staff.id:
        raise ApiError(409, "SELF_ACTION_NOT_ALLOWED", "The Owner cannot change their own role")
    try:
        updated = staff_service.re_role_staff(staff.account, user_id, role)
    except StaffNotOwnerError as exc:
        raise ApiError(403, "FORBIDDEN", "Only the Owner can re-role staff") from exc
    except StaffNotFoundError as exc:
        raise ApiError(404, "NOT_FOUND", "Resource not found") from exc
    except OwnerProtectedError as exc:
        raise ApiError(409, "OWNER_PROTECTED", "The Owner account cannot be re-roled") from exc
    except DuplicateOwnerError as exc:
        raise ApiError(409, "SECOND_OWNER", "The platform has exactly one Owner") from exc
    # No router audit row (M1 fix): the service writes the ONE row
    # (staff.role_changed, correct before/after).
    return StaffUserResponse.from_row(updated)


@router.post("/users/{user_id}/revoke-sessions", response_model=SessionsRevokedResponse)
def revoke_sessions(
    user_id: UUID,
    staff: StaffUser = Depends(get_current_staff),
) -> SessionsRevokedResponse:
    require_staff(staff, "admin.users.revoke_sessions")
    try:
        count = staff_service.revoke_staff_sessions(staff.account, user_id)
    except StaffNotOwnerError as exc:
        raise ApiError(403, "FORBIDDEN", "Only the Owner can revoke sessions") from exc
    except StaffNotFoundError as exc:
        raise ApiError(404, "NOT_FOUND", "Resource not found") from exc
    # No router audit row (M1 fix): the service writes the ONE row
    # (staff.sessions_revoked).
    return SessionsRevokedResponse(user_id=user_id, sessions_revoked=count)


@router.post("/users/{user_id}/force-reset", response_model=ActionResultResponse)
def force_reset(
    user_id: UUID,
    staff: StaffUser = Depends(get_current_staff),
) -> ActionResultResponse:
    require_staff(staff, "admin.users.force_reset")
    try:
        staff_service.force_password_reset(staff.account, user_id)
    except StaffNotOwnerError as exc:
        raise ApiError(403, "FORBIDDEN", "Only the Owner can force a password reset") from exc
    except StaffNotFoundError as exc:
        raise ApiError(404, "NOT_FOUND", "Resource not found") from exc
    # Provider failures (503 unconfigured / 502 upstream) propagate:
    # the Owner must see that the reset email did NOT go out.
    # No router audit row (M1 fix): the service writes the ONE row
    # (staff.force_reset).
    return ActionResultResponse(id=user_id, status="password_reset_requested")


@router.post("/users/{user_id}/mfa-re-enroll", response_model=StaffUserResponse)
def mfa_re_enroll(
    user_id: UUID,
    staff: StaffUser = Depends(get_current_staff),
) -> StaffUserResponse:
    require_staff(staff, "admin.users.mfa_re_enroll")
    try:
        updated = staff_service.mfa_re_enroll_staff(staff.account, user_id)
    except StaffNotOwnerError as exc:
        raise ApiError(403, "FORBIDDEN", "Only the Owner can re-enroll MFA") from exc
    except StaffNotFoundError as exc:
        raise ApiError(404, "NOT_FOUND", "Resource not found") from exc
    # No router audit row (M1 fix): the service writes the ONE row
    # (staff.mfa_re_enroll, correct before/after).
    return StaffUserResponse.from_row(updated)
