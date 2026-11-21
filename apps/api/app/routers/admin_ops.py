"""Admin operations API — ``/admin`` (Child D, admin-foundation build).

Ops screens: scans + queue, billing, abuse, support, security, system
audit, settings, Founder. Shared staff auth / central ``can()`` /
audit helpers live in ``app.routers.admin``; see that module's
docstring for the honest gaps (cross-tenant list methods and the
settings store have not landed yet).

Prefix rotation (``POST /admin/settings/rotate-prefix``) bumps the
real version counter in ``app.core.staff_prefix``; staff sessions
stamped with an older version are dead (Child B's SessionManager
enforces it on validate). The Founder gate reads the step-up state
from the caller's OWN session (``app.routers.admin``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.auth.sessions import get_session_manager
from app.core.config import settings
from app.core.errors import ApiError
from app.core.staff_prefix import bump_prefix_version, get_prefix_version
from app.db.store import Store
from app.routers.admin import (
    QUEUE_NAMES,
    ConfirmRequest,
    StaffUser,
    _all_rows,
    _audit,
    _field,
    _list_page,
    _optional_method,
    get_current_staff,
    require_staff,
)
from app.routers.deps import get_store_dep
from app.routers.scans import ScanListResponse, ScanResponse
from app.services import staff as staff_service
from app.workers.redis_client import get_redis_client

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_step_up(staff: StaffUser) -> None:
    """Founder gate: when the STAFF_STEP_UP_MFA flag is on (the plan's
    default, now a real config key), the session needs a fresh MFA
    check (Child B's ``POST /staff/auth/step-up/verify`` marks it)."""
    if settings.staff_step_up_mfa and not staff.step_up_verified:
        raise ApiError(
            403,
            "STEP_UP_REQUIRED",
            "Opening the Founder screen requires a fresh MFA check",
        )


def _queue_depths() -> dict[str, Any]:
    """Real Celery queue depths + DLQ counts from Redis (the broker).

    Celery's Redis broker stores each queue as a list named after the
    queue; DLQ entries live under ``dlq:scan:<scan_id>`` lists (see
    ``app.workers.dlq``). A broker that cannot be reached reports every
    depth as null with status "unavailable" — never an invented 0.
    """
    queues: list[dict[str, Any]] = []
    try:
        client = get_redis_client()
        for name in QUEUE_NAMES:
            try:
                # redis-py's stubs type llen as Awaitable[int] | int
                # (one stub serves the sync + async clients); this
                # client is sync, so the result is an int.
                depth = cast(int, client.llen(name))
            except Exception:  # noqa: BLE001 - one bad queue must not hide the rest
                depth = None
            queues.append(
                {
                    "name": name,
                    "depth": depth,
                    "status": "ok" if depth is not None else "unavailable",
                }
            )
        try:
            dlq_keys = list(client.scan_iter(match="dlq:scan:*"))
            dlq_entries = sum(cast(int, client.llen(key)) for key in dlq_keys)
            dlq: dict[str, Any] = {
                "scan_keys": len(dlq_keys),
                "entries": dlq_entries,
                "status": "ok",
            }
        except Exception:  # noqa: BLE001 - DLQ read failure is reported, not fatal
            dlq = {"scan_keys": None, "entries": None, "status": "unavailable"}
        broker_reachable = any(q["depth"] is not None for q in queues) or dlq["status"] == "ok"
    except Exception:  # noqa: BLE001 - an unreachable broker is a status, not a 500
        queues = [{"name": name, "depth": None, "status": "unavailable"} for name in QUEUE_NAMES]
        dlq = {"scan_keys": None, "entries": None, "status": "unavailable"}
        broker_reachable = False
    return {"queues": queues, "dlq": dlq, "broker_reachable": broker_reachable}


def _list_audit_page(
    store: Store, cursor: str | None, limit: int, **filters: Any
) -> tuple[list[Any], str | None]:
    """Call the protocol's ``list_audit_logs`` (keyword-only filters,
    Child A). 503 when no implementation exists yet; 422 on a
    malformed cursor."""
    method = _optional_method(store, "list_audit_logs")
    try:
        items, next_cursor = method(cursor=cursor, limit=limit, **filters)
    except ValueError as exc:
        raise ApiError(422, "VALIDATION_ERROR", "Invalid cursor") from exc
    return items, next_cursor


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class QueueDepth(BaseModel):
    name: str
    depth: int | None
    status: str


class DlqSummary(BaseModel):
    scan_keys: int | None
    entries: int | None
    status: str


class QueueResponse(BaseModel):
    queues: list[QueueDepth]
    dlq: DlqSummary
    broker_reachable: bool


class BillingSummaryResponse(BaseModel):
    total_subscriptions: int
    active_subscriptions: int
    by_plan: dict[str, int]
    by_status: dict[str, int]


class AbuseReportResponse(BaseModel):
    id: UUID
    user_id: UUID | None = None
    subject: str
    status: str
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: Any) -> AbuseReportResponse:
        user_id = _field(row, "user_id")
        return cls(
            id=UUID(str(_field(row, "id"))),
            user_id=UUID(str(user_id)) if user_id is not None else None,
            subject=str(_field(row, "subject", "")),
            status=str(_field(row, "status", "open")),
            created_at=_field(row, "created_at"),
        )


class AbuseListResponse(BaseModel):
    data: list[AbuseReportResponse]
    next_cursor: str | None
    has_more: bool


class TicketResponse(BaseModel):
    id: UUID
    user_id: UUID
    subject: str
    status: str
    priority: str
    scan_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @classmethod
    def from_row(cls, row: Any) -> TicketResponse:
        scan_id = _field(row, "scan_id")
        return cls(
            id=UUID(str(_field(row, "id"))),
            user_id=UUID(str(_field(row, "user_id"))),
            subject=str(_field(row, "subject", "")),
            status=str(_field(row, "status", "open")),
            priority=str(_field(row, "priority", "medium")),
            scan_id=UUID(str(scan_id)) if scan_id is not None else None,
            created_at=_field(row, "created_at"),
            updated_at=_field(row, "updated_at"),
        )


class TicketListResponse(BaseModel):
    data: list[TicketResponse]
    next_cursor: str | None
    has_more: bool


class LoginEventResponse(BaseModel):
    id: UUID
    user_id: UUID
    action: str
    created_at: datetime | None = None
    metadata: dict[str, Any] = {}


class StaffSessionResponse(BaseModel):
    id: UUID
    user_id: UUID
    issued_at: datetime | None = None
    last_seen_at: datetime | None = None
    ip: str | None = None
    prefix_version: int | None = None
    revoked_at: datetime | None = None

    @classmethod
    def from_row(cls, row: Any) -> StaffSessionResponse:
        return cls(
            id=UUID(str(_field(row, "id"))),
            user_id=UUID(str(_field(row, "user_id"))),
            issued_at=_field(row, "issued_at"),
            last_seen_at=_field(row, "last_seen_at"),
            ip=_field(row, "ip"),
            prefix_version=_field(row, "prefix_version"),
            revoked_at=_field(row, "revoked_at"),
        )


class SecurityResponse(BaseModel):
    login_events: list[LoginEventResponse]
    active_sessions: list[StaffSessionResponse]
    sessions_available: bool
    # No API-key feature exists in Week 1/2: empty is factual, not a
    # placeholder, and the flag says so.
    api_keys: list[dict[str, Any]] = []
    api_keys_available: bool = False


class AuditEntryResponse(BaseModel):
    id: UUID
    user_id: UUID
    action: str
    target_domain: str | None = None
    metadata: dict[str, Any] = {}
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: Any) -> AuditEntryResponse:
        return cls(
            id=UUID(str(_field(row, "id"))),
            user_id=UUID(str(_field(row, "user_id"))),
            action=str(_field(row, "action", "")),
            target_domain=_field(row, "target_domain"),
            metadata=dict(_field(row, "metadata") or {}),
            created_at=_field(row, "created_at"),
        )


class AuditListResponse(BaseModel):
    data: list[AuditEntryResponse]
    next_cursor: str | None
    has_more: bool


class SettingsUpdateRequest(BaseModel):
    staff_step_up_mfa: bool | None = None
    max_scans_free_per_month: int | None = Field(default=None, ge=0, le=1000)
    max_targets_free: int | None = Field(default=None, ge=0, le=100)


class SettingsResponse(BaseModel):
    flags: dict[str, Any]
    quotas: dict[str, Any]
    staff_prefix_version: int | None
    staff_prefix_version_available: bool


class FounderResponse(BaseModel):
    total_subscriptions: int | None
    active_subscriptions: int | None
    subscriptions_available: bool
    by_plan: dict[str, int]
    by_status: dict[str, int]
    total_scans: int | None
    scans_available: bool
    total_staff: int
    # Runway, goals, decision journal and cohorts have no data source
    # yet (Weeks 3-4 billing/product data) — they are omitted, not faked.
    business_figures_note: str = (
        "Subscription and scan figures only; runway, cohorts, goals and "
        "decision journal have no data source yet."
    )


class PrefixRotatedResponse(BaseModel):
    prefix_version: int
    staff_sessions_invalidated: bool = True
    # Sessions explicitly revoked in the DB at rotation time (C3
    # fix) — the version bump alone would also kill them on next
    # validate, but revocation is the auditable, immediate kill.
    sessions_revoked: int = 0
    # Honest note (carried from the live-proof handoff): rotation
    # bumps the persisted VERSION, which is what kills sessions. The
    # URL path string itself changes only via a new STAFF_URL_PREFIX
    # env value + API restart — the old path stops working only
    # after that restart.
    prefix_path_note: str = (
        "Rotation bumps the persisted prefix version and revokes all "
        "live staff sessions. The URL path string itself changes only "
        "by setting a new STAFF_URL_PREFIX value and restarting the API."
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


@router.get("/scans", response_model=ScanListResponse)
def list_all_scans(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    staff: StaffUser = Depends(get_current_staff),
    store: Store = Depends(get_store_dep),
) -> ScanListResponse:
    require_staff(staff, "admin.scans.read")
    items, next_cursor = _list_page(store, "list_all_scans", cursor, limit)
    return ScanListResponse(
        data=[ScanResponse.from_scan(scan) for scan in items],
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/scans/queue", response_model=QueueResponse)
def get_queue(
    staff: StaffUser = Depends(get_current_staff),
) -> QueueResponse:
    require_staff(staff, "admin.scans.queue.read")
    return QueueResponse(**_queue_depths())


@router.get("/billing", response_model=BillingSummaryResponse)
def get_billing(
    staff: StaffUser = Depends(get_current_staff),
    store: Store = Depends(get_store_dep),
) -> BillingSummaryResponse:
    require_staff(staff, "admin.billing.read")
    rows = _all_rows(store, "list_all_subscriptions")
    by_plan: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for row in rows:
        plan = str(_field(row, "plan", "free"))
        status = str(_field(row, "status", "active"))
        by_plan[plan] = by_plan.get(plan, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
    return BillingSummaryResponse(
        total_subscriptions=len(rows),
        active_subscriptions=by_status.get("active", 0),
        by_plan=by_plan,
        by_status=by_status,
    )


@router.get("/abuse", response_model=AbuseListResponse)
def list_abuse(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    staff: StaffUser = Depends(get_current_staff),
    store: Store = Depends(get_store_dep),
) -> AbuseListResponse:
    require_staff(staff, "admin.abuse.read")
    items, next_cursor = _list_page(store, "list_abuse_reports", cursor, limit)
    return AbuseListResponse(
        data=[AbuseReportResponse.from_row(row) for row in items],
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/support/tickets", response_model=TicketListResponse)
def list_tickets(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    staff: StaffUser = Depends(get_current_staff),
    store: Store = Depends(get_store_dep),
) -> TicketListResponse:
    require_staff(staff, "admin.support.read")
    items, next_cursor = _list_page(store, "list_all_support_tickets", cursor, limit)
    return TicketListResponse(
        data=[TicketResponse.from_row(row) for row in items],
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/security", response_model=SecurityResponse)
def get_security(
    staff: StaffUser = Depends(get_current_staff),
    store: Store = Depends(get_store_dep),
) -> SecurityResponse:
    require_staff(staff, "admin.security.read")
    items, _ = _list_audit_page(store, None, 50)
    login_events = [
        LoginEventResponse(
            id=UUID(str(_field(row, "id"))),
            user_id=UUID(str(_field(row, "user_id"))),
            action=str(_field(row, "action", "")),
            created_at=_field(row, "created_at"),
            metadata=dict(_field(row, "metadata") or {}),
        )
        for row in items
        # N4 fix: staff login events are staff.* (staff.login,
        # staff.mfa_verified, staff.logout, ...) — the old auth.*
        # filter matched only customer auth events, so this list was
        # always empty for staff.
        if str(_field(row, "action", "")).startswith(("auth.", "staff."))
    ]
    # Active sessions come from Child B's SessionManager (the real
    # session model), across every staff account.
    manager = get_session_manager()
    sessions: list[StaffSessionResponse] = []
    for account in staff_service.list_staff_accounts():
        sessions.extend(
            StaffSessionResponse.from_row(session)
            for session in manager.list_active_sessions(account.user_id)
        )
    sessions.sort(key=lambda s: s.last_seen_at or datetime.min, reverse=True)
    return SecurityResponse(
        login_events=login_events,
        active_sessions=sessions,
        sessions_available=True,
    )


@router.get("/system/audit", response_model=AuditListResponse)
def list_audit(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    actor: UUID | None = Query(default=None),
    action: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    search: str | None = Query(default=None),
    staff: StaffUser = Depends(get_current_staff),
    store: Store = Depends(get_store_dep),
) -> AuditListResponse:
    require_staff(staff, "admin.audit.read")
    items, next_cursor = _list_audit_page(
        store,
        cursor,
        limit,
        actor_id=actor,
        action=action,
        since=since,
        until=until,
        search=search,
    )
    return AuditListResponse(
        data=[AuditEntryResponse.from_row(row) for row in items],
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/settings", response_model=SettingsResponse)
def get_settings(
    staff: StaffUser = Depends(get_current_staff),
) -> SettingsResponse:
    require_staff(staff, "admin.settings.read")
    return SettingsResponse(
        flags={"staff_step_up_mfa": settings.staff_step_up_mfa},
        quotas={
            "max_scans_free_per_month": settings.max_scans_free_per_month,
            "max_targets_free": settings.max_targets_free,
            "staff_session_absolute_hours": settings.staff_session_absolute_hours,
            "staff_session_idle_minutes": settings.staff_session_idle_minutes,
        },
        staff_prefix_version=get_prefix_version(),
        staff_prefix_version_available=True,
    )


@router.post("/settings", response_model=SettingsResponse)
def update_settings(
    body: SettingsUpdateRequest,
    staff: StaffUser = Depends(get_current_staff),
) -> SettingsResponse:
    require_staff(staff, "admin.settings.write")
    # Blocked: flags/quotas have no persistence layer yet (Child B owns
    # the staff settings in config; no settings store exists). Validated
    # above, changed nowhere — a 200 claiming success would be fake.
    raise ApiError(
        503,
        "SETTINGS_STORE_UNAVAILABLE",
        "Settings have no persistence layer yet (Child B), so nothing was changed.",
    )


@router.post("/settings/rotate-prefix", response_model=PrefixRotatedResponse)
def rotate_prefix(
    body: ConfirmRequest,
    staff: StaffUser = Depends(get_current_staff),
) -> PrefixRotatedResponse:
    require_staff(staff, "admin.settings.rotate_prefix")
    if not body.confirm:
        raise ApiError(
            422,
            "VALIDATION_ERROR",
            "Rotating the staff prefix requires confirm=true (two-step confirm)",
        )
    # C3 fix: the version bump is PERSISTED (admin_settings table),
    # so a restart cannot resurrect rotated-out sessions — and every
    # live staff session is ALSO explicitly revoked in the DB at
    # rotation time (belt and braces: the version check kills them
    # on next validate even if a revoke row is missed).
    version = bump_prefix_version()
    # F6 fix (red-team, 20 Nov 2026): this used
    # ``app.auth.sessions.get_session_manager()`` — the DEFAULT
    # store — while login/logout/suspend all revoke through
    # ``app.services.staff.get_staff_session_manager()``
    # (override-aware). Whenever the store is overridden, the
    # explicit revoke silently ran against the wrong store
    # (sessions_revoked: 0, rows unrevoked) and only the version
    # check killed the sessions. One wiring point now.
    manager = staff_service.get_staff_session_manager()
    sessions_revoked = 0
    for account in staff_service.list_staff_accounts():
        sessions_revoked += manager.revoke_all_for_user(account.user_id)
    _audit(
        staff,
        "admin.settings.rotate_prefix",
        after={"prefix_version": version, "sessions_revoked": sessions_revoked},
    )
    return PrefixRotatedResponse(prefix_version=version, sessions_revoked=sessions_revoked)


@router.get("/founder", response_model=FounderResponse)
def get_founder(
    staff: StaffUser = Depends(get_current_staff),
    store: Store = Depends(get_store_dep),
) -> FounderResponse:
    require_staff(staff, "admin.founder.read")
    _require_step_up(staff)
    total_staff = len(staff_service.list_staff_accounts())
    subscriptions_available = True
    by_plan: dict[str, int] = {}
    by_status: dict[str, int] = {}
    total_subscriptions: int | None = None
    active_subscriptions: int | None = None
    try:
        rows = _all_rows(store, "list_all_subscriptions")
        for row in rows:
            plan = str(_field(row, "plan", "free"))
            status = str(_field(row, "status", "active"))
            by_plan[plan] = by_plan.get(plan, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
        total_subscriptions = len(rows)
        active_subscriptions = by_status.get("active", 0)
    except ApiError as exc:
        if exc.code != "STAFF_DATA_UNAVAILABLE":
            raise
        subscriptions_available = False
    total_scans: int | None = None
    scans_available = True
    try:
        total_scans = _optional_method(store, "count_all_scans")()
    except ApiError as exc:
        if exc.code != "STAFF_DATA_UNAVAILABLE":
            raise
        scans_available = False
    return FounderResponse(
        total_subscriptions=total_subscriptions,
        active_subscriptions=active_subscriptions,
        subscriptions_available=subscriptions_available,
        by_plan=by_plan,
        by_status=by_status,
        total_scans=total_scans,
        scans_available=scans_available,
        total_staff=total_staff,
    )
