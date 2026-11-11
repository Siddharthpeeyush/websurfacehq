"""Scans endpoints — ``/api/v1/scans``.

Week 1 scope: a scan is created as ``status='queued'`` and STAYS queued.
No dispatch/enqueue happens here — the Celery dispatch wiring lands with
Builder D's worker tasks, and the coordinator owns the integration. The
API shape is kept clean (the scan object, no fake queue fields) and the
gap is recorded in the Builder C report, not papered over in the response.

Quota (owner-locked 11 Nov 2026): Free = 3 scans/month, max 1 active scan.
Both breaches answer 429 QUOTA_EXCEEDED.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.errors import ApiError, ErrorResponse
from app.core.logging import logger
from app.db.store import Scan, ScanConflictError, Store, hash_resource_id
from app.routers.deps import (
    User,
    can,
    get_current_user,
    get_store_dep,
    require_resource,
)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ScanConfigRequest(BaseModel):
    depth: Literal["quick", "standard", "deep"] = "standard"
    max_urls: int = Field(default=500, ge=1, le=500)


class ScanCreateRequest(BaseModel):
    target_id: UUID
    config: ScanConfigRequest = ScanConfigRequest()


class ScanResponse(BaseModel):
    id: UUID
    user_id: UUID
    target_id: UUID
    status: str
    config: dict[str, object]
    progress: int
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime | None
    updated_at: datetime | None

    @classmethod
    def from_scan(cls, scan: Scan) -> ScanResponse:
        return cls(
            id=scan.id,
            user_id=scan.user_id,
            target_id=scan.target_id,
            status=scan.status,
            config=dict(scan.config),
            progress=scan.progress,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            error=scan.error,
            created_at=scan.created_at,
            updated_at=scan.updated_at,
        )


class ScanListResponse(BaseModel):
    data: list[ScanResponse]
    next_cursor: str | None
    has_more: bool


class ScanProgressResponse(BaseModel):
    scan_id: UUID
    status: str
    progress: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _retry_after_until_month_end() -> str:
    """Seconds until the next UTC month boundary (for the Retry-After
    header on monthly-quota 429s)."""
    now = datetime.now(timezone.utc)
    if now.month == 12:
        nxt = now.replace(year=now.year + 1, month=1, day=1)
    else:
        nxt = now.replace(month=now.month + 1, day=1)
    nxt = nxt.replace(hour=0, minute=0, second=0, microsecond=0)
    return str(int((nxt - now).total_seconds()))


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


@router.post("/", status_code=202, response_model=ScanResponse)
def create_scan(
    body: ScanCreateRequest,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> ScanResponse | JSONResponse:
    # Tenant check FIRST: another tenant's target is 404 even if it is
    # also unverified — never leak state across tenants.
    target = require_resource(
        user,
        "target.read",
        store.get_target(user.id, body.target_id),
        store=store,
        resource_id=body.target_id,
    )
    # The state precondition lives in can() (L16 review fix): can() is the
    # single source of truth for "may this user create a scan on this
    # target" — the handler maps its denial to 409 TARGET_NOT_VERIFIED
    # (tenancy was already proven by require_resource above, so a False
    # here can only be the unverified state, never another tenant).
    if not can(user, "scan.create", target):
        raise ApiError(
            409,
            "TARGET_NOT_VERIFIED",
            "This target has not been verified yet. Complete DNS or file "
            "verification before creating a scan.",
            details={
                "target_id": str(target.id),
                "verification_status": target.verification_status,
            },
        )
    # Quotas: monthly count, then the 1-active-scan cap. NOTE: these
    # return a JSONResponse directly instead of raising ApiError, because
    # a 429 must carry a Retry-After header and headers set on the
    # injected Response object are lost when an exception is raised.
    if store.count_scans_this_month(user.id) >= settings.max_scans_free_per_month:
        return JSONResponse(
            status_code=429,
            content=ErrorResponse(
                code="QUOTA_EXCEEDED",
                message="Monthly scan quota reached for the Free plan",
                details={
                    "limit": settings.max_scans_free_per_month,
                    "period": "month",
                },
            ).model_dump(),
            headers={"Retry-After": _retry_after_until_month_end()},
        )
    if store.count_active_scans(user.id) >= 1:
        return JSONResponse(
            status_code=429,
            content=ErrorResponse(
                code="QUOTA_EXCEEDED",
                message="Only one active scan is allowed on the Free plan",
                details={"limit": 1, "period": "active"},
            ).model_dump(),
            # Advisory: re-check after a minute; the active scan may have
            # finished by then.
            headers={"Retry-After": "60"},
        )
    try:
        scan = store.create_scan(
            user.id,
            target.id,
            {"depth": body.config.depth, "max_urls": body.config.max_urls},
        )
    except ScanConflictError:
        # M4 review fix: the 1-active-scan cap is enforced atomically by
        # the DB partial unique index (migration 0004). A concurrent
        # request slipped past the count check above — the cap still held,
        # and the loser answers 429, not 409.
        # (The monthly 3/month cap has no DB-level equivalent yet — the
        # count-then-create race there is a known Week 1 limitation, to be
        # closed by an atomic counter in Week 4 with billing.)
        return JSONResponse(
            status_code=429,
            content=ErrorResponse(
                code="QUOTA_EXCEEDED",
                message="Only one active scan is allowed on the Free plan",
                details={"limit": 1, "period": "active"},
            ).model_dump(),
            headers={"Retry-After": "60"},
        )
    store.log_audit(
        user.id,
        "scan.create",
        target.domain,
        {
            "scan_id": hash_resource_id(scan.id),
            "target_id": hash_resource_id(target.id),
        },
    )
    # Dispatch the pipeline (Week 1: verify_target only — see
    # app/workers/dispatch.py). Best-effort: if the broker is unreachable
    # (no Redis in dev), the scan stays 'queued' and the dispatch is
    # retried by the operator — dispatch must never fail scan creation.
    # Imported here so importing the router never opens a broker connection.
    try:
        from app.workers.dispatch import dispatch_scan

        dispatch_scan(str(scan.id), str(user.id))
    except Exception:  # noqa: BLE001 - dispatch failure leaves scan queued
        logger.warning(
            "scan dispatch deferred: broker unreachable",
            extra={"scan_id": str(scan.id)},
        )
    return ScanResponse.from_scan(scan)


@router.get("/", response_model=ScanListResponse)
def list_scans(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> ScanListResponse:
    if not can(user, "scan.list", None):
        raise ApiError(404, "NOT_FOUND", "Resource not found")
    try:
        items, next_cursor = store.list_scans(user.id, cursor, limit)
    except ValueError as exc:
        raise ApiError(422, "VALIDATION_ERROR", "Invalid cursor") from exc
    return ScanListResponse(
        data=[ScanResponse.from_scan(s) for s in items],
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> ScanResponse:
    scan = require_resource(
        user,
        "scan.read",
        store.get_scan(user.id, scan_id),
        store=store,
        resource_id=scan_id,
    )
    return ScanResponse.from_scan(scan)


@router.get("/{scan_id}/progress", response_model=ScanProgressResponse)
def get_scan_progress(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> ScanProgressResponse:
    scan = require_resource(
        user,
        "scan.read",
        store.get_scan(user.id, scan_id),
        store=store,
        resource_id=scan_id,
    )
    return ScanProgressResponse(scan_id=scan.id, status=scan.status, progress=scan.progress)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> ScanResponse:
    scan = require_resource(
        user,
        # "scan.read", not "scan.cancel": can("scan.cancel", terminal_scan)
        # is False by state, and this handler must answer 409 for a
        # terminal scan, not 404. Tenancy is checked here; the terminal
        # state is checked by store.cancel_scan below.
        "scan.read",
        store.get_scan(user.id, scan_id),
        store=store,
        resource_id=scan_id,
    )
    try:
        cancelled = store.cancel_scan(user.id, scan.id)
    except ScanConflictError as exc:
        raise ApiError(
            409,
            "SCAN_CONFLICT",
            f"Scan is already {scan.status} and cannot be cancelled",
            details={"scan_id": str(scan.id), "status": scan.status},
        ) from exc
    if cancelled is None:
        # The scan was deleted concurrently — a 404, not a 500
        # (L10 review fix: asserts race under concurrent delete).
        raise ApiError(404, "NOT_FOUND", "Resource not found")
    store.log_audit(user.id, "scan.cancel", None, {"scan_id": hash_resource_id(scan.id)})
    return ScanResponse.from_scan(cancelled)
