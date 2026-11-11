"""Findings endpoints — ``/api/v1/scans/{id}/findings`` and
``/api/v1/findings/{id}`` (+ feedback).

Feedback changes ONLY the finding's ``status`` (``confirmed`` |
``false_positive``); the ``ai_*`` triage fields are never touched by a
user verdict, and the feedback is audit-logged.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.core.errors import ApiError
from app.db.store import Finding, Store, hash_resource_id
from app.routers.deps import (
    User,
    get_current_user,
    get_store_dep,
    require_resource,
)

router = APIRouter(prefix="/api/v1", tags=["findings"])

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class FindingResponse(BaseModel):
    id: UUID
    user_id: UUID
    scan_id: UUID
    target_id: UUID
    template_id: str
    title: str
    severity: str
    cvss: float | None
    epss: float | None
    kev: bool
    cve: str | None
    url: str | None
    evidence: str | None
    ai_verdict: str | None
    ai_confidence: int | None
    ai_reason: str | None
    status: str
    created_at: datetime | None
    updated_at: datetime | None

    @classmethod
    def from_finding(cls, finding: Finding) -> FindingResponse:
        return cls(
            id=finding.id,
            user_id=finding.user_id,
            scan_id=finding.scan_id,
            target_id=finding.target_id,
            template_id=finding.template_id,
            title=finding.title,
            severity=finding.severity,
            cvss=finding.cvss,
            epss=finding.epss,
            kev=finding.kev,
            cve=finding.cve,
            url=finding.url,
            evidence=finding.evidence,
            ai_verdict=finding.ai_verdict,
            ai_confidence=finding.ai_confidence,
            ai_reason=finding.ai_reason,
            status=finding.status,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
        )


class FindingListResponse(BaseModel):
    data: list[FindingResponse]
    next_cursor: str | None
    has_more: bool


class FindingFeedbackRequest(BaseModel):
    verdict: Literal["confirmed", "false_positive"]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


@router.get("/scans/{scan_id}/findings", response_model=FindingListResponse)
def list_findings(
    scan_id: UUID,
    severity: Literal["critical", "high", "medium", "low", "info"] | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> FindingListResponse:
    # Tenant check on the scan first: another tenant's scan id -> 404,
    # never their findings. "scan.read" (no state precondition) is the
    # tenancy check; "finding.list" is a collection action and must not
    # be called with a resource.
    scan = require_resource(
        user,
        "scan.read",
        store.get_scan(user.id, scan_id),
        store=store,
        resource_id=scan_id,
    )
    try:
        items, next_cursor = store.list_findings(user.id, scan.id, cursor, limit, severity=severity)
    except ValueError as exc:
        raise ApiError(422, "VALIDATION_ERROR", "Invalid cursor") from exc
    return FindingListResponse(
        data=[FindingResponse.from_finding(f) for f in items],
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: UUID,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> FindingResponse:
    finding = require_resource(
        user,
        "finding.read",
        store.get_finding(user.id, finding_id),
        store=store,
        resource_id=finding_id,
    )
    return FindingResponse.from_finding(finding)


@router.post("/findings/{finding_id}/feedback", response_model=FindingResponse)
def submit_finding_feedback(
    finding_id: UUID,
    body: FindingFeedbackRequest,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> FindingResponse:
    finding = require_resource(
        user,
        "finding.feedback",
        store.get_finding(user.id, finding_id),
        store=store,
        resource_id=finding_id,
    )
    updated = store.update_finding_feedback(user.id, finding.id, body.verdict)
    if updated is None:
        # The finding was deleted concurrently — a 404, not a 500
        # (L10 review fix: asserts race under concurrent delete).
        raise ApiError(404, "NOT_FOUND", "Resource not found")
    store.log_audit(
        user.id,
        "finding.feedback",
        None,
        {"finding_id": hash_resource_id(finding.id), "verdict": body.verdict},
    )
    return FindingResponse.from_finding(updated)
