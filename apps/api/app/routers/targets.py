"""Targets endpoints — ``/api/v1/targets``.

Every handler: authenticate (``get_current_user`` -> 401 when absent) ->
load tenant-scoped -> ``can()`` (False -> 404) -> business logic. The raw
verification token is returned ONCE, at creation, and never again; only
its SHA-256 hash is stored.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from app.core.config import settings
from app.core.errors import ApiError, ErrorResponse
from app.db.store import DuplicateTargetError, Store, Target, TargetCapError
from app.routers.deps import (
    User,
    can,
    get_current_user,
    get_store_dep,
    require_resource,
)
from app.services import verification

router = APIRouter(prefix="/api/v1/targets", tags=["targets"])

# Hostname: labels of 1-63 alphanumerics/hyphens, not starting/ending with
# a hyphen, total <= 253 chars, at least one dot (a bare label such as
# "localhost" is not a registrable domain and is rejected here — it is
# also SSRF-blocked downstream). No scheme, userinfo, or port: a target
# is a domain, not a URL (docs/api-conventions.md §3).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_domain(value: str) -> str:
    """Normalize + validate a domain. Returns the lowercase, dot-stripped
    form. Raises ValueError (mapped to 422 by the Pydantic validator)."""
    normalized = value.strip().lower().rstrip(".")
    if not _HOSTNAME_RE.match(normalized):
        raise ValueError(
            "domain must be a valid hostname (e.g. example.com): no scheme, userinfo, port, or path"
        )
    return normalized


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TargetCreateRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        return validate_domain(value)


class TargetVerifyRequest(BaseModel):
    method: Literal["dns", "file"]


class VerificationInstructions(BaseModel):
    dns_txt_name: str
    dns_txt_record: str
    file_url: str
    file_content: str


class TargetResponse(BaseModel):
    id: UUID
    user_id: UUID
    domain: str
    verification_status: str
    verification_method: str | None
    verified_at: datetime | None
    created_at: datetime | None
    updated_at: datetime | None

    @classmethod
    def from_target(cls, target: Target) -> TargetResponse:
        return cls(
            id=target.id,
            user_id=target.user_id,
            domain=target.domain,
            verification_status=target.verification_status,
            verification_method=target.verification_method,
            verified_at=target.verified_at,
            created_at=target.created_at,
            updated_at=target.updated_at,
        )


class TargetCreateResponse(TargetResponse):
    # Raw token + instructions: present ONLY on this response, once.
    verification_token: str
    verification_instructions: VerificationInstructions


class TargetListResponse(BaseModel):
    data: list[TargetResponse]
    next_cursor: str | None
    has_more: bool


class VerifyChecked(BaseModel):
    method: str
    record_found: bool


class TargetVerifyResponse(BaseModel):
    id: UUID
    domain: str
    verification_status: str
    verification_method: str | None
    verified_at: datetime | None
    checked: VerifyChecked


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _quota_exceeded_response() -> JSONResponse:
    """429 for the Free 1-domain cap (shared by the router's count check
    and the TargetCapError backstop from the DB index)."""
    return JSONResponse(
        status_code=429,
        content=ErrorResponse(
            code="QUOTA_EXCEEDED",
            message="Free plan allows 1 domain",
            details={"limit": settings.max_targets_free, "period": "account"},
        ).model_dump(),
        headers={"Retry-After": "3600"},
    )


@router.post("/", status_code=201, response_model=TargetCreateResponse)
def create_target(
    body: TargetCreateRequest,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> TargetCreateResponse | JSONResponse:
    # Collection-level action: can() with resource None (owner may create).
    if not can(user, "target.create", None):
        raise ApiError(404, "NOT_FOUND", "Resource not found")
    domain = validate_domain(body.domain)
    # Duplicate first: a domain the user already has is 409, not 429.
    if store.get_target_by_domain(user.id, domain) is not None:
        raise ApiError(
            409,
            "TARGET_ALREADY_EXISTS",
            "A target for this domain already exists",
            details={"domain": domain},
        )
    # Free cap: 1 domain (M3 review fix — the dashboard's "Free plan:
    # 1 domain" was unenforced; unlimited targets meant unlimited token
    # generation + rows per user).
    if store.count_targets(user.id) >= settings.max_targets_free:
        return _quota_exceeded_response()
    token = verification.generate_verification_token()
    try:
        target = store.create_target(user.id, domain, verification.hash_token(token))
    except DuplicateTargetError as exc:
        # Race with a concurrent create of the same domain.
        raise ApiError(
            409,
            "TARGET_ALREADY_EXISTS",
            "A target for this domain already exists",
            details={"domain": domain},
        ) from exc
    except TargetCapError:
        # Race with a concurrent create of a DIFFERENT domain: the
        # router's count check passed for both, the DB index caught the
        # second. Same 429 as the count check (round-2 review, Blocker 2).
        return _quota_exceeded_response()
    store.log_audit(user.id, "target.create", target.domain, {})
    instructions = VerificationInstructions(
        dns_txt_name=target.domain,
        dns_txt_record=f"{verification.DNS_TXT_PREFIX}{token}",
        file_url=f"https://{target.domain}{verification.WELL_KNOWN_PATH}",
        file_content=token,
    )
    base = TargetResponse.from_target(target)
    return TargetCreateResponse(
        **base.model_dump(),
        verification_token=token,
        verification_instructions=instructions,
    )


@router.get("/", response_model=TargetListResponse)
def list_targets(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> TargetListResponse:
    if not can(user, "target.list", None):
        raise ApiError(404, "NOT_FOUND", "Resource not found")
    try:
        items, next_cursor = store.list_targets(user.id, cursor, limit)
    except ValueError as exc:
        raise ApiError(422, "VALIDATION_ERROR", "Invalid cursor") from exc
    return TargetListResponse(
        data=[TargetResponse.from_target(t) for t in items],
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: UUID,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> TargetResponse:
    target = require_resource(
        user,
        "target.read",
        store.get_target(user.id, target_id),
        store=store,
        resource_id=target_id,
    )
    return TargetResponse.from_target(target)


@router.post("/{target_id}/verify", response_model=TargetVerifyResponse)
def verify_target(
    target_id: UUID,
    body: TargetVerifyRequest,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> TargetVerifyResponse:
    target = require_resource(
        user,
        "target.verify",
        store.get_target(user.id, target_id),
        store=store,
        resource_id=target_id,
    )
    if target.verification_status == "verified":
        return TargetVerifyResponse(
            id=target.id,
            domain=target.domain,
            verification_status="verified",
            verification_method=target.verification_method,
            verified_at=target.verified_at,
            checked=VerifyChecked(method=body.method, record_found=True),
        )
    # Token expiry: the store sets verification_expires_at to creation +
    # 7 days (settings.verification_token_ttl_days). Past that instant the
    # token is dead — the user creates a new target for a fresh token.
    if (
        target.verification_expires_at is not None
        and datetime.now(timezone.utc) > target.verification_expires_at
    ):
        raise ApiError(
            410,
            "VERIFICATION_EXPIRED",
            "The verification token has expired. Create a new target to get a fresh token.",
            details={"target_id": str(target.id)},
        )
    matched, published = verification.check_verification_hash(
        target.domain, target.verification_token_hash, body.method
    )
    if matched:
        updated = store.update_target_verification(
            user.id,
            target.id,
            status="verified",
            method=body.method,
            verified_at=datetime.now(timezone.utc),
        )
        if updated is None:
            # The target was deleted concurrently — a 404, not a 500
            # (L10 review fix: asserts race under concurrent delete).
            raise ApiError(404, "NOT_FOUND", "Resource not found")
        store.log_audit(user.id, "target.verify", target.domain, {"method": body.method})
        return TargetVerifyResponse(
            id=updated.id,
            domain=updated.domain,
            verification_status="verified",
            verification_method=updated.verification_method,
            verified_at=updated.verified_at,
            checked=VerifyChecked(method=body.method, record_found=True),
        )
    # Failure: 200 with status + what was checked. The expected token
    # value is NEVER echoed back.
    return TargetVerifyResponse(
        id=target.id,
        domain=target.domain,
        verification_status=target.verification_status,
        verification_method=target.verification_method,
        verified_at=target.verified_at,
        checked=VerifyChecked(method=body.method, record_found=published),
    )


@router.delete("/{target_id}", status_code=204)
def delete_target(
    target_id: UUID,
    user: User = Depends(get_current_user),
    store: Store = Depends(get_store_dep),
) -> None:
    target = require_resource(
        user,
        "target.delete",
        store.get_target(user.id, target_id),
        store=store,
        resource_id=target_id,
    )
    store.delete_target(user.id, target.id)
    store.log_audit(user.id, "target.delete", target.domain, {})
    return None
