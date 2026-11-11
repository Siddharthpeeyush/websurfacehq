"""The ``Store`` protocol — the single data-access interface for the API.

Every data access in the API goes through this protocol: Builder B's auth
code and Builder D's worker code program against these exact method names —
do not rename them after this file lands. Two implementations exist:

- :class:`app.db.memory.InMemoryStore` — used by all tests and by dev when
  Supabase is not configured.
- :class:`app.db.supabase_store.SupabaseStore` — Postgres via supabase-py
  with the service-role key (server-side only).

Tenancy rule (non-negotiable, per docs/permissions.md): EVERY method takes
``user_id`` and never returns another tenant's rows. A cross-tenant lookup
returns ``None`` (single-get) or an empty page (list) — never an error that
reveals the row exists, and never the row itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable
from uuid import UUID


def hash_resource_id(resource_id: UUID | str) -> str:
    """SHA-256 hex of a resource id, for audit-log metadata (never the raw
    id — see AuditLog). Used by routers when they log an id."""
    return hashlib.sha256(str(resource_id).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Row shapes (dataclasses, not Pydantic: the store layer has no HTTP shape)
# ---------------------------------------------------------------------------


@dataclass
class Target:
    """A domain a user wants to scan. Verification token is stored as a
    SHA-256 hex hash only — the raw token is returned once at creation and
    never stored (see app.services.verification)."""

    id: UUID
    user_id: UUID
    domain: str
    verification_token_hash: str
    verification_method: str | None = None
    verification_status: str = "pending"  # pending | verified
    # Expiry instant for the verification token (schema column
    # verification_expires_at; set to creation + 7 days by the store).
    # The router answers 410 VERIFICATION_EXPIRED past this instant.
    verification_expires_at: datetime | None = None
    verified_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    deleted_at: datetime | None = None


@dataclass
class Scan:
    """One scan run against a target. ``status`` is one of
    queued | recon | crawling | scanning | triaging | done | failed |
    cancelled. ``config`` is ``{depth: quick|standard|deep, max_urls: int}``."""

    id: UUID
    user_id: UUID
    target_id: UUID
    status: str = "queued"
    config: dict[str, Any] = field(default_factory=dict)
    progress: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    # Set only by the SQL soft_delete_scan RPC helper (no delete_scan in
    # the Store protocol yet). list_scans filters on it (round-2 review).
    deleted_at: datetime | None = None


@dataclass
class Finding:
    """One vulnerability finding from a scan. ``ai_*`` fields are set by the
    triage service; user feedback changes ``status`` only, never ``ai_*``."""

    id: UUID
    user_id: UUID
    scan_id: UUID
    target_id: UUID
    template_id: str = ""
    title: str = ""
    severity: str = "info"  # critical | high | medium | low | info
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    cve: str | None = None
    url: str | None = None
    evidence: str | None = None
    ai_verdict: str | None = None
    ai_confidence: int | None = None
    ai_reason: str | None = None
    status: str = "new"  # new | confirmed | false_positive | fixed
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass
class Subscription:
    """Billing state for one user. Money is integer paise/cents elsewhere;
    the plan row itself carries no money in Week 1."""

    id: UUID
    user_id: UUID
    plan: str = "free"  # free | starter | pro | business
    status: str = "active"  # active | past_due | cancelled
    current_period_end: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass
class AuditLog:
    """Append-only audit row. ``metadata`` never contains secrets or tokens
    (resource ids are stored hashed, per docs/permissions.md §3.6)."""

    id: UUID
    user_id: UUID
    action: str
    target_domain: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None


@dataclass
class ScanJob:
    """One pipeline stage of one scan. ``idempotency_key`` is
    ``scan_id:stage:target_hash`` (blueprint §1.5) — re-running the same
    stage returns the stored row instead of duplicating work."""

    id: UUID
    user_id: UUID
    scan_id: UUID
    stage: str
    status: str = "queued"  # queued | running | done | failed
    attempt: int = 0
    celery_task_id: str | None = None
    idempotency_key: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    log: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


# ---------------------------------------------------------------------------
# Cursor pagination (opaque, base64 of sort key + id; created_at desc, id desc)
# ---------------------------------------------------------------------------


def encode_cursor(created_at: datetime, item_id: UUID) -> str:
    """Encode the sort key of the last item on a page as an opaque cursor."""
    payload = json.dumps(
        {"c": created_at.isoformat(), "i": str(item_id)}, separators=(",", ":")
    ).encode()
    return base64.urlsafe_b64encode(payload).decode()


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    """Decode a cursor. Raises ValueError on anything malformed — callers
    map that to 422 VALIDATION_ERROR."""
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return datetime.fromisoformat(str(payload["c"])), UUID(str(payload["i"]))
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"Invalid cursor: {cursor!r}") from exc


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DuplicateTargetError(ValueError):
    """Raised by create_target when (user_id, domain) already exists
    (among non-deleted targets). Routers map it to 409."""


class TargetCapError(ValueError):
    """Raised by create_target when the user already has their one live
    target (migration 0004 partial unique index
    ``targets_one_live_per_user``). The router maps it to 429
    QUOTA_EXCEEDED — it is the atomic backstop for the router's
    count-then-create check, which races under parallel requests
    (round-2 review, Blocker 2). Deliberately distinct from
    DuplicateTargetError: same-domain is 409, second-domain is 429."""


class ScanConflictError(ValueError):
    """Raised by cancel_scan when the scan is in a terminal state
    (done / failed / already cancelled). Routers map it to 409
    SCAN_CONFLICT."""


# ---------------------------------------------------------------------------
# The protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Store(Protocol):
    """Single data-access interface. All methods are tenant-scoped via
    ``user_id``; see the module docstring. List methods take
    ``(user_id, cursor, limit)`` and return ``(items, next_cursor)`` where
    ``next_cursor`` is ``None`` when there are no more pages."""

    # -- health ----------------------------------------------------------
    def ping(self) -> bool:
        """True when the store answers. Used by component_status()."""
        ...

    # -- targets ---------------------------------------------------------
    def create_target(self, user_id: UUID, domain: str, verification_token_hash: str) -> Target:
        """Create a target (status pending, token hash stored). May raise
        DuplicateTargetError (same domain) or TargetCapError (the user
        already has a live target): on the Supabase path the partial
        unique index targets_one_live_per_user (migration 0004) enforces
        the Free 1-domain cap atomically (a concurrent create hits it
        even when the router's count check passed first); the router maps
        the cap to 429 QUOTA_EXCEEDED. The in-memory store does NOT
        enforce the cap here — the router's count check is its
        enforcement (tests seed several targets per user directly
        through the store). Same asymmetry as create_scan (M4)."""

    def get_target(self, user_id: UUID, target_id: UUID) -> Target | None: ...

    def get_target_by_domain(self, user_id: UUID, domain: str) -> Target | None:
        """The user's (non-deleted) target for a domain, or None. Used by
        the create handler to answer 409 for a duplicate BEFORE the
        target-count cap check (a duplicate is 409, not 429)."""
        ...

    def count_targets(self, user_id: UUID) -> int:
        """Number of the user's non-deleted targets (Free cap: 1 domain)."""
        ...

    def list_targets(
        self, user_id: UUID, cursor: str | None, limit: int
    ) -> tuple[list[Target], str | None]: ...

    def delete_target(self, user_id: UUID, target_id: UUID) -> bool:
        """Soft delete (sets deleted_at). False if not found / not yours."""
        ...

    def update_target_verification(
        self,
        user_id: UUID,
        target_id: UUID,
        *,
        status: str,
        method: str | None = None,
        verified_at: datetime | None = None,
    ) -> Target | None: ...

    # -- scans -----------------------------------------------------------
    def create_scan(self, user_id: UUID, target_id: UUID, config: dict[str, Any]) -> Scan:
        """Create a queued scan. May raise ScanConflictError when the user
        already has an active scan: on the Supabase path the partial unique
        index scans_one_active_per_user (migration 0004) enforces the
        1-active-scan cap atomically (a concurrent create hits it even
        when the router's count check passed first); the router maps that
        conflict to 429 QUOTA_EXCEEDED. The in-memory store does NOT
        enforce the cap here — the router's count check is its enforcement
        (tests seed several scans per user directly through the store)."""
        ...

    def get_scan(self, user_id: UUID, scan_id: UUID) -> Scan | None: ...

    def list_scans(
        self, user_id: UUID, cursor: str | None, limit: int
    ) -> tuple[list[Scan], str | None]: ...

    def update_scan(
        self,
        user_id: UUID,
        scan_id: UUID,
        *,
        status: str | None = None,
        progress: int | None = None,
        error: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> Scan | None: ...

    def cancel_scan(self, user_id: UUID, scan_id: UUID) -> Scan | None:
        """Cancel a queued/running scan. Returns None if not found / not
        yours; raises ScanConflictError if already in a terminal state."""
        ...

    def count_scans_this_month(self, user_id: UUID) -> int: ...

    def count_active_scans(self, user_id: UUID) -> int:
        """Scans in a non-terminal state (queued/recon/crawling/scanning/
        triaging). Free tier allows at most 1."""
        ...

    # -- findings --------------------------------------------------------
    def create_finding(
        self,
        user_id: UUID,
        scan_id: UUID,
        target_id: UUID,
        template_id: str,
        title: str,
        severity: str,
        *,
        cvss: float | None = None,
        epss: float | None = None,
        kev: bool = False,
        cve: str | None = None,
        url: str | None = None,
        evidence: str | None = None,
        ai_verdict: str | None = None,
        ai_confidence: int | None = None,
        ai_reason: str | None = None,
    ) -> Finding: ...

    def get_finding(self, user_id: UUID, finding_id: UUID) -> Finding | None: ...

    def list_findings(
        self,
        user_id: UUID,
        scan_id: UUID,
        cursor: str | None,
        limit: int,
        severity: str | None = None,
    ) -> tuple[list[Finding], str | None]: ...

    def update_finding_feedback(
        self, user_id: UUID, finding_id: UUID, status: str
    ) -> Finding | None:
        """Apply a user verdict (``confirmed`` | ``false_positive``).
        Only ``status`` changes — ``ai_*`` fields are untouched."""
        ...

    # -- subscriptions ---------------------------------------------------
    def get_subscription(self, user_id: UUID) -> Subscription | None: ...

    def upsert_subscription(
        self,
        user_id: UUID,
        *,
        plan: str = "free",
        status: str = "active",
        current_period_end: datetime | None = None,
    ) -> Subscription: ...

    # -- audit -----------------------------------------------------------
    def log_audit(
        self,
        user_id: UUID,
        action: str,
        target_domain: str | None,
        metadata: dict[str, Any],
    ) -> AuditLog: ...

    def get_owner(self, resource_kind: str, resource_id: UUID) -> UUID | None:
        """The owning user_id of a row REGARDLESS of tenancy, or None when
        the id does not exist. Audit-only: routers use it to distinguish
        "no such id" from "another tenant's id" when a tenant-scoped get
        returns None, so a cross-tenant probe is audit-logged while still
        answering 404. ``resource_kind`` is "target" | "scan" | "finding".
        The row itself is never returned — only its owner."""
        ...

    # -- scan jobs --------------------------------------------------------
    def create_scan_job(
        self, user_id: UUID, scan_id: UUID, stage: str, idempotency_key: str
    ) -> ScanJob: ...

    def get_scan_job_by_key(self, user_id: UUID, idempotency_key: str) -> ScanJob | None: ...

    def update_scan_job(
        self,
        user_id: UUID,
        job_id: UUID,
        *,
        status: str | None = None,
        attempt: int | None = None,
        celery_task_id: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        log: str | None = None,
    ) -> ScanJob | None: ...
