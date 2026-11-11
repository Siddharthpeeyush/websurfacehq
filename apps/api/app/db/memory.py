"""In-memory :class:`~app.db.store.Store` implementation.

Used by ALL tests and by dev when Supabase is not configured. Thread-safe
via a single re-entrant lock around every method (good enough for tests and
single-process dev; this store is never the production store).

Two-tenant seed data lives here too: :func:`seed_two_tenants` creates
tenant A + tenant B with FIXED user UUIDs. No ``supabase/seed.sql`` exists
yet (Builder A has not written it), so these UUIDs are the canonical seed
identities — the SQL seed must use these same UUIDs in the integration pass.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from app.core.config import settings
from app.db.store import (
    AuditLog,
    DuplicateTargetError,
    Finding,
    Scan,
    ScanConflictError,
    ScanJob,
    Store,
    Subscription,
    Target,
    decode_cursor,
    encode_cursor,
)

# --- Canonical two-tenant seed identities ---------------------------------
# Deterministic UUIDs. Recorded here AND in the Builder C report so the
# future supabase/seed.sql can use the exact same values.
TENANT_A_USER_ID = UUID("11111111-1111-4111-8111-111111111111")
TENANT_B_USER_ID = UUID("22222222-2222-4222-8222-222222222222")

# Deterministic resource ids for the seed (uuid5 over a stable namespace).
_SEED_NS = UUID("aaaaaaaa-0000-4000-8000-000000000000")


def _seed_id(kind: str, name: str) -> UUID:
    return uuid.uuid5(_SEED_NS, f"{kind}:{name}")


TERMINAL_SCAN_STATUSES: frozenset[str] = frozenset({"done", "failed", "cancelled"})
ACTIVE_SCAN_STATUSES: frozenset[str] = frozenset(
    {"queued", "recon", "crawling", "scanning", "triaging"}
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _paginate(items: list[Any], cursor: str | None, limit: int) -> tuple[list[Any], str | None]:
    """Sort created_at desc / id desc, apply the cursor, slice one page."""
    ordered = sorted(
        items,
        key=lambda row: (row.created_at or _now(), row.id),
        reverse=True,
    )
    if cursor is not None:
        cursor_created_at, cursor_id = decode_cursor(cursor)
        ordered = [
            row
            for row in ordered
            if (row.created_at or _now(), row.id) < (cursor_created_at, cursor_id)
        ]
    page = ordered[:limit]
    next_cursor: str | None = None
    if len(ordered) > limit and page:
        last = page[-1]
        next_cursor = encode_cursor(last.created_at or _now(), last.id)
    return page, next_cursor


class InMemoryStore:
    """Thread-safe in-memory store. Implements the full Store protocol."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._targets: dict[UUID, Target] = {}
        self._scans: dict[UUID, Scan] = {}
        self._findings: dict[UUID, Finding] = {}
        self._subscriptions: dict[UUID, Subscription] = {}
        self._audit: dict[UUID, AuditLog] = {}
        self._scan_jobs: dict[UUID, ScanJob] = {}

    # -- health ----------------------------------------------------------
    def ping(self) -> bool:
        return True

    # -- targets ---------------------------------------------------------
    def create_target(self, user_id: UUID, domain: str, verification_token_hash: str) -> Target:
        with self._lock:
            domain = domain.lower().rstrip(".")
            for target in self._targets.values():
                if (
                    target.user_id == user_id
                    and target.domain == domain
                    and target.deleted_at is None
                ):
                    raise DuplicateTargetError(f"Target already exists for domain {domain}")
            now = _now()
            target = Target(
                id=uuid.uuid4(),
                user_id=user_id,
                domain=domain,
                verification_token_hash=verification_token_hash,
                verification_expires_at=now + timedelta(days=settings.verification_token_ttl_days),
                created_at=now,
                updated_at=now,
            )
            self._targets[target.id] = target
            return target

    def get_target(self, user_id: UUID, target_id: UUID) -> Target | None:
        with self._lock:
            target = self._targets.get(target_id)
            if target is None or target.user_id != user_id:
                return None
            if target.deleted_at is not None:
                return None
            return target

    def get_target_by_domain(self, user_id: UUID, domain: str) -> Target | None:
        with self._lock:
            domain = domain.lower().rstrip(".")
            for target in self._targets.values():
                if (
                    target.user_id == user_id
                    and target.domain == domain
                    and target.deleted_at is None
                ):
                    return target
            return None

    def count_targets(self, user_id: UUID) -> int:
        with self._lock:
            return sum(
                1 for t in self._targets.values() if t.user_id == user_id and t.deleted_at is None
            )

    def list_targets(
        self, user_id: UUID, cursor: str | None, limit: int
    ) -> tuple[list[Target], str | None]:
        with self._lock:
            rows = [
                t for t in self._targets.values() if t.user_id == user_id and t.deleted_at is None
            ]
            return _paginate(rows, cursor, limit)

    def delete_target(self, user_id: UUID, target_id: UUID) -> bool:
        with self._lock:
            target = self.get_target(user_id, target_id)
            if target is None:
                return False
            target.deleted_at = _now()
            target.updated_at = _now()
            return True

    def update_target_verification(
        self,
        user_id: UUID,
        target_id: UUID,
        *,
        status: str,
        method: str | None = None,
        verified_at: datetime | None = None,
    ) -> Target | None:
        with self._lock:
            target = self.get_target(user_id, target_id)
            if target is None:
                return None
            target.verification_status = status
            if method is not None:
                target.verification_method = method
            if verified_at is not None:
                target.verified_at = verified_at
            target.updated_at = _now()
            return target

    # -- scans -----------------------------------------------------------
    def create_scan(self, user_id: UUID, target_id: UUID, config: dict[str, Any]) -> Scan:
        with self._lock:
            now = _now()
            scan = Scan(
                id=uuid.uuid4(),
                user_id=user_id,
                target_id=target_id,
                status="queued",
                config=dict(config),
                progress=0,
                created_at=now,
                updated_at=now,
            )
            self._scans[scan.id] = scan
            return scan

    def get_scan(self, user_id: UUID, scan_id: UUID) -> Scan | None:
        with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None or scan.user_id != user_id:
                return None
            return scan

    def list_scans(
        self, user_id: UUID, cursor: str | None, limit: int
    ) -> tuple[list[Scan], str | None]:
        with self._lock:
            # Soft-deleted scans are excluded, like list_targets (round-2
            # review finding — the Supabase path had the same gap).
            rows = [
                s for s in self._scans.values() if s.user_id == user_id and s.deleted_at is None
            ]
            return _paginate(rows, cursor, limit)

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
    ) -> Scan | None:
        with self._lock:
            scan = self.get_scan(user_id, scan_id)
            if scan is None:
                return None
            if status is not None:
                scan.status = status
            if progress is not None:
                scan.progress = progress
            if error is not None:
                scan.error = error
            if started_at is not None:
                scan.started_at = started_at
            if finished_at is not None:
                scan.finished_at = finished_at
            scan.updated_at = _now()
            return scan

    def cancel_scan(self, user_id: UUID, scan_id: UUID) -> Scan | None:
        with self._lock:
            scan = self.get_scan(user_id, scan_id)
            if scan is None:
                return None
            if scan.status in TERMINAL_SCAN_STATUSES:
                raise ScanConflictError(
                    f"Scan {scan.id} is already {scan.status} and cannot be cancelled"
                )
            scan.status = "cancelled"
            scan.finished_at = _now()
            scan.updated_at = _now()
            return scan

    def count_scans_this_month(self, user_id: UUID) -> int:
        with self._lock:
            now = _now()
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            return sum(
                1
                for s in self._scans.values()
                if s.user_id == user_id and s.created_at is not None and s.created_at >= month_start
            )

    def count_active_scans(self, user_id: UUID) -> int:
        with self._lock:
            return sum(
                1
                for s in self._scans.values()
                if s.user_id == user_id and s.status in ACTIVE_SCAN_STATUSES
            )

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
    ) -> Finding:
        with self._lock:
            now = _now()
            finding = Finding(
                id=uuid.uuid4(),
                user_id=user_id,
                scan_id=scan_id,
                target_id=target_id,
                template_id=template_id,
                title=title,
                severity=severity,
                cvss=cvss,
                epss=epss,
                kev=kev,
                cve=cve,
                url=url,
                evidence=evidence,
                ai_verdict=ai_verdict,
                ai_confidence=ai_confidence,
                ai_reason=ai_reason,
                status="new",
                created_at=now,
                updated_at=now,
            )
            self._findings[finding.id] = finding
            return finding

    def get_finding(self, user_id: UUID, finding_id: UUID) -> Finding | None:
        with self._lock:
            finding = self._findings.get(finding_id)
            if finding is None or finding.user_id != user_id:
                return None
            return finding

    def list_findings(
        self,
        user_id: UUID,
        scan_id: UUID,
        cursor: str | None,
        limit: int,
        severity: str | None = None,
    ) -> tuple[list[Finding], str | None]:
        with self._lock:
            # The scan itself must be the caller's; otherwise this is an
            # empty page, never another tenant's findings.
            scan = self.get_scan(user_id, scan_id)
            if scan is None:
                return [], None
            rows = [
                f
                for f in self._findings.values()
                if f.user_id == user_id
                and f.scan_id == scan_id
                and (severity is None or f.severity == severity)
            ]
            return _paginate(rows, cursor, limit)

    def update_finding_feedback(
        self, user_id: UUID, finding_id: UUID, status: str
    ) -> Finding | None:
        with self._lock:
            finding = self.get_finding(user_id, finding_id)
            if finding is None:
                return None
            # Only status changes; ai_* fields are untouched by design.
            finding.status = status
            finding.updated_at = _now()
            return finding

    # -- subscriptions ---------------------------------------------------
    def get_subscription(self, user_id: UUID) -> Subscription | None:
        with self._lock:
            return self._subscriptions.get(user_id)

    def upsert_subscription(
        self,
        user_id: UUID,
        *,
        plan: str = "free",
        status: str = "active",
        current_period_end: datetime | None = None,
    ) -> Subscription:
        with self._lock:
            now = _now()
            existing = self._subscriptions.get(user_id)
            if existing is None:
                sub = Subscription(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    plan=plan,
                    status=status,
                    current_period_end=current_period_end,
                    created_at=now,
                    updated_at=now,
                )
            else:
                existing.plan = plan
                existing.status = status
                existing.current_period_end = current_period_end
                existing.updated_at = now
                sub = existing
            self._subscriptions[user_id] = sub
            return sub

    # -- audit -----------------------------------------------------------
    def log_audit(
        self,
        user_id: UUID,
        action: str,
        target_domain: str | None,
        metadata: dict[str, Any],
    ) -> AuditLog:
        with self._lock:
            entry = AuditLog(
                id=uuid.uuid4(),
                user_id=user_id,
                action=action,
                target_domain=target_domain,
                metadata=dict(metadata),
                created_at=_now(),
            )
            self._audit[entry.id] = entry
            return entry

    def get_owner(self, resource_kind: str, resource_id: UUID) -> UUID | None:
        # Audit-only: the row itself is never returned, only its owner.
        with self._lock:
            row: Target | Scan | Finding | None = None
            if resource_kind == "target":
                row = self._targets.get(resource_id)
            elif resource_kind == "scan":
                row = self._scans.get(resource_id)
            elif resource_kind == "finding":
                row = self._findings.get(resource_id)
            else:
                raise ValueError(f"Unknown resource kind: {resource_kind!r}")
            return row.user_id if row is not None else None

    # -- scan jobs --------------------------------------------------------
    def create_scan_job(
        self, user_id: UUID, scan_id: UUID, stage: str, idempotency_key: str
    ) -> ScanJob:
        with self._lock:
            now = _now()
            job = ScanJob(
                id=uuid.uuid4(),
                user_id=user_id,
                scan_id=scan_id,
                stage=stage,
                status="queued",
                attempt=0,
                idempotency_key=idempotency_key,
                created_at=now,
                updated_at=now,
            )
            self._scan_jobs[job.id] = job
            return job

    def get_scan_job_by_key(self, user_id: UUID, idempotency_key: str) -> ScanJob | None:
        with self._lock:
            for job in self._scan_jobs.values():
                if job.user_id == user_id and job.idempotency_key == idempotency_key:
                    return job
            return None

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
    ) -> ScanJob | None:
        with self._lock:
            job = self._scan_jobs.get(job_id)
            if job is None or job.user_id != user_id:
                return None
            if status is not None:
                job.status = status
            if attempt is not None:
                job.attempt = attempt
            if celery_task_id is not None:
                job.celery_task_id = celery_task_id
            if started_at is not None:
                job.started_at = started_at
            if finished_at is not None:
                job.finished_at = finished_at
            if log is not None:
                job.log = log
            job.updated_at = _now()
            return job


# ---------------------------------------------------------------------------
# Two-tenant seed
# ---------------------------------------------------------------------------


def seed_two_tenants(store: Store) -> dict[str, UUID]:
    """Seed one verified target + one scan for tenant A, one pending target
    for tenant B, and one finding on A's scan. Returns the ids created.

    Tenant A: 11111111-1111-4111-8111-111111111111 (example-a.com, verified)
    Tenant B: 22222222-2222-4222-8222-222222222222 (example-b.com, pending)

    The seed verification-token hashes are SHA-256 of the literal strings
    "seed-token-tenant-a" / "seed-token-tenant-b" — the same strings as
    supabase/seed.sql, so both fixtures hash identically (L9 review fix).
    Never real tokens, never used for a real verification; they only let
    the seeded targets look realistic.
    """
    target_a = store.create_target(
        TENANT_A_USER_ID,
        "example-a.com",
        hashlib.sha256(b"seed-token-tenant-a").hexdigest(),
    )
    store.update_target_verification(
        TENANT_A_USER_ID,
        target_a.id,
        status="verified",
        method="dns",
        verified_at=target_a.created_at,
    )
    scan_a = store.create_scan(
        TENANT_A_USER_ID,
        target_a.id,
        {"depth": "standard", "max_urls": 500},
    )
    finding_a = store.create_finding(
        TENANT_A_USER_ID,
        scan_a.id,
        target_a.id,
        template_id="http-missing-security-headers",
        title="Missing security headers",
        severity="medium",
        url="https://example-a.com/",
        evidence="X-Frame-Options header missing",
    )
    target_b = store.create_target(
        TENANT_B_USER_ID,
        "example-b.com",
        hashlib.sha256(b"seed-token-tenant-b").hexdigest(),
    )
    return {
        "tenant_a_user_id": TENANT_A_USER_ID,
        "tenant_b_user_id": TENANT_B_USER_ID,
        "target_a_id": target_a.id,
        "scan_a_id": scan_a.id,
        "finding_a_id": finding_a.id,
        "target_b_id": target_b.id,
    }
