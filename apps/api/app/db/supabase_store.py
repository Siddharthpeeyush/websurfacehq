"""Supabase (Postgres) :class:`~app.db.store.Store` implementation.

Uses supabase-py with the SERVICE-ROLE key — server-side only. The key must
NEVER appear in frontend code, the frontend bundle, or any committed file.

Tenancy is enforced TWICE, by design (docs/permissions.md §3.4, docs/
threat-model.md §3.4):

1. The API enforces tenancy through ``can()`` + this store's ``user_id``
   scoping on every query (``.eq("user_id", ...)``).
2. Row-Level Security policies in Postgres enforce the same rule for any
   direct DB access.

RLS is defense-in-depth for direct DB access; it is NOT a substitute for
the API-side checks. A bug in one layer must not leak data through the
other — that is why every method here still scopes by ``user_id`` even
though RLS exists.

Raises :class:`app.core.errors.ApiError` 503 ``SUPABASE_NOT_CONFIGURED``
when ``settings.supabase_configured`` is False. This store is NEVER called
from a test — no live Supabase project exists yet, so its methods are
exercised only against a real project in the integration pass.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from app.core.config import Settings, settings
from app.core.errors import ApiError
from app.db.store import (
    AuditLog,
    DuplicateOwnerAccountError,
    DuplicateStaffAccountError,
    DuplicateTargetError,
    Finding,
    Scan,
    ScanConflictError,
    ScanJob,
    StaffAccountRow,
    StaffInviteRow,
    Subscription,
    Target,
    TargetCapError,
    decode_cursor,
    encode_cursor,
)

TERMINAL_SCAN_STATUSES: frozenset[str] = frozenset({"done", "failed", "cancelled"})
ACTIVE_SCAN_STATUSES: frozenset[str] = frozenset(
    {"queued", "recon", "crawling", "scanning", "triaging"}
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


class SupabaseStore:
    """Store backed by Supabase Postgres via supabase-py (service role)."""

    def __init__(self, app_settings: Settings | None = None) -> None:
        cfg = app_settings or settings
        if not cfg.supabase_configured:
            raise ApiError(
                503,
                "SUPABASE_NOT_CONFIGURED",
                "Supabase is not configured for this environment",
            )
        # NOTE: the local ``create_client`` name is the proxy-safe wrapper
        # (app.core.http.create_supabase_client), NOT supabase.create_client
        # directly — it injects a trust_env=False httpx client via
        # SyncClientOptions (live-proof fix F1: the VM's bracketed no_proxy
        # entries make a plain httpx.Client() raise InvalidURL). Imported
        # lazily here so tests patching ``supabase.create_client`` still
        # intercept (the wrapper resolves that binding at call time).
        from app.core.http import create_supabase_client as create_client

        service_key = cfg.supabase_service_role_key
        assert service_key is not None  # guaranteed by supabase_configured
        assert cfg.supabase_url is not None
        self._client = create_client(cfg.supabase_url, service_key.get_secret_value())

    # -- row mapping ------------------------------------------------------
    @staticmethod
    def _target(row: dict[str, Any]) -> Target:
        return Target(
            id=UUID(str(row["id"])),
            user_id=UUID(str(row["user_id"])),
            domain=str(row["domain"]),
            verification_token_hash=str(row["verification_token_hash"]),
            verification_method=row.get("verification_method"),
            verification_status=str(row.get("verification_status", "pending")),
            verification_expires_at=_parse_dt(row.get("verification_expires_at")),
            verified_at=_parse_dt(row.get("verified_at")),
            created_at=_parse_dt(row.get("created_at")),
            updated_at=_parse_dt(row.get("updated_at")),
            deleted_at=_parse_dt(row.get("deleted_at")),
        )

    @staticmethod
    def _scan(row: dict[str, Any]) -> Scan:
        return Scan(
            id=UUID(str(row["id"])),
            user_id=UUID(str(row["user_id"])),
            target_id=UUID(str(row["target_id"])),
            status=str(row.get("status", "queued")),
            config=dict(row.get("config") or {}),
            progress=int(row.get("progress", 0)),
            started_at=_parse_dt(row.get("started_at")),
            finished_at=_parse_dt(row.get("finished_at")),
            error=row.get("error"),
            created_at=_parse_dt(row.get("created_at")),
            updated_at=_parse_dt(row.get("updated_at")),
            deleted_at=_parse_dt(row.get("deleted_at")),
        )

    @staticmethod
    def _finding(row: dict[str, Any]) -> Finding:
        return Finding(
            id=UUID(str(row["id"])),
            user_id=UUID(str(row["user_id"])),
            scan_id=UUID(str(row["scan_id"])),
            target_id=UUID(str(row["target_id"])),
            template_id=str(row.get("template_id", "")),
            title=str(row.get("title", "")),
            severity=str(row.get("severity", "info")),
            cvss=row.get("cvss"),
            epss=row.get("epss"),
            kev=bool(row.get("kev", False)),
            cve=row.get("cve"),
            url=row.get("url"),
            evidence=row.get("evidence"),
            ai_verdict=row.get("ai_verdict"),
            ai_confidence=row.get("ai_confidence"),
            ai_reason=row.get("ai_reason"),
            status=str(row.get("status", "new")),
            created_at=_parse_dt(row.get("created_at")),
            updated_at=_parse_dt(row.get("updated_at")),
        )

    @staticmethod
    def _subscription(row: dict[str, Any]) -> Subscription:
        return Subscription(
            id=UUID(str(row["id"])),
            # Schema column is owner_id (0002_billing_teams.sql), not
            # user_id — the protocol's user_id IS the subscription owner.
            user_id=UUID(str(row["owner_id"])),
            plan=str(row.get("plan", "free")),
            status=str(row.get("status", "active")),
            current_period_end=_parse_dt(row.get("current_period_end")),
            created_at=_parse_dt(row.get("created_at")),
            updated_at=_parse_dt(row.get("updated_at")),
        )

    @staticmethod
    def _audit(row: dict[str, Any]) -> AuditLog:
        return AuditLog(
            id=UUID(str(row["id"])),
            user_id=UUID(str(row["user_id"])),
            action=str(row["action"]),
            target_domain=row.get("target_domain"),
            metadata=dict(row.get("metadata") or {}),
            created_at=_parse_dt(row.get("created_at")),
        )

    @staticmethod
    def _staff_account(row: dict[str, Any]) -> StaffAccountRow:
        # Migration 0007 has NO mfa_enrolled column: enrollment is
        # derived from the stored verified factor id (a row with a
        # current factor is enrolled; clearing it un-enrolls). The
        # in-memory row carries the flag as a cache; the Supabase
        # row derives it, so the two can never disagree.
        return StaffAccountRow(
            user_id=UUID(str(row["user_id"])),
            email=str(row["email"]),
            role=str(row["role"]),
            status=str(row.get("status", "active")),
            invited_by=UUID(str(row["invited_by"])) if row.get("invited_by") else None,
            created_at=_parse_dt(row.get("created_at")),
            updated_at=_parse_dt(row.get("updated_at")),
            mfa_enrolled=row.get("current_factor_id") is not None,
            current_factor_id=row.get("current_factor_id"),
            pending_factor_id=row.get("pending_factor_id"),
        )

    @staticmethod
    def _staff_invite(row: dict[str, Any]) -> StaffInviteRow:
        return StaffInviteRow(
            id=UUID(str(row["id"])),
            token_hash=str(row["token_hash"]),
            email=str(row["email"]),
            role=str(row["role"]),
            invited_by=UUID(str(row["invited_by"])),
            expires_at=_parse_dt(row.get("expires_at")) or _now(),
            used_at=_parse_dt(row.get("used_at")),
            created_at=_parse_dt(row.get("created_at")),
        )

    @staticmethod
    def _scan_job(row: dict[str, Any]) -> ScanJob:
        return ScanJob(
            id=UUID(str(row["id"])),
            user_id=UUID(str(row["user_id"])),
            scan_id=UUID(str(row["scan_id"])),
            stage=str(row["stage"]),
            status=str(row.get("status", "queued")),
            attempt=int(row.get("attempt", 0)),
            celery_task_id=row.get("celery_task_id"),
            idempotency_key=str(row.get("idempotency_key", "")),
            started_at=_parse_dt(row.get("started_at")),
            finished_at=_parse_dt(row.get("finished_at")),
            log=row.get("log"),
            created_at=_parse_dt(row.get("created_at")),
            updated_at=_parse_dt(row.get("updated_at")),
        )

    def _page(
        self,
        table: str,
        user_id: UUID,
        cursor: str | None,
        limit: int,
        extra_eq: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """One ordered page of raw rows, newest first.

        Known Week 1 limitation: the keyset filter is on ``created_at``
        only (``.lte`` + a Python-side id tiebreak). Two rows sharing the
        exact same ``created_at`` microsecond at a page boundary can be
        skipped or repeated — in practice impossible for distinct inserts
        (Postgres ``now()`` has microsecond resolution), and the
        InMemoryStore (the tested path) implements the full composite
        keyset. A proper composite keyset query lands with real-DB
        integration testing.
        """
        query = (
            self._client.table(table)
            .select("*")
            .eq("user_id", str(user_id))
            .order("created_at", desc=True)
            .order("id", desc=True)
        )
        if extra_eq:
            for key, value in extra_eq.items():
                query = query.eq(key, value)
        if cursor is not None:
            cursor_created_at, _ = decode_cursor(cursor)
            query = query.lte("created_at", cursor_created_at.isoformat())
        query = query.limit(limit + 1)
        response = query.execute()
        rows: list[dict[str, Any]] = [dict(r) for r in (response.data or [])]
        if cursor is not None:
            cursor_created_at, cursor_id = decode_cursor(cursor)
            rows = [
                r
                for r in rows
                if (
                    _parse_dt(r.get("created_at")) or _now(),
                    UUID(str(r["id"])),
                )
                < (cursor_created_at, cursor_id)
            ]
        return rows[: limit + 1]

    @staticmethod
    def _next_cursor(full_rows: list[Any], limit: int) -> str | None:
        """``full_rows`` is the mapped page BEFORE slicing to ``limit``
        (it holds up to ``limit + 1`` rows); the cursor points at the last
        row of the returned page when a further page exists."""
        if len(full_rows) > limit:
            last = full_rows[limit - 1]
            return encode_cursor(last.created_at or _now(), last.id)
        return None

    # -- health ----------------------------------------------------------
    def ping(self) -> bool:
        try:
            self._client.table("targets").select("id").limit(1).execute()
            return True
        except Exception:
            return False

    # -- targets ---------------------------------------------------------
    def create_target(self, user_id: UUID, domain: str, verification_token_hash: str) -> Target:
        domain = domain.lower().rstrip(".")
        now = _now()
        try:
            response = (
                self._client.table("targets")
                .insert(
                    {
                        "id": str(uuid.uuid4()),
                        "user_id": str(user_id),
                        "domain": domain,
                        "verification_token_hash": verification_token_hash,
                        "verification_status": "pending",
                        # The schema column is verification_expires_at
                        # (0001_core.sql) — the TTL is enforced by the
                        # router against this instant, never by an age
                        # computed from created_at.
                        "verification_expires_at": (
                            now + timedelta(days=settings.verification_token_ttl_days)
                        ).isoformat(),
                        "created_at": now.isoformat(),
                        "updated_at": now.isoformat(),
                    }
                )
                .execute()
            )
        except Exception as exc:
            # Two distinct unique violations can surface here — check the
            # one-live-target index FIRST (its message also contains
            # "duplicate", so the generic check below would misclassify
            # it as a same-domain duplicate):
            #   * targets_one_live_per_user (migration 0004): the user
            #     already has a live target — the atomic backstop for the
            #     router's count check (round-2 review, Blocker 2).
            #   * (user_id, domain): the same domain already exists.
            # NOTE (live-verification gap, round-2 review): the mapping
            # keys on the constraint/index name appearing in postgrest-py's
            # error string. That string is unproven against a live
            # Supabase project — if it surfaces differently, a cap hit
            # becomes a 500 instead of a 429 (fail-closed, wrong status).
            # Same caveat as the M4 ScanConflictError mapping in
            # create_scan; prove both once the migrations are applied.
            if "targets_one_live_per_user" in str(exc):
                raise TargetCapError(
                    "Free plan allows 1 domain (user already has a live target)"
                ) from exc
            # Postgres unique-violation on (user_id, domain) surfaces here
            # as a Postgrest error; surface it as the duplicate the
            # protocol promises instead of leaking a DB message.
            if "duplicate" in str(exc).lower() or "23505" in str(exc):
                raise DuplicateTargetError(f"Target already exists for domain {domain}") from exc
            raise
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to create target")
        return self._target(dict(rows[0]))

    def get_target(self, user_id: UUID, target_id: UUID) -> Target | None:
        response = (
            self._client.table("targets")
            .select("*")
            .eq("id", str(target_id))
            .eq("user_id", str(user_id))
            .is_("deleted_at", "null")
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._target(dict(rows[0]))

    def get_target_by_domain(self, user_id: UUID, domain: str) -> Target | None:
        response = (
            self._client.table("targets")
            .select("*")
            .eq("user_id", str(user_id))
            .eq("domain", domain.lower().rstrip("."))
            .is_("deleted_at", "null")
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._target(dict(rows[0]))

    def count_targets(self, user_id: UUID) -> int:
        response = (
            self._client.table("targets")
            .select("id")
            .eq("user_id", str(user_id))
            .is_("deleted_at", "null")
            .execute()
        )
        return len(response.data or [])

    def list_targets(
        self, user_id: UUID, cursor: str | None, limit: int
    ) -> tuple[list[Target], str | None]:
        rows = self._page("targets", user_id, cursor, limit)
        # Soft-deleted rows are excluded (RLS + this filter both apply).
        # NOTE: a deleted row consumes a page slot here; exact page sizes
        # on the Supabase path are a known Week 1 limitation.
        all_targets = [self._target(r) for r in rows if r.get("deleted_at") is None]
        return all_targets[:limit], self._next_cursor(all_targets, limit)

    def delete_target(self, user_id: UUID, target_id: UUID) -> bool:
        target = self.get_target(user_id, target_id)
        if target is None:
            return False
        # Direct UPDATE (not the soft_delete_target RPC helper): this store
        # connects with the SERVICE-ROLE key, which bypasses RLS entirely,
        # so the UPDATE works here — and the helper would NOT work, because
        # it checks auth.uid(), which is NULL for service-role requests.
        # Tenancy is enforced by the get_target() check above (user_id
        # filter). The RPC helpers exist for the direct / user-JWT path
        # (dashboard, SQL), where a plain UPDATE of deleted_at fails under
        # the SELECT policy. If this store ever switches to per-user JWTs,
        # delete MUST switch to the RPC helpers.
        now = _now()
        self._client.table("targets").update(
            {"deleted_at": now.isoformat(), "updated_at": now.isoformat()}
        ).eq("id", str(target_id)).eq("user_id", str(user_id)).execute()
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
        if self.get_target(user_id, target_id) is None:
            return None
        patch: dict[str, Any] = {
            "verification_status": status,
            "updated_at": _now().isoformat(),
        }
        if method is not None:
            patch["verification_method"] = method
        if verified_at is not None:
            patch["verified_at"] = verified_at.isoformat()
        response = (
            self._client.table("targets")
            .update(patch)
            .eq("id", str(target_id))
            .eq("user_id", str(user_id))
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._target(dict(rows[0]))

    # -- scans -----------------------------------------------------------
    def create_scan(self, user_id: UUID, target_id: UUID, config: dict[str, Any]) -> Scan:
        now = _now()
        try:
            response = (
                self._client.table("scans")
                .insert(
                    {
                        "id": str(uuid.uuid4()),
                        "user_id": str(user_id),
                        "target_id": str(target_id),
                        "status": "queued",
                        "config": dict(config),
                        "progress": 0,
                        "created_at": now.isoformat(),
                        "updated_at": now.isoformat(),
                    }
                )
                .execute()
            )
        except Exception as exc:
            # Unique-violation on the partial index scans_one_active_per_user
            # (migration 0004): a concurrent request already opened the
            # user's one active scan. Surface it as the conflict the
            # protocol promises; the router maps it to 429 QUOTA_EXCEEDED.
            if "duplicate" in str(exc).lower() or "23505" in str(exc):
                raise ScanConflictError("User already has an active scan") from exc
            raise
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to create scan")
        return self._scan(dict(rows[0]))

    def get_scan(self, user_id: UUID, scan_id: UUID) -> Scan | None:
        response = (
            self._client.table("scans")
            .select("*")
            .eq("id", str(scan_id))
            .eq("user_id", str(user_id))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._scan(dict(rows[0]))

    def list_scans(
        self, user_id: UUID, cursor: str | None, limit: int
    ) -> tuple[list[Scan], str | None]:
        rows = self._page("scans", user_id, cursor, limit)
        # Soft-deleted rows are excluded, like list_targets (round-2
        # review finding — list_scans used to return soft-deleted scans).
        all_scans = [self._scan(r) for r in rows if r.get("deleted_at") is None]
        return all_scans[:limit], self._next_cursor(all_scans, limit)

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
        if self.get_scan(user_id, scan_id) is None:
            return None
        patch: dict[str, Any] = {"updated_at": _now().isoformat()}
        if status is not None:
            patch["status"] = status
        if progress is not None:
            patch["progress"] = progress
        if error is not None:
            patch["error"] = error
        if started_at is not None:
            patch["started_at"] = started_at.isoformat()
        if finished_at is not None:
            patch["finished_at"] = finished_at.isoformat()
        response = (
            self._client.table("scans")
            .update(patch)
            .eq("id", str(scan_id))
            .eq("user_id", str(user_id))
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._scan(dict(rows[0]))

    def cancel_scan(self, user_id: UUID, scan_id: UUID) -> Scan | None:
        scan = self.get_scan(user_id, scan_id)
        if scan is None:
            return None
        if scan.status in TERMINAL_SCAN_STATUSES:
            raise ScanConflictError(
                f"Scan {scan.id} is already {scan.status} and cannot be cancelled"
            )
        return self.update_scan(user_id, scan_id, status="cancelled", finished_at=_now())

    def count_scans_this_month(self, user_id: UUID) -> int:
        now = _now()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        response = (
            self._client.table("scans")
            .select("id")
            .eq("user_id", str(user_id))
            .gte("created_at", month_start.isoformat())
            .execute()
        )
        return len(response.data or [])

    def count_active_scans(self, user_id: UUID) -> int:
        response = (
            self._client.table("scans")
            .select("id")
            .eq("user_id", str(user_id))
            .in_("status", sorted(ACTIVE_SCAN_STATUSES))
            .execute()
        )
        return len(response.data or [])

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
        now = _now()
        response = (
            self._client.table("findings")
            .insert(
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(user_id),
                    "scan_id": str(scan_id),
                    "target_id": str(target_id),
                    "template_id": template_id,
                    "title": title,
                    "severity": severity,
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev,
                    "cve": cve,
                    "url": url,
                    "evidence": evidence,
                    "ai_verdict": ai_verdict,
                    "ai_confidence": ai_confidence,
                    "ai_reason": ai_reason,
                    "status": "new",
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                }
            )
            .execute()
        )
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to create finding")
        return self._finding(dict(rows[0]))

    def get_finding(self, user_id: UUID, finding_id: UUID) -> Finding | None:
        response = (
            self._client.table("findings")
            .select("*")
            .eq("id", str(finding_id))
            .eq("user_id", str(user_id))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._finding(dict(rows[0]))

    def list_findings(
        self,
        user_id: UUID,
        scan_id: UUID,
        cursor: str | None,
        limit: int,
        severity: str | None = None,
    ) -> tuple[list[Finding], str | None]:
        if self.get_scan(user_id, scan_id) is None:
            return [], None
        extra = {"scan_id": str(scan_id)}
        if severity is not None:
            extra["severity"] = severity
        rows = self._page("findings", user_id, cursor, limit, extra_eq=extra)
        all_findings = [self._finding(r) for r in rows]
        return all_findings[:limit], self._next_cursor(all_findings, limit)

    def update_finding_feedback(
        self, user_id: UUID, finding_id: UUID, status: str
    ) -> Finding | None:
        if self.get_finding(user_id, finding_id) is None:
            return None
        response = (
            self._client.table("findings")
            .update({"status": status, "updated_at": _now().isoformat()})
            .eq("id", str(finding_id))
            .eq("user_id", str(user_id))
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._finding(dict(rows[0]))

    # -- subscriptions ---------------------------------------------------
    def get_subscription(self, user_id: UUID) -> Subscription | None:
        response = (
            self._client.table("subscriptions")
            .select("*")
            .eq("owner_id", str(user_id))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._subscription(dict(rows[0]))

    def upsert_subscription(
        self,
        user_id: UUID,
        *,
        plan: str = "free",
        status: str = "active",
        current_period_end: datetime | None = None,
    ) -> Subscription:
        now = _now()
        payload: dict[str, Any] = {
            "owner_id": str(user_id),
            "plan": plan,
            "status": status,
            "current_period_end": _iso(current_period_end),
            "updated_at": now.isoformat(),
        }
        existing = self.get_subscription(user_id)
        if existing is None:
            payload["id"] = str(uuid.uuid4())
            payload["created_at"] = now.isoformat()
            response = self._client.table("subscriptions").insert(payload).execute()
        else:
            response = (
                self._client.table("subscriptions")
                .update(payload)
                .eq("owner_id", str(user_id))
                .execute()
            )
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to upsert subscription")
        return self._subscription(dict(rows[0]))

    # -- audit -----------------------------------------------------------
    def log_audit(
        self,
        user_id: UUID,
        action: str,
        target_domain: str | None,
        metadata: dict[str, Any],
    ) -> AuditLog:
        now = _now()
        response = (
            self._client.table("audit_logs")
            .insert(
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(user_id),
                    "action": action,
                    "target_domain": target_domain,
                    "metadata": dict(metadata),
                    "created_at": now.isoformat(),
                }
            )
            .execute()
        )
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to write audit log")
        return self._audit(dict(rows[0]))

    def list_audit_logs(
        self,
        *,
        actor_id: UUID | None = None,
        action: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        search: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[AuditLog], str | None]:
        # NO user_id scoping: audit rows span all tenants and this
        # method is staff-only — the caller MUST gate it with
        # can(user, "admin.audit.read", platform_role=...) first.
        # Same keyset convention as _page (created_at + id, newest
        # first); the Python-side tiebreak closes the same-timestamp
        # boundary the SQL lte leaves open.
        query = (
            self._client.table("audit_logs")
            .select("*")
            .order("created_at", desc=True)
            .order("id", desc=True)
        )
        if actor_id is not None:
            query = query.eq("user_id", str(actor_id))
        if action is not None:
            query = query.eq("action", action)
        if since is not None:
            query = query.gte("created_at", since.isoformat())
        if until is not None:
            query = query.lte("created_at", until.isoformat())
        if search:
            # PostgREST or_ splits on commas, so a comma in the term
            # would misparse the filter; % is a wildcard. Both are
            # stripped (documented limitation — the in-memory
            # implementation matches the raw substring instead).
            term = search.replace(",", "").replace("%", "")
            if term:
                query = query.or_(f"action.ilike.%{term}%,target_domain.ilike.%{term}%")
        if cursor is not None:
            cursor_created_at, _ = decode_cursor(cursor)
            query = query.lte("created_at", cursor_created_at.isoformat())
        response = query.limit(limit + 1).execute()
        rows: list[dict[str, Any]] = [dict(r) for r in (response.data or [])]
        if cursor is not None:
            cursor_created_at, cursor_id = decode_cursor(cursor)
            rows = [
                r
                for r in rows
                if (
                    _parse_dt(r.get("created_at")) or _now(),
                    UUID(str(r["id"])),
                )
                < (cursor_created_at, cursor_id)
            ]
        mapped = [self._audit(r) for r in rows]
        return mapped[:limit], self._next_cursor(mapped, limit)

    def get_staff_role(self, user_id: UUID) -> tuple[str, str] | None:
        # Service-role read of staff_roles (RLS gives authenticated
        # nothing on this table by design — the role is never trusted
        # from the client). No row means "not staff".
        response = (
            self._client.table("staff_roles")
            .select("role,status")
            .eq("user_id", str(user_id))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return (str(rows[0]["role"]), str(rows[0]["status"]))

    # -- staff accounts (admin foundation, C2 fix) ----------------------
    # The DB is the source of truth. Unique violations surface as
    # PostgREST errors; the constraint/index name in the message is
    # the mapping key (same caveat as create_target's cap mapping —
    # unproven against live Supabase until the integration pass;
    # a mis-map fails closed as a 500, never as a wrong 200).
    def create_staff_account(
        self,
        user_id: UUID,
        email: str,
        role: str,
        invited_by: UUID | None,
        created_at: datetime | None = None,
    ) -> StaffAccountRow:
        normalized = email.strip().lower()
        now = created_at or _now()
        try:
            response = (
                self._client.table("staff_roles")
                .insert(
                    {
                        "user_id": str(user_id),
                        "email": normalized,
                        "role": role,
                        "status": "active",
                        "invited_by": str(invited_by) if invited_by is not None else None,
                        "created_at": now.isoformat(),
                        "updated_at": now.isoformat(),
                    }
                )
                .execute()
            )
        except Exception as exc:
            # Second-Owner backstops (trigger message, then the
            # partial unique index) — checked FIRST: a duplicate
            # email for an "owner@..." address must not misclassify
            # as a second Owner.
            if "only one Owner" in str(exc) or "staff_roles_single_owner_idx" in str(exc):
                raise DuplicateOwnerAccountError("An Owner account already exists") from exc
            if "duplicate" in str(exc).lower() or "23505" in str(exc):
                raise DuplicateStaffAccountError(
                    f"Staff account already exists for {normalized}"
                ) from exc
            raise
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to create staff account")
        return self._staff_account(dict(rows[0]))

    def get_staff_account(self, user_id: UUID) -> StaffAccountRow | None:
        response = (
            self._client.table("staff_roles")
            .select("*")
            .eq("user_id", str(user_id))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._staff_account(dict(rows[0]))

    def get_staff_account_by_email(self, email: str) -> StaffAccountRow | None:
        response = (
            self._client.table("staff_roles")
            .select("*")
            .eq("email", email.strip().lower())
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._staff_account(dict(rows[0]))

    def list_staff_accounts(self) -> list[StaffAccountRow]:
        response = self._client.table("staff_roles").select("*").order("created_at").execute()
        return [self._staff_account(dict(row)) for row in (response.data or [])]

    def update_staff_account(
        self,
        user_id: UUID,
        *,
        role: str | None = None,
        status: str | None = None,
        mfa_enrolled: bool | None = None,
    ) -> StaffAccountRow | None:
        # mfa_enrolled is NOT a column (see _staff_account): it is
        # derived from current_factor_id, so there is nothing to
        # write for it — callers set the factor ids instead.
        if self.get_staff_account(user_id) is None:
            return None
        patch: dict[str, Any] = {"updated_at": _now().isoformat()}
        if role is not None:
            patch["role"] = role
        if status is not None:
            patch["status"] = status
        try:
            response = (
                self._client.table("staff_roles")
                .update(patch)
                .eq("user_id", str(user_id))
                .execute()
            )
        except Exception as exc:
            if "only one Owner" in str(exc) or "staff_roles_single_owner_idx" in str(exc):
                raise DuplicateOwnerAccountError("An Owner account already exists") from exc
            raise
        rows = response.data or []
        if not rows:
            return None
        return self._staff_account(dict(rows[0]))

    def set_staff_factor_ids(
        self,
        user_id: UUID,
        *,
        current_factor_id: str | None,
        pending_factor_id: str | None,
    ) -> StaffAccountRow | None:
        if self.get_staff_account(user_id) is None:
            return None
        response = (
            self._client.table("staff_roles")
            .update(
                {
                    "current_factor_id": current_factor_id,
                    "pending_factor_id": pending_factor_id,
                    "updated_at": _now().isoformat(),
                }
            )
            .eq("user_id", str(user_id))
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._staff_account(dict(rows[0]))

    def delete_staff_account(self, user_id: UUID) -> bool:
        if self.get_staff_account(user_id) is None:
            return False
        self._client.table("staff_roles").delete().eq("user_id", str(user_id)).execute()
        return True

    # -- staff invites (admin foundation, C2 fix) -----------------------
    def create_staff_invite(
        self,
        email: str,
        role: str,
        invited_by: UUID,
        token_hash: str,
        expires_at: datetime,
        created_at: datetime | None = None,
    ) -> StaffInviteRow:
        now = created_at or _now()
        response = (
            self._client.table("staff_invites")
            .insert(
                {
                    "id": str(uuid.uuid4()),
                    "token_hash": token_hash,
                    "email": email.strip().lower(),
                    "role": role,
                    "invited_by": str(invited_by),
                    "expires_at": expires_at.isoformat(),
                    "used_at": None,
                    "created_at": now.isoformat(),
                }
            )
            .execute()
        )
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to create staff invite")
        return self._staff_invite(dict(rows[0]))

    def claim_staff_invite(self, token_hash: str, now: datetime) -> StaffInviteRow | None:
        # Atomic single-use claim: one UPDATE ... WHERE used_at IS
        # NULL AND expires_at > now RETURNING — two concurrent claims
        # cannot both return a row.
        response = (
            self._client.table("staff_invites")
            .update({"used_at": now.isoformat()})
            .eq("token_hash", token_hash)
            .is_("used_at", "null")
            .gt("expires_at", now.isoformat())
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._staff_invite(dict(rows[0]))

    def get_staff_invite(self, invite_id: UUID) -> StaffInviteRow | None:
        response = (
            self._client.table("staff_invites")
            .select("*")
            .eq("id", str(invite_id))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._staff_invite(dict(rows[0]))

    def revoke_pending_staff_invites(self, email: str, now: datetime) -> int:
        # Same used_at reuse as the in-memory store (see the Store
        # protocol): revoked reads as used at claim time, so the old
        # token 404s; the audit row records the revocation.
        response = (
            self._client.table("staff_invites")
            .update({"used_at": now.isoformat()})
            .eq("email", email.strip().lower())
            .is_("used_at", "null")
            .gt("expires_at", now.isoformat())
            .execute()
        )
        return len(response.data or [])

    def revoke_staff_invite(self, invite_id: UUID, now: datetime) -> StaffInviteRow | None:
        response = (
            self._client.table("staff_invites")
            .update({"used_at": now.isoformat()})
            .eq("id", str(invite_id))
            .is_("used_at", "null")
            .gt("expires_at", now.isoformat())
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._staff_invite(dict(rows[0]))

    # -- admin settings (admin foundation, C3 fix) ----------------------
    def get_admin_setting(self, key: str) -> str | None:
        response = (
            self._client.table("admin_settings").select("value").eq("key", key).limit(1).execute()
        )
        rows = response.data or []
        if not rows:
            return None
        value = rows[0].get("value")
        return str(value) if value is not None else None

    def set_admin_setting(self, key: str, value: str) -> str:
        payload: dict[str, Any] = {
            "key": key,
            "value": value,
            "updated_at": _now().isoformat(),
        }
        response = self._client.table("admin_settings").upsert(payload, on_conflict="key").execute()
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to write admin setting")
        stored = rows[0].get("value")
        return str(stored) if stored is not None else value

    def get_prefix_version(self) -> int:
        value = self.get_admin_setting("prefix_version")
        if value is None:
            return 1
        try:
            return max(int(value), 1)
        except ValueError:
            return 1

    def set_prefix_version(self, version: int) -> int:
        self.set_admin_setting("prefix_version", str(max(version, 1)))
        return self.get_prefix_version()

    def bump_prefix_version(self) -> int:
        # Read-modify-write (no single-statement increment through
        # the PostgREST query builder): a lost race between two
        # rotations bumps once instead of twice — fail-safe, since a
        # rotation's session invalidation depends on the version
        # CHANGING, not on its exact value. Residual noted in ADR.
        return self.set_prefix_version(self.get_prefix_version() + 1)

    def get_owner(self, resource_kind: str, resource_id: UUID) -> UUID | None:
        # Audit-only: service_role sees all rows, so this answers "whose
        # is it" without returning the row. Used by require_resource to
        # audit cross-tenant probes while still answering 404.
        table = {"target": "targets", "scan": "scans", "finding": "findings"}.get(resource_kind)
        if table is None:
            raise ValueError(f"Unknown resource kind: {resource_kind!r}")
        response = (
            self._client.table(table)
            .select("user_id")
            .eq("id", str(resource_id))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return UUID(str(rows[0]["user_id"]))

    # -- scan jobs --------------------------------------------------------
    def create_scan_job(
        self, user_id: UUID, scan_id: UUID, stage: str, idempotency_key: str
    ) -> ScanJob:
        now = _now()
        response = (
            self._client.table("scan_jobs")
            .insert(
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(user_id),
                    "scan_id": str(scan_id),
                    "stage": stage,
                    "status": "queued",
                    "attempt": 0,
                    "idempotency_key": idempotency_key,
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                }
            )
            .execute()
        )
        rows = response.data or []
        if not rows:
            raise ApiError(500, "INTERNAL_ERROR", "Failed to create scan job")
        return self._scan_job(dict(rows[0]))

    def get_scan_job_by_key(self, user_id: UUID, idempotency_key: str) -> ScanJob | None:
        response = (
            self._client.table("scan_jobs")
            .select("*")
            .eq("user_id", str(user_id))
            .eq("idempotency_key", idempotency_key)
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._scan_job(dict(rows[0]))

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
        existing = (
            self._client.table("scan_jobs")
            .select("id")
            .eq("id", str(job_id))
            .eq("user_id", str(user_id))
            .limit(1)
            .execute()
        )
        if not (existing.data or []):
            return None
        patch: dict[str, Any] = {"updated_at": _now().isoformat()}
        if status is not None:
            patch["status"] = status
        if attempt is not None:
            patch["attempt"] = attempt
        if celery_task_id is not None:
            patch["celery_task_id"] = celery_task_id
        if started_at is not None:
            patch["started_at"] = started_at.isoformat()
        if finished_at is not None:
            patch["finished_at"] = finished_at.isoformat()
        if log is not None:
            patch["log"] = log
        response = (
            self._client.table("scan_jobs")
            .update(patch)
            .eq("id", str(job_id))
            .eq("user_id", str(user_id))
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return self._scan_job(dict(rows[0]))
