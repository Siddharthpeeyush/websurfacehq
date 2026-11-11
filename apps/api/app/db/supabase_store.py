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
    DuplicateTargetError,
    Finding,
    Scan,
    ScanConflictError,
    ScanJob,
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
