"""Celery tasks: idempotency base, verification gate, pipeline registry.

Week 1 ships exactly ONE real stage — ``verify_target``. Every other stage
in :data:`SCAN_PIPELINE` is registered with ``implemented=False`` and is
never enqueued; the stages become real tasks in Weeks 2–3.

Contracts (as delivered by Builder C — these supersede the Week 1 brief's
sketch where they differ; every deviation is flagged in the Week 1 report):

- Store: ``app.db.get_store()`` returns the tenant-scoped
  ``app.db.store.Store``. EVERY method takes ``user_id`` first, so task
  args are ``(scan_id, user_id)`` (UUIDs as strings — Celery's JSON
  serializer cannot carry UUID objects).
- Scan jobs are keyed by the full idempotency key string
  (``scan_id:stage:target_hash``) via
  ``get_scan_job_by_key(user_id, idempotency_key)``; ``create_scan_job``
  takes the key and always starts the row ``queued``.
- Job results are stored as JSON in the row's ``log`` field (the only
  free-text field in the ``scan_jobs`` schema).
- Verification re-check uses ``check_verification_hash(domain,
  token_hash, method)`` — the raw token is never stored, so the
  ``check_verification(domain, token, method)`` form is unusable by
  workers. Methods are ``'dns'`` | ``'file'``.
- Target verification status is written via
  ``update_target_verification(user_id, target_id, status=..., ...)``.

Idempotency (blueprint §1.5): before running, the base task looks up the
``scan_jobs`` row for the stage's idempotency key:

- ``done`` → return the stored result, never re-run;
- ``running`` with a fresh heartbeat AND a different task id → skip
  (a concurrent duplicate delivery);
- ``running`` with the SAME task id → this is a retry of the same
  execution, so proceed;
- ``running`` with a stale heartbeat → the previous attempt died, proceed.

Retry policy (blueprint §1.5): autoretry on ``Exception``, exponential
backoff, max 3 retries, then DLQ + scan marked ``failed``. Celery's
native backoff is ``min(900, 60 * 2**retries)`` = 60/120/240 s
(jitter off, so the delays are deterministic); the blueprint's nominal
60/300/900 s schedule is not expressible as Celery's doubling formula.

Deterministic failures do NOT retry (M2 review fix): an SSRF refusal,
a missing agent binary, or an agent stage failure is returned as a
``status="refused"`` result instead of raising, so it never burns the
3 retries. Only transient failures (agent timeout, transport /
``OSError``) still raise into Celery's autoretry.

Pipeline chaining (B2 review fix): ``dispatch.py`` still enqueues only
``verify_target``; each stage, on a fresh successful run, enqueues the
next stage (``verify_target`` → ``dns_enum`` → ``subdomain_enum`` →
``port_scan`` → ``http_probe`` → ``tech_fingerprint`` → ``crawl`` →
``js_secret_scan``) via :func:`_enqueue_next_stage`. The enqueue
happens in ``IdempotentTask.__call__`` AFTER the fresh result is
persisted — not in the task bodies — so a chained stage that reads the
parent's job log (``port_scan`` / ``http_probe`` / ``crawl`` read
``subdomain_enum``'s log for ``hosts=``) always sees it, including in
eager mode where the child runs synchronously. A cached re-run returns
before the task body, so it never re-enqueues. ``port_scan``,
``http_probe`` and ``crawl`` take their ``hosts=`` from the
``subdomain_enum`` / ``dns_enum`` job logs (apex first, capped at 100),
falling back to the apex domain alone.

Request budget (M4 review fix — honest scope): HTTP-request counting
is NOT enforced end-to-end. The agent's tools do not report per-tool
request counts back to Python, so the Free 1,000 requests/scan quota
cannot be counted here. The enforceable bounds now are: at most 100
hosts probed per stage, stored subdomain/URL lists capped at 5,000
entries, JS fetches capped at 50 files/scan. Do not claim the
1,000-request quota is enforced until the agent reports request
counts.

Verification gate (docs/testing.md §4): a Celery task handed an
unverified target REFUSES to run — no outbound request is made at all.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from celery import Task  # type: ignore[import-untyped]

from app.core.ssrf import UnsafeUrlError
from app.db.store import Store, hash_resource_id
from app.services.js_secrets import scan_js
from app.services.techprint import fingerprint
from app.workers.celery_app import celery_app
from app.workers.dlq import send_to_dlq
from app.workers.pinned_http import pinned_get
from app.workers.scanner_runner import (
    ScannerAgentError,
    ScannerAgentTimeout,
    ScannerAgentUnavailable,
    run_stage,
)

logger = logging.getLogger(__name__)

# A ``running`` job row whose heartbeat is younger than this is treated as
# still executing (a duplicate delivery is skipped). Older than this, the
# previous attempt is presumed dead and the stage may re-run.
HEARTBEAT_FRESH_SECONDS = 600

# Stored-list caps (M4 review fix): a scan that enumerates tens of
# thousands of subdomains / URLs must not bloat the job log without
# bound. Lists are truncated deterministically (sorted, first N kept)
# and the result records ``truncated: true`` + the pre-truncation total.
_MAX_STORED_SUBDOMAINS = 5000
_MAX_STORED_URLS = 5000

# Per-stage host cap (B2/M4): port_scan / http_probe / crawl receive at
# most this many hosts from the prior stages' logs. This is the
# enforceable bound on per-scan probing until the agent reports
# request counts (see the module docstring).
_MAX_HOSTS_PER_STAGE = 100


# ---------------------------------------------------------------------------
# Domain normalisation + idempotency key
# ---------------------------------------------------------------------------


def normalize_domain(domain: str) -> str:
    """Normalise a target domain for hashing/comparison.

    Lower-cases, strips whitespace, tolerates a pasted URL (drops the
    scheme, path and port) and a trailing dot. ``Example.COM/`` and
    ``https://example.com`` hash identically.
    """
    value = domain.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]  # drop any trailing path
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def target_hash_for(domain: str) -> str:
    """First 12 hex chars of the SHA-256 of the normalized domain."""
    return hashlib.sha256(normalize_domain(domain).encode("utf-8")).hexdigest()[:12]


def idempotency_key(scan_id: str, stage: str, domain: str) -> str:
    """Task id for one stage of one scan: ``scan_id:stage:target_hash``."""
    return f"{scan_id}:{stage}:{target_hash_for(domain)}"


def _coerce_uuid(value: str) -> UUID:
    """Parse a UUID string from task args (raises ValueError on garbage)."""
    return UUID(value)


# ---------------------------------------------------------------------------
# Pipeline registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineStage:
    """One stage of the scan pipeline."""

    stage: str
    queue: str
    implemented: bool


# Ordered stage list (architecture §4 / blueprint §1.5). Week 1: ONLY
# verify_target was implemented. Week 2 flips the seven recon stages to
# implemented=True as they land (see the tasks below); the rest are
# listed so dispatch can create their ``queued`` scan_jobs rows — they
# MUST NOT be enqueued yet.
# Queue note: ai_triage / enrichment / generate_report / notify_user are
# lightweight post-processing, not scanning; the architecture has only
# three queues, so they ride ``recon`` (10 workers) until a dedicated
# queue is justified. Flagged as an assumption in the Week 1 report.
SCAN_PIPELINE: list[PipelineStage] = [
    PipelineStage("verify_target", "recon", True),
    PipelineStage("dns_enum", "recon", True),
    PipelineStage("subdomain_enum", "recon", True),
    PipelineStage("port_scan", "recon", True),
    PipelineStage("http_probe", "recon", True),
    PipelineStage("tech_fingerprint", "recon", True),
    PipelineStage("crawl", "crawl", True),
    PipelineStage("js_secret_scan", "crawl", True),
    PipelineStage("nuclei_scan", "vuln", False),
    PipelineStage("ai_triage", "recon", False),
    PipelineStage("enrichment", "recon", False),
    PipelineStage("generate_report", "recon", False),
    PipelineStage("notify_user", "recon", False),
]


# ---------------------------------------------------------------------------
# Lazy contract imports (kept lazy so importing the workers needs no DB)
# ---------------------------------------------------------------------------


def _load_store() -> Store:
    """Load the active store (``app.db.get_store`` — NOT ``app.db.store``,
    which only holds the ``Store`` protocol)."""
    from app.db import get_store

    return get_store()


def _recheck_verification(domain: str, token_hash: str, method: str | None) -> bool:
    """Re-check ownership against the STORED token hash.

    Uses ``check_verification_hash`` (the router path — the raw token is
    gone by verification time). Raises ValueError on an unknown/None
    method; callers turn that into a clean refusal, not a retry.
    """
    from app.services.verification import check_verification_hash

    matched, _published = check_verification_hash(domain, token_hash, method or "")
    return matched


def _assert_verification_url_safe(domain: str) -> None:
    """Worker-side SSRF pre-check on the file-method verification URL.

    The fetch itself happens inside ``check_verification_hash`` via the
    guarded ``safe_get``; this is defence in depth and raises
    ``UnsafeUrlError`` before any outbound request when the URL is unsafe.
    """
    from app.core.ssrf import assert_url_safe

    assert_url_safe(f"https://{normalize_domain(domain)}/.well-known/scan-verify.txt")


def _is_unsafe_url_error(exc: BaseException) -> bool:
    """True when ``exc`` is the SSRF guard's refusal (fail-closed)."""
    from app.core.ssrf import UnsafeUrlError

    return isinstance(exc, UnsafeUrlError)


# ---------------------------------------------------------------------------
# Row helpers (store rows are dataclasses with attribute access)
# ---------------------------------------------------------------------------


def _row_get(row: Any, name: str, default: Any = None) -> Any:
    if row is None:
        return default
    if isinstance(row, dict):
        return row.get(name, default)
    return getattr(row, name, default)


def _parse_stored_result(row: Any) -> dict[str, Any]:
    """Recover a previously stored task result from the job row.

    Results are stored as JSON in the row's ``log`` field. A row whose
    log is not JSON still counts as done — return the fallback marker.
    """
    log = _row_get(row, "log")
    if isinstance(log, str) and log:
        try:
            parsed = json.loads(log)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            return parsed
    return {
        "status": "done",
        "stage": _row_get(row, "stage"),
        "scan_id": str(_row_get(row, "scan_id")),
        "cached": True,
    }


def _set_target_verification(store: Store, user_id: UUID, target_id: UUID, status: str) -> None:
    """Persist ``target.verification_status`` via the store contract."""
    store.update_target_verification(
        user_id,
        target_id,
        status=status,
        verified_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Idempotent base task
# ---------------------------------------------------------------------------


class IdempotentTask(Task):  # type: ignore[misc]
    """Base task with idempotency, retries and DLQ-on-final-failure.

    Subclasses / decorated tasks set ``stage`` (the pipeline stage name).
    The first two positional arguments (or ``scan_id`` / ``user_id``
    kwargs) must be the scan id and the owning user id, as strings —
    the tenant-scoped store needs ``user_id`` for every call.
    """

    abstract = True
    stage: str = ""

    # Retry policy — blueprint §1.5. See the module docstring for why the
    # realised delays are 60/120/240 s rather than the nominal 60/300/900 s.
    autoretry_for: tuple[type[Exception], ...] = (Exception,)
    retry_backoff: int = 60
    retry_backoff_max: int = 900
    retry_jitter: bool = False
    max_retries: int = 3

    # -- plumbing ------------------------------------------------------------

    def _ids_from(
        self, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        scan_id: str | None = None
        user_id: str | None = None
        if args and isinstance(args[0], str):
            scan_id = args[0]
        elif isinstance(kwargs.get("scan_id"), str):
            scan_id = kwargs["scan_id"]
        if len(args) > 1 and isinstance(args[1], str):
            user_id = args[1]
        elif isinstance(kwargs.get("user_id"), str):
            user_id = kwargs["user_id"]
        return scan_id, user_id

    def _heartbeat_fresh(self, job: Any) -> bool:
        """True when a ``running`` job row has a recent heartbeat.

        The heartbeat is the row's ``started_at`` (refreshed on every
        attempt start); the schema has no dedicated heartbeat column.
        A missing or unparsable timestamp counts as stale, so a crashed
        attempt can always be retried.
        """
        started_at = _row_get(job, "started_at")
        if started_at is None:
            return False
        if isinstance(started_at, str):
            try:
                started = datetime.fromisoformat(started_at)
            except ValueError:
                return False
        elif isinstance(started_at, datetime):
            started = started_at
        else:
            return False
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - started < timedelta(seconds=HEARTBEAT_FRESH_SECONDS)

    def _cached_result(
        self, store: Store, user_id: UUID, key: str, scan_id: str
    ) -> dict[str, Any] | None:
        """Return a cached result / skip marker, or None to proceed."""
        job = store.get_scan_job_by_key(user_id, key)
        if job is None:
            return None
        status = _row_get(job, "status")
        if status == "done":
            result = _parse_stored_result(job)
            result.setdefault("cached", True)
            return result
        if status == "running" and self._heartbeat_fresh(job):
            request_id = getattr(self.request, "id", None)
            if _row_get(job, "celery_task_id") != request_id:
                return {
                    "status": "skipped",
                    "reason": "already_running",
                    "stage": self.stage,
                    "scan_id": scan_id,
                    "cached": True,
                }
        return None

    def _ensure_job_row(self, store: Store, user_id: UUID, scan_id: UUID, key: str) -> None:
        """Create the job row (or refresh the heartbeat on a re-run)."""
        job = store.get_scan_job_by_key(user_id, key)
        now = datetime.now(timezone.utc)
        if job is not None:
            store.update_scan_job(user_id, job.id, status="running", started_at=now)
            return
        job = store.create_scan_job(user_id, scan_id, self.stage, key)
        task_id = getattr(self.request, "id", None) or key
        store.update_scan_job(
            user_id,
            job.id,
            status="running",
            celery_task_id=task_id,
            started_at=now,
        )

    def _mark_job_done(self, store: Store, user_id: UUID, key: str, result: Any) -> None:
        job = store.get_scan_job_by_key(user_id, key)
        if job is None:
            logger.warning("no scan_jobs row for key %s; result not stored", key)
            return
        store.update_scan_job(
            user_id,
            job.id,
            status="done",
            finished_at=datetime.now(timezone.utc),
            log=json.dumps(result, default=str),
        )

    # -- Celery hooks --------------------------------------------------------

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        scan_id, user_id = self._ids_from(args, kwargs)
        if scan_id is None or user_id is None or not self.stage:
            return super().__call__(*args, **kwargs)
        store = _load_store()
        user_uuid = _coerce_uuid(user_id)
        scan_uuid = _coerce_uuid(scan_id)
        scan = store.get_scan(user_uuid, scan_uuid)
        if scan is None:
            raise ValueError(f"scan not found: {scan_id}")
        target = store.get_target(user_uuid, scan.target_id)
        if target is None:
            raise ValueError(f"target not found for scan: {scan_id}")
        key = idempotency_key(scan_id, self.stage, target.domain)
        cached = self._cached_result(store, user_uuid, key, scan_id)
        if cached is not None:
            return cached
        self._ensure_job_row(store, user_uuid, scan_uuid, key)
        result = super().__call__(*args, **kwargs)
        self._mark_job_done(store, user_uuid, key, result)
        # B2 chaining lives HERE, not in the task bodies: the next stage
        # is enqueued only after this stage's result is persisted, so a
        # chained stage that reads this stage's job log (port_scan /
        # http_probe / crawl read subdomain_enum's log) always sees it —
        # including in eager mode, where the child runs synchronously
        # inside this call. A cached re-run returns above, so it never
        # re-enqueues; a refusal (status "refused") enqueues nothing.
        # A chaining failure never fails this stage (its result is
        # already stored): it is logged, and the child records its own
        # failure via on_failure/DLQ when it runs.
        if isinstance(result, dict) and result.get("status") in ("done", "verified"):
            try:
                _enqueue_next_stage(self.stage, scan_id, user_id, target.domain)
            except Exception:
                logger.exception(
                    "chaining failed after %s for scan %s",
                    self.stage,
                    scan_id,
                )
        return result

    def on_failure(
        self,
        exc: BaseException,
        task_id: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        einfo: Any,
    ) -> None:
        """Final failure (retries exhausted): DLQ + scan marked failed.

        Never raises: a failure in the failure handler must not mask the
        original error.
        """
        scan_id, user_id = self._ids_from(args or (), kwargs or {})
        if scan_id is not None and user_id is not None and self.stage:
            error = str(exc) or exc.__class__.__name__
            try:
                store = _load_store()
                user_uuid = _coerce_uuid(user_id)
                scan_uuid = _coerce_uuid(scan_id)
                scan = store.get_scan(user_uuid, scan_uuid)
                target = store.get_target(user_uuid, scan.target_id) if scan is not None else None
                domain = target.domain if target is not None else ""
                payload: dict[str, Any] = {
                    "scan_id": scan_id,
                    "stage": self.stage,
                    "domain": domain,
                    "task_id": task_id,
                }
                send_to_dlq(scan_id, self.stage, payload, error)
                store.update_scan(
                    user_uuid,
                    scan_uuid,
                    status="failed",
                    error=f"{self.stage} failed: {error}",
                    finished_at=datetime.now(timezone.utc),
                )
                if target is not None:
                    key = idempotency_key(scan_id, self.stage, domain)
                    job = store.get_scan_job_by_key(user_uuid, key)
                    if job is not None:
                        store.update_scan_job(
                            user_uuid,
                            job.id,
                            status="failed",
                            finished_at=datetime.now(timezone.utc),
                            log=error,
                        )
            except Exception:
                logger.exception(
                    "on_failure: could not record failure for scan %s stage %s",
                    scan_id,
                    self.stage,
                )
        super().on_failure(exc, task_id, args, kwargs, einfo)


# ---------------------------------------------------------------------------
# verify_target — the ONLY implemented stage in Week 1 (queue: recon)
# ---------------------------------------------------------------------------


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.recon.verify_target",
    stage="verify_target",
    time_limit=120,  # recon is 2 s/host per task; a re-check is one fetch.
)
def verify_target(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """Re-check target ownership before any scanning stage runs.

    Worker-side verification gate (docs/testing.md §4): if the target is
    not ``verified`` the task REFUSES to run — the scan is marked
    ``failed`` with ``TARGET_NOT_VERIFIED``, an audit log is written, and
    the function returns WITHOUT any outbound request (in particular,
    the verification re-check is never called for an unverified target).

    Otherwise ownership is re-checked live against the stored token hash;
    on success the target stays ``verified`` and the scan moves to
    ``recon``.
    """
    store = _load_store()
    user_uuid = _coerce_uuid(user_id)
    scan_uuid = _coerce_uuid(scan_id)
    scan = store.get_scan(user_uuid, scan_uuid)
    if scan is None:
        raise ValueError(f"scan not found: {scan_id}")
    target = store.get_target(user_uuid, scan.target_id)
    if target is None:
        raise ValueError(f"target not found for scan: {scan_id}")
    domain = target.domain
    target_id = target.id
    verification_status = target.verification_status
    now = datetime.now(timezone.utc)

    if verification_status != "verified":
        store.update_scan(
            user_uuid,
            scan_uuid,
            status="failed",
            error="TARGET_NOT_VERIFIED",
            finished_at=now,
        )
        store.log_audit(
            user_uuid,
            "scan_refused_unverified_target",
            domain,
            {
                "scan_id_hash": hash_resource_id(scan_id),
                "stage": "verify_target",
                "verification_status": verification_status,
            },
        )
        logger.warning(
            "verify_target refused scan %s: target %s is %s (not verified)",
            scan_id,
            domain,
            verification_status,
        )
        return {
            "status": "refused",
            "error": "TARGET_NOT_VERIFIED",
            "scan_id": scan_id,
            "target_id": str(target_id),
            "domain": domain,
        }

    # Verified on record — re-check live. For the file method, run the
    # worker-side SSRF pre-check first; an unsafe URL is a clean refusal
    # (fail closed), while any other pre-check failure (e.g. transient
    # DNS) falls through to the service check, which handles it
    # gracefully. The outbound fetch itself happens inside
    # check_verification_hash via the guarded safe_get.
    if target.verification_method == "file":
        try:
            _assert_verification_url_safe(domain)
        except Exception as exc:
            if _is_unsafe_url_error(exc):
                store.update_scan(
                    user_uuid,
                    scan_uuid,
                    status="failed",
                    error="TARGET_UNSAFE_URL",
                    finished_at=now,
                )
                store.log_audit(
                    user_uuid,
                    "scan_refused_unsafe_target",
                    domain,
                    {"scan_id_hash": hash_resource_id(scan_id), "stage": "verify_target"},
                )
                logger.warning(
                    "verify_target refused scan %s: verification URL for %s is SSRF-unsafe",
                    scan_id,
                    domain,
                )
                return {
                    "status": "refused",
                    "error": "TARGET_UNSAFE_URL",
                    "scan_id": scan_id,
                    "target_id": str(target_id),
                    "domain": domain,
                }
            logger.warning(
                "SSRF pre-check inconclusive for %s (%s); continuing to the service check",
                domain,
                exc,
            )
    try:
        matched = _recheck_verification(
            domain,
            target.verification_token_hash,
            target.verification_method,
        )
    except ValueError:
        # Unknown/None method — a corrupt row, not a transient failure:
        # refuse cleanly instead of burning 3 retries on it.
        store.update_scan(
            user_uuid,
            scan_uuid,
            status="failed",
            error="TARGET_VERIFICATION_FAILED",
            finished_at=now,
        )
        store.log_audit(
            user_uuid,
            "scan_refused_verification_failed",
            domain,
            {
                "scan_id_hash": hash_resource_id(scan_id),
                "stage": "verify_target",
                "reason": "unknown_method",
            },
        )
        return {
            "status": "refused",
            "error": "TARGET_VERIFICATION_FAILED",
            "scan_id": scan_id,
            "target_id": str(target_id),
            "domain": domain,
        }
    if not matched:
        store.update_scan(
            user_uuid,
            scan_uuid,
            status="failed",
            error="TARGET_VERIFICATION_FAILED",
            finished_at=now,
        )
        store.log_audit(
            user_uuid,
            "scan_refused_verification_failed",
            domain,
            {"scan_id_hash": hash_resource_id(scan_id), "stage": "verify_target"},
        )
        logger.warning(
            "verify_target refused scan %s: live re-check failed for %s",
            scan_id,
            domain,
        )
        return {
            "status": "refused",
            "error": "TARGET_VERIFICATION_FAILED",
            "scan_id": scan_id,
            "target_id": str(target_id),
            "domain": domain,
        }

    _set_target_verification(store, user_uuid, target_id, "verified")
    store.update_scan(user_uuid, scan_uuid, status="recon")
    # B2 chaining happens in IdempotentTask.__call__ after this result
    # is persisted (dns_enum next).
    return {
        "status": "verified",
        "scan_id": scan_id,
        "target_id": str(target_id),
        "domain": domain,
    }


# ---------------------------------------------------------------------------
# Week 2 — recon stages (docs/week-2-plan.md)
#
# Every stage re-checks target.verification_status == "verified" before
# ANY outbound request and refuses cleanly (scan failed, audit log, no
# runner call) when unverified — the same refusal pattern as
# verify_target. Stages chain via IdempotentTask.__call__ (after the
# fresh result is persisted — see _enqueue_next_stage at the end of
# this module); dispatch.py still enqueues only verify_target.
# ---------------------------------------------------------------------------


def _load_scan_and_target(store: Store, scan_id: str, user_id: str) -> tuple[UUID, UUID, Any, Any]:
    """Load (user_uuid, scan_uuid, scan, target) or raise ValueError."""
    user_uuid = _coerce_uuid(user_id)
    scan_uuid = _coerce_uuid(scan_id)
    scan = store.get_scan(user_uuid, scan_uuid)
    if scan is None:
        raise ValueError(f"scan not found: {scan_id}")
    target = store.get_target(user_uuid, scan.target_id)
    if target is None:
        raise ValueError(f"target not found for scan: {scan_id}")
    return user_uuid, scan_uuid, scan, target


def _refuse_unverified_target(
    store: Store, user_uuid: UUID, scan_uuid: UUID, target: Any, stage: str
) -> dict[str, Any]:
    """Refuse a recon stage for an unverified target (no outbound call).

    Mirrors verify_target's refusal: scan marked failed with
    TARGET_NOT_VERIFIED, audit log with the HASHED scan id, warning
    logged. The returned dict is stored as the job result by the base
    task, so a redelivery returns the stored refusal.
    """
    now = datetime.now(timezone.utc)
    store.update_scan(
        user_uuid,
        scan_uuid,
        status="failed",
        error="TARGET_NOT_VERIFIED",
        finished_at=now,
    )
    store.log_audit(
        user_uuid,
        "scan_refused_unverified_target",
        target.domain,
        {
            "scan_id_hash": hash_resource_id(str(scan_uuid)),
            "stage": stage,
            "verification_status": target.verification_status,
        },
    )
    logger.warning(
        "%s refused scan %s: target %s is %s (not verified)",
        stage,
        scan_uuid,
        target.domain,
        target.verification_status,
    )
    return {
        "status": "refused",
        "error": "TARGET_NOT_VERIFIED",
        "scan_id": str(scan_uuid),
        "target_id": str(target.id),
        "domain": target.domain,
    }


def _prior_stage_result(
    store: Store, user_uuid: UUID, scan_id: str, stage: str, domain: str
) -> dict[str, Any] | None:
    """The stored result dict of a prior stage's job row, or None.

    A missing row, a non-JSON log, or a non-dict log all read as "no
    prior result" — callers hash over what exists instead of failing.
    """
    key = idempotency_key(scan_id, stage, domain)
    job = store.get_scan_job_by_key(user_uuid, key)
    if job is None:
        return None
    log = _row_get(job, "log")
    if isinstance(log, str) and log:
        try:
            parsed = json.loads(log)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def compute_attack_surface_hash(snapshot: dict[str, Any]) -> str:
    """SHA-256 hex of the canonical JSON of an attack-surface snapshot.

    Canonical form: sorted keys, compact separators, so the same
    snapshot hashes identically regardless of construction order (the
    Week 4 diff compares these hashes across scans of one target).
    """
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _cap_stored_list(items: list[str], limit: int) -> tuple[list[str], bool, int]:
    """Truncate a stored list deterministically (M4 review fix).

    Returns ``(kept, truncated, total)`` where ``kept`` is the first
    ``limit`` items of the (already sorted) list. Callers store
    ``truncated`` + ``total`` alongside the capped list.
    """
    total = len(items)
    if total <= limit:
        return items, False, total
    return items[:limit], True, total


def _hosts_for_stage(
    store: Store, user_uuid: UUID, scan_id: str, domain: str
) -> tuple[list[str], bool]:
    """Hosts for port_scan / http_probe / crawl (B2 review fix).

    Reads the ``subdomain_enum`` (then ``dns_enum``) job logs, dedupes,
    sorts with the apex domain first, and caps at
    ``_MAX_HOSTS_PER_STAGE``. With no prior log at all, falls back to
    ``[domain]`` and reports ``True`` so the caller can record
    ``"hosts_fallback_apex": true``.
    """
    found: set[str] = set()
    for stage in ("subdomain_enum", "dns_enum"):
        prior = _prior_stage_result(store, user_uuid, scan_id, stage, domain)
        if prior is None:
            continue
        subdomains = prior.get("subdomains")
        if isinstance(subdomains, list):
            for item in subdomains:
                if isinstance(item, str) and item.strip():
                    found.add(item.strip())
    if not found:
        return [domain], True
    ordered = sorted(found, key=lambda host: (0 if host == domain else 1, host))
    return ordered[:_MAX_HOSTS_PER_STAGE], False


def _refuse_stage_error(
    store: Store,
    user_uuid: UUID,
    scan_uuid: UUID,
    target: Any,
    stage: str,
    error_code: str,
    exc: BaseException,
) -> dict[str, Any]:
    """Refuse a recon stage on a deterministic failure (M2 review fix).

    Mirrors verify_target's refusal pattern: the scan is marked failed
    with the error code, an audit log is written (hashed scan id), and
    the returned dict is stored as the job result — so a redelivery
    returns the stored refusal instead of re-running. The exception
    detail goes only to the log line, never into the stored result
    (the agent's error text may echo target-served content).
    """
    now = datetime.now(timezone.utc)
    store.update_scan(
        user_uuid,
        scan_uuid,
        status="failed",
        error=error_code,
        finished_at=now,
    )
    store.log_audit(
        user_uuid,
        "scan_stage_refused",
        target.domain,
        {
            "scan_id_hash": hash_resource_id(str(scan_uuid)),
            "stage": stage,
            "error": error_code,
        },
    )
    # R4 re-review fix: log only the error code + exception class, never
    # the exception message — it can name a resolved IP (e.g. an SSRF
    # refusal naming 169.254.169.254), which must not sit in worker logs.
    logger.warning(
        "%s refused scan %s: %s (%s)",
        stage,
        scan_uuid,
        error_code,
        type(exc).__name__,
    )
    return {
        "status": "refused",
        "error": error_code,
        "scan_id": str(scan_uuid),
        "target_id": str(target.id),
        "domain": target.domain,
    }


def _call_agent_stage(
    store: Store,
    user_uuid: UUID,
    scan_uuid: UUID,
    target: Any,
    stage: str,
    domain: str,
    **runner_kwargs: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Run one agent stage, turning deterministic failures into refusals.

    Returns ``(outcome, None)`` on success or ``(None, refusal)`` on a
    deterministic failure (M2): an SSRF refusal (``SSRF_REFUSED``), a
    missing/unexecutable agent binary (``AGENT_UNAVAILABLE``), or an
    agent stage failure (``AGENT_STAGE_FAILED`` — re-running the same
    stage against the same target would fail the same way). A refused
    stage does NOT raise, so Celery never burns its 3 retries on it.

    Still raises (transient, worth retrying): :class:`ScannerAgentTimeout`
    and ``OSError`` from the transport.
    """
    try:
        return run_stage(stage, domain, **runner_kwargs), None
    except ScannerAgentTimeout:
        raise
    except UnsafeUrlError as exc:
        return None, _refuse_stage_error(
            store, user_uuid, scan_uuid, target, stage, "SSRF_REFUSED", exc
        )
    except ScannerAgentUnavailable as exc:
        return None, _refuse_stage_error(
            store, user_uuid, scan_uuid, target, stage, "AGENT_UNAVAILABLE", exc
        )
    except ScannerAgentError as exc:
        return None, _refuse_stage_error(
            store, user_uuid, scan_uuid, target, stage, "AGENT_STAGE_FAILED", exc
        )


def _parse_robots_disallow(robots_text: str) -> list[str]:
    """``Disallow`` paths applying to ``User-agent: *`` in robots.txt.

    Only the ``*`` group is honoured (the scanner has no named
    user-agent); a group ends when another ``User-agent:`` line starts.
    Comments (``# ...``) are stripped; an empty ``Disallow:`` allows
    everything and contributes no rule.
    """
    disallowed: list[str] = []
    in_star_group = False
    for raw_line in robots_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            in_star_group = value == "*"
        elif field == "disallow" and in_star_group and value:
            disallowed.append(value)
    return disallowed


def _robots_filter(urls: list[str], disallowed: list[str]) -> tuple[list[str], int]:
    """Drop URLs whose path starts with a robots ``Disallow`` prefix.

    Returns ``(kept, removed_count)``. Prefix match on the URL path
    only (``Disallow: /private/`` blocks ``/private/x`` but not
    ``/private`` without the trailing slash — the robots.txt rule as
    written).
    """
    if not disallowed:
        return urls, 0
    kept: list[str] = []
    removed = 0
    for url in urls:
        path = urlparse(url).path or "/"
        if any(path.startswith(rule) for rule in disallowed):
            removed += 1
        else:
            kept.append(url)
    return kept, removed


def _is_same_domain_or_subdomain(host: str, domain: str) -> bool:
    """True when ``host`` is ``domain`` or a subdomain of it (M6).

    Suffix match on the normalized target domain: ``evil-example.com``
    does NOT match ``example.com`` (the dot boundary matters).
    """
    host = host.lower().rstrip(".")
    domain = normalize_domain(domain)
    return host == domain or host.endswith(f".{domain}")


# -- tolerant result extraction (the agent's data shapes are its own) ------


def _extract_subdomains(results: list[Any]) -> list[str]:
    """Deduped, sorted subdomain list from agent ``result`` data payloads.

    Accepts ``{"subdomains": [...]}``, ``{"hosts": [...]}`` (strings or
    ``{"host": ...}`` dicts), and bare ``{"host"/"hostname"/"subdomain"}``
    records — whichever shape the agent emits.
    """
    found: set[str] = set()
    for entry in results:
        if isinstance(entry, str):
            found.add(entry)
            continue
        if not isinstance(entry, dict):
            continue
        for key in ("subdomains", "hosts"):
            value = entry.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        found.add(item)
                    elif isinstance(item, dict):
                        for host_key in ("host", "hostname", "subdomain", "name"):
                            host_value = item.get(host_key)
                            if isinstance(host_value, str):
                                found.add(host_value)
        for key in ("host", "hostname", "subdomain", "name"):
            value = entry.get(key)
            if isinstance(value, str):
                found.add(value)
    return sorted(found)


def _extract_open_ports(results: list[Any]) -> list[dict[str, Any]]:
    """Deduped, sorted ``{"host", "port"}`` list from agent port data.

    Accepts ``{"host": ..., "open_ports": [80, ...]}``,
    ``{"host": ..., "ports": [{"port": ...}]}``, and single
    ``{"host": ..., "port": ...}`` records.
    """
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for entry in results:
        if not isinstance(entry, dict):
            continue
        host = entry.get("host") or entry.get("hostname")
        if not isinstance(host, str):
            continue
        ports: list[Any] = []
        for key in ("open_ports", "ports"):
            value = entry.get(key)
            if isinstance(value, list):
                ports.extend(value)
        if isinstance(entry.get("port"), int):
            ports.append(entry["port"])
        for item in ports:
            port = (
                item
                if isinstance(item, int)
                else item.get("port")
                if isinstance(item, dict)
                else None
            )
            if isinstance(port, int) and (host, port) not in seen:
                seen.add((host, port))
                found.append({"host": host, "port": port})
    return sorted(found, key=lambda item: (str(item["host"]), int(item["port"])))


def _extract_live_hosts(results: list[Any], logs: list[str]) -> tuple[list[dict[str, Any]], bool]:
    """Live-host records + whether the agent reported screenshots off.

    Each host: ``host`` / ``status`` / ``status_code`` / ``title`` /
    ``ip`` / ``tls`` / ``headers`` (missing fields become None / {}) plus
    the agent's own fields passed through verbatim: ``technologies``
    (the agent's key — NOT renamed to ``tech``), ``webserver``,
    ``content_type`` and ``url`` (B3 contract fix: the Python side must
    not drop what the agent emits, or the fingerprint stage loses it).
    The ``screenshot_unavailable`` marker is read from result data first,
    then from the agent's log lines.

    NOTE (M14 — stored-XSS surface): the page ``title`` is stored
    verbatim here. It is target-controlled text and MUST be HTML-escaped
    by the Week 4 UI on render — never injected into HTML unescaped.
    """
    hosts: list[dict[str, Any]] = []
    screenshot_unavailable = any("screenshot_unavailable" in line for line in logs)
    for entry in results:
        if not isinstance(entry, dict):
            continue
        if entry.get("screenshot_unavailable") is True:
            screenshot_unavailable = True
        host = entry.get("host") or entry.get("hostname") or entry.get("url")
        if not isinstance(host, str):
            continue
        tls = entry.get("tls")
        headers = entry.get("headers")
        technologies = entry.get("technologies")
        webserver = entry.get("webserver")
        content_type = entry.get("content_type")
        status_code = entry.get("status_code")
        if status_code is None:
            status_code = entry.get("status")
        hosts.append(
            {
                "host": host,
                "status": entry.get("status"),
                "status_code": status_code if isinstance(status_code, int) else None,
                "title": entry.get("title"),
                "ip": entry.get("ip"),
                "tls": tls if isinstance(tls, dict) else {},
                "headers": headers if isinstance(headers, dict) else {},
                "technologies": (
                    [item for item in technologies if isinstance(item, str)]
                    if isinstance(technologies, list)
                    else []
                ),
                "webserver": webserver if isinstance(webserver, str) else None,
                "content_type": content_type if isinstance(content_type, str) else None,
                "url": entry.get("url") if isinstance(entry.get("url"), str) else None,
            }
        )
    return hosts, screenshot_unavailable


def _extract_crawl(results: list[Any]) -> tuple[list[str], list[str]]:
    """(sorted URLs, sorted JS file URLs) from agent crawl data."""
    urls: set[str] = set()
    js_files: set[str] = set()
    for entry in results:
        if not isinstance(entry, dict):
            continue
        value = entry.get("urls")
        if isinstance(value, list):
            urls.update(item for item in value if isinstance(item, str))
        for key in ("js_files", "js"):
            value = entry.get(key)
            if isinstance(value, list):
                js_files.update(item for item in value if isinstance(item, str))
        url = entry.get("url")
        if isinstance(url, str):
            urls.add(url)
            if url.lower().split("?", 1)[0].endswith(".js"):
                js_files.add(url)
    return sorted(urls), sorted(js_files)


# -- recon tasks -------------------------------------------------------------

# NOTE on task names: the brief names every recon task
# ``websurfacehq.recon.<stage>``. That routes the two crawl-queue stages
# (crawl, js_secret_scan) to the ``recon`` queue under celery_app's
# ``*.recon.*`` route, not the ``crawl`` queue SCAN_PIPELINE lists for
# them. The per-task time_limit below still applies; renaming to
# ``websurfacehq.crawl.<stage>`` is a one-line change for the parent
# when dispatch starts enqueuing these stages.


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.recon.dns_enum",
    stage="dns_enum",
    time_limit=300,
)
def dns_enum(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """DNS enumeration via the agent (crt.sh + Go stdlib DNS).

    Stores the subdomain list in the job log; no findings (subdomains
    are structure, not vulnerabilities).
    """
    store = _load_store()
    user_uuid, scan_uuid, _scan, target = _load_scan_and_target(store, scan_id, user_id)
    if target.verification_status != "verified":
        return _refuse_unverified_target(store, user_uuid, scan_uuid, target, "dns_enum")
    domain = target.domain
    outcome, refusal = _call_agent_stage(
        store, user_uuid, scan_uuid, target, "dns_enum", domain, timeout_seconds=300
    )
    if refusal is not None:
        return refusal
    assert outcome is not None
    subdomains, truncated, total = _cap_stored_list(
        _extract_subdomains(outcome["results"]), _MAX_STORED_SUBDOMAINS
    )
    result = {
        "status": "done",
        "stage": "dns_enum",
        "scan_id": scan_id,
        "target_id": str(target.id),
        "domain": domain,
        "subdomains": subdomains,
        "count": len(subdomains),
        "total_count": total,
        "truncated": truncated,
        "counts": outcome["counts"],
    }
    return result


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.recon.subdomain_enum",
    stage="subdomain_enum",
    time_limit=300,
)
def subdomain_enum(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """Subdomain enumeration via the agent (subfinder); deduped + sorted."""
    store = _load_store()
    user_uuid, scan_uuid, _scan, target = _load_scan_and_target(store, scan_id, user_id)
    if target.verification_status != "verified":
        return _refuse_unverified_target(store, user_uuid, scan_uuid, target, "subdomain_enum")
    domain = target.domain
    outcome, refusal = _call_agent_stage(
        store, user_uuid, scan_uuid, target, "subdomain_enum", domain, timeout_seconds=300
    )
    if refusal is not None:
        return refusal
    assert outcome is not None
    subdomains, truncated, total = _cap_stored_list(
        _extract_subdomains(outcome["results"]), _MAX_STORED_SUBDOMAINS
    )
    result = {
        "status": "done",
        "stage": "subdomain_enum",
        "scan_id": scan_id,
        "target_id": str(target.id),
        "domain": domain,
        "subdomains": subdomains,
        "count": len(subdomains),
        "total_count": total,
        "truncated": truncated,
        "counts": outcome["counts"],
    }
    return result


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.recon.port_scan",
    stage="port_scan",
    time_limit=600,
)
def port_scan(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """Port scan via the agent (naabu connect scan).

    Open ports other than 80/443 each become one info-severity finding
    (template ``recon-open-port``); evidence is host + port ONLY — no
    banner content, which could contain secrets.
    """
    store = _load_store()
    user_uuid, scan_uuid, _scan, target = _load_scan_and_target(store, scan_id, user_id)
    if target.verification_status != "verified":
        return _refuse_unverified_target(store, user_uuid, scan_uuid, target, "port_scan")
    domain = target.domain
    hosts, hosts_fallback = _hosts_for_stage(store, user_uuid, scan_id, domain)
    outcome, refusal = _call_agent_stage(
        store,
        user_uuid,
        scan_uuid,
        target,
        "port_scan",
        domain,
        hosts=hosts,
        timeout_seconds=600,
    )
    if refusal is not None:
        return refusal
    assert outcome is not None
    open_ports = _extract_open_ports(outcome["results"])
    # R2 re-review fix: cap the stored open-ports list like every other
    # stored list (M4, 5,000); the per-port findings are capped with it.
    total_open_ports = len(open_ports)
    open_ports_truncated = total_open_ports > _MAX_STORED_URLS
    if open_ports_truncated:
        open_ports = open_ports[:_MAX_STORED_URLS]
    findings_created = 0
    for item in open_ports:
        if item["port"] in (80, 443):
            continue
        store.create_finding(
            user_uuid,
            scan_uuid,
            target.id,
            "recon-open-port",
            f"Open port {item['port']} on {item['host']}",
            "info",
            evidence=f"host={item['host']} port={item['port']}",
        )
        findings_created += 1
    result = {
        "status": "done",
        "stage": "port_scan",
        "scan_id": scan_id,
        "target_id": str(target.id),
        "domain": domain,
        "hosts": hosts,
        "hosts_fallback_apex": hosts_fallback,
        "open_ports": open_ports,
        "open_ports_total": total_open_ports,
        "open_ports_truncated": open_ports_truncated,
        "count": len(open_ports),
        "findings_created": findings_created,
        "counts": outcome["counts"],
    }
    return result


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.recon.http_probe",
    stage="http_probe",
    time_limit=600,
)
def http_probe(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """HTTP probe via the agent (httpx): live hosts, status, title, TLS.

    Records a ``screenshot_unavailable`` marker when the agent reports
    screenshots are off — never a fabricated image.
    """
    store = _load_store()
    user_uuid, scan_uuid, _scan, target = _load_scan_and_target(store, scan_id, user_id)
    if target.verification_status != "verified":
        return _refuse_unverified_target(store, user_uuid, scan_uuid, target, "http_probe")
    domain = target.domain
    hosts, hosts_fallback = _hosts_for_stage(store, user_uuid, scan_id, domain)
    outcome, refusal = _call_agent_stage(
        store,
        user_uuid,
        scan_uuid,
        target,
        "http_probe",
        domain,
        hosts=hosts,
        timeout_seconds=600,
    )
    if refusal is not None:
        return refusal
    assert outcome is not None
    hosts_found, screenshot_unavailable = _extract_live_hosts(outcome["results"], outcome["logs"])
    result = {
        "status": "done",
        "stage": "http_probe",
        "scan_id": scan_id,
        "target_id": str(target.id),
        "domain": domain,
        "hosts": hosts_found,
        "probed_hosts": hosts,
        "hosts_fallback_apex": hosts_fallback,
        "count": len(hosts_found),
        "screenshot_unavailable": screenshot_unavailable,
        "counts": outcome["counts"],
    }
    return result


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.recon.tech_fingerprint",
    stage="tech_fingerprint",
    time_limit=300,
)
def tech_fingerprint(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """Tech fingerprint + attack-surface snapshot hash (no outbound fetch).

    Derives technologies from the stored ``http_probe`` job log via
    ``app.services.techprint.fingerprint``, then hashes the snapshot: sorted subdomains
    (from ``subdomain_enum``) + sorted open ports (from ``port_scan``) +
    tech stack + TLS summary. A missing/unparseable prior stage never
    fails this stage: the hash covers what exists and the result records
    ``snapshot_partial`` with the missing stages listed.
    """
    store = _load_store()
    user_uuid, scan_uuid, _scan, target = _load_scan_and_target(store, scan_id, user_id)
    if target.verification_status != "verified":
        return _refuse_unverified_target(store, user_uuid, scan_uuid, target, "tech_fingerprint")
    domain = target.domain
    missing_stages: list[str] = []
    probe = _prior_stage_result(store, user_uuid, scan_id, "http_probe", domain)
    probe_hosts = probe.get("hosts") if probe else None
    if not isinstance(probe_hosts, list):
        probe_hosts = []
        missing_stages.append("http_probe")
    fingerprinted: list[dict[str, Any]] = []
    tech_names: set[str] = set()
    tls_summary: dict[str, Any] = {}
    for host_result in probe_hosts:
        if not isinstance(host_result, dict):
            continue
        printed = fingerprint(host_result)
        host = host_result.get("host")
        fingerprinted.append({"host": host, **printed})
        for tech in printed.get("technologies", []):
            # techprint returns plain names; tolerate the {"name": ...}
            # dict form too so a future shape change stays compatible.
            if isinstance(tech, str):
                tech_names.add(tech)
            elif isinstance(tech, dict) and isinstance(tech.get("name"), str):
                tech_names.add(str(tech["name"]))
        if isinstance(host, str):
            tls_summary[host] = printed.get("tls", {})

    subdomains: list[str] | None = None
    sub_result = _prior_stage_result(store, user_uuid, scan_id, "subdomain_enum", domain)
    if sub_result is not None and isinstance(sub_result.get("subdomains"), list):
        subdomains = sorted(str(item) for item in sub_result["subdomains"])
    else:
        missing_stages.append("subdomain_enum")

    open_ports: list[dict[str, Any]] | None = None
    port_result = _prior_stage_result(store, user_uuid, scan_id, "port_scan", domain)
    if port_result is not None and isinstance(port_result.get("open_ports"), list):
        open_ports = sorted(
            (item for item in port_result["open_ports"] if isinstance(item, dict)),
            key=lambda item: (str(item.get("host", "")), int(item.get("port", 0) or 0)),
        )
    else:
        missing_stages.append("port_scan")

    snapshot = {
        "subdomains": subdomains or [],
        "open_ports": open_ports or [],
        "technologies": sorted(tech_names),
        "tls": tls_summary,
        # M3 review fix: "partial" + "missing_stages" live INSIDE the
        # hashed snapshot, so a partial scan hashes differently from a
        # genuinely empty complete surface. The list is sorted so the
        # hash is order-independent.
        "partial": bool(missing_stages),
        "missing_stages": sorted(missing_stages),
    }
    attack_surface_hash = compute_attack_surface_hash(snapshot)
    result = {
        "status": "done",
        "stage": "tech_fingerprint",
        "scan_id": scan_id,
        "target_id": str(target.id),
        "domain": domain,
        "hosts": fingerprinted,
        "count": len(fingerprinted),
        "attack_surface_hash": attack_surface_hash,
        "snapshot_counts": {
            "subdomains": len(subdomains or []),
            "open_ports": len(open_ports or []),
            "technologies": len(tech_names),
            "hosts": len(fingerprinted),
        },
        "snapshot_partial": bool(missing_stages),
        "missing_stages": missing_stages,
    }
    return result


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.recon.crawl",
    stage="crawl",
    time_limit=600,
)
def crawl(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """Crawl via the agent (katana): URL list + JS file list in the log.

    Respects robots.txt (M7 review fix): ``/<domain>/robots.txt`` is
    fetched best-effort via the pinned transport before the katana run;
    ``Disallow`` rules for ``User-agent: *`` filter katana's returned
    URLs (prefix match on path) before anything is stored. A failed
    robots fetch is NOT fatal — the crawl proceeds and records
    ``robots_fetch_failed``. Katana itself is not asked to obey robots
    (it has no such flag); the filtering happens here, in Python.
    """
    store = _load_store()
    user_uuid, scan_uuid, _scan, target = _load_scan_and_target(store, scan_id, user_id)
    if target.verification_status != "verified":
        return _refuse_unverified_target(store, user_uuid, scan_uuid, target, "crawl")
    domain = target.domain

    robots_disallowed: list[str] = []
    robots_fetch_failed = False
    try:
        robots_response = pinned_get(
            f"https://{domain}/robots.txt", timeout=10.0, max_bytes=_JS_MAX_BYTES
        )
        if robots_response.status_code == 200:
            robots_disallowed = _parse_robots_disallow(robots_response.text)
    except Exception as exc:  # best effort: a missing robots.txt never fails the crawl
        robots_fetch_failed = True
        logger.warning("crawl: robots.txt fetch failed for %s: %s", domain, exc)

    hosts, hosts_fallback = _hosts_for_stage(store, user_uuid, scan_id, domain)
    outcome, refusal = _call_agent_stage(
        store,
        user_uuid,
        scan_uuid,
        target,
        "crawl",
        domain,
        hosts=hosts,
        timeout_seconds=600,
    )
    if refusal is not None:
        return refusal
    assert outcome is not None
    urls, js_files = _extract_crawl(outcome["results"])
    urls, robots_filtered_urls = _robots_filter(urls, robots_disallowed)
    js_files, robots_filtered_js = _robots_filter(js_files, robots_disallowed)
    urls, urls_truncated, total_urls = _cap_stored_list(urls, _MAX_STORED_URLS)
    js_files, js_truncated, total_js = _cap_stored_list(js_files, _MAX_STORED_URLS)
    result = {
        "status": "done",
        "stage": "crawl",
        "scan_id": scan_id,
        "target_id": str(target.id),
        "domain": domain,
        "hosts": hosts,
        "hosts_fallback_apex": hosts_fallback,
        "urls": urls,
        "js_files": js_files,
        "url_count": len(urls),
        "js_count": len(js_files),
        "total_url_count": total_urls,
        "total_js_count": total_js,
        "truncated": urls_truncated or js_truncated,
        "robots_fetch_failed": robots_fetch_failed,
        "robots_disallowed_filtered": robots_filtered_urls + robots_filtered_js,
        "counts": outcome["counts"],
    }
    return result


# JS fetch politeness (plan §3): 5 req/s per domain, 64 KiB per file,
# at most 50 JS files per scan.
_JS_MAX_FILES = 50
_JS_FETCH_DELAY_SECONDS = 0.2
_JS_MAX_BYTES = 65536


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.recon.js_secret_scan",
    stage="js_secret_scan",
    time_limit=600,
)
def js_secret_scan(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """JS secret scan over the crawl stage's JS files.

    Each JS file is fetched with the pinned-IP transport
    (:func:`app.workers.pinned_http.pinned_get`, 64 KiB cap, 5 req/s,
    max 50 files) and scanned with ``app.services.js_secrets.scan_js``. One finding per
    secret (template ``js-secret-<pattern>``, severity from the
    scraper); evidence is pattern name + file + line + redacted snippet
    ONLY — a secret value never reaches a finding, a log, or a job
    result. A single failed fetch is skipped, never fatal.

    Same-domain only (M6 review fix): only JS hosted on the target
    domain or its subdomains is fetched. Third-party / CDN JS is
    skipped and counted in ``files_skipped_off_domain`` — it is
    intentionally NOT scanned until an allowlist is decided, so a
    crawl that lists a CDN script can never turn this stage into a
    fetch against an arbitrary public host.
    """
    store = _load_store()
    user_uuid, scan_uuid, _scan, target = _load_scan_and_target(store, scan_id, user_id)
    if target.verification_status != "verified":
        return _refuse_unverified_target(store, user_uuid, scan_uuid, target, "js_secret_scan")
    domain = target.domain

    crawl_result = _prior_stage_result(store, user_uuid, scan_id, "crawl", domain)
    js_urls: list[str] = []
    if crawl_result is not None:
        raw_js = crawl_result.get("js_files")
        if isinstance(raw_js, list):
            js_urls = [item for item in raw_js if isinstance(item, str)]
        if not js_urls:
            raw_urls = crawl_result.get("urls")
            if isinstance(raw_urls, list):
                js_urls = [
                    item
                    for item in raw_urls
                    if isinstance(item, str) and item.lower().split("?", 1)[0].endswith(".js")
                ]
    # M6: fetch only same-domain (or subdomain) JS; skip + count the rest.
    on_domain_urls: list[str] = []
    files_skipped_off_domain = 0
    for js_url in js_urls:
        host = urlparse(js_url).hostname or ""
        if _is_same_domain_or_subdomain(host, domain):
            on_domain_urls.append(js_url)
        else:
            files_skipped_off_domain += 1
            logger.warning(
                "js_secret_scan: skipping off-domain JS %s (not on %s or a subdomain)",
                js_url,
                domain,
            )
    js_urls = on_domain_urls[:_JS_MAX_FILES]

    files_scanned = 0
    files_failed = 0
    secrets_found = 0
    by_pattern: dict[str, int] = {}
    for index, js_url in enumerate(js_urls):
        if index > 0:
            time.sleep(_JS_FETCH_DELAY_SECONDS)
        try:
            response = pinned_get(js_url, timeout=10.0, max_bytes=_JS_MAX_BYTES)
        except Exception as exc:  # one bad file must not fail the stage
            files_failed += 1
            logger.warning("js_secret_scan: fetch failed for %s: %s", js_url, exc)
            continue
        files_scanned += 1
        for hit in scan_js(response.text, js_url):
            store.create_finding(
                user_uuid,
                scan_uuid,
                target.id,
                f"js-secret-{hit['pattern_name']}",
                f"Possible secret in JS ({hit['pattern_name']}) at line {hit['line']}",
                str(hit["severity"]),
                url=js_url,
                evidence=(
                    f"pattern={hit['pattern_name']} file={js_url} "
                    f"line={hit['line']} snippet={hit['redacted_snippet']}"
                ),
            )
            secrets_found += 1
            by_pattern[str(hit["pattern_name"])] = by_pattern.get(str(hit["pattern_name"]), 0) + 1
    return {
        "status": "done",
        "stage": "js_secret_scan",
        "scan_id": scan_id,
        "target_id": str(target.id),
        "domain": domain,
        "files_scanned": files_scanned,
        "files_failed": files_failed,
        "files_skipped_off_domain": files_skipped_off_domain,
        "secrets_found": secrets_found,
        "by_pattern": by_pattern,
    }


# ---------------------------------------------------------------------------
# Pipeline chaining (B2 review fix)
#
# ``dispatch.py`` still enqueues only ``verify_target``; each stage, on
# a FRESH successful run, enqueues the next stage with the stage's
# idempotency key as the task id (mirroring dispatch.py's enqueue
# pattern) on the next stage's pipeline queue. The enqueue is done by
# ``IdempotentTask.__call__`` AFTER the fresh result is persisted (see
# the chaining block there) — NOT in the task bodies: chaining in a
# body would run the child before the parent's job log is written, so
# in eager mode the child would read an empty prior log and fall back
# to the apex. A cached re-run returns from ``IdempotentTask.__call__``
# before the task body, so it never re-enqueues — the chain advances
# exactly once per stage. A refusal (unverified target, deterministic
# agent failure) enqueues nothing: the scan is already marked failed.
# A chaining failure never fails the parent stage (its result is
# already stored); it is logged and the child records its own failure
# when it runs.
# ---------------------------------------------------------------------------


_NEXT_STAGE: dict[str, str] = {
    "verify_target": "dns_enum",
    "dns_enum": "subdomain_enum",
    "subdomain_enum": "port_scan",
    "port_scan": "http_probe",
    "http_probe": "tech_fingerprint",
    "tech_fingerprint": "crawl",
    "crawl": "js_secret_scan",
    # js_secret_scan is terminal — no next stage.
}

_TASK_BY_STAGE: dict[str, Any] = {
    "dns_enum": dns_enum,
    "subdomain_enum": subdomain_enum,
    "port_scan": port_scan,
    "http_probe": http_probe,
    "tech_fingerprint": tech_fingerprint,
    "crawl": crawl,
    "js_secret_scan": js_secret_scan,
}


def _enqueue_next_stage(stage: str, scan_id: str, user_id: str, domain: str) -> None:
    """Enqueue the stage after ``stage`` (no-op when terminal).

    Uses the next stage's idempotency key as the Celery task id, so a
    duplicate enqueue is the same idempotent delivery, and the queue
    from :data:`SCAN_PIPELINE`.
    """
    next_stage = _NEXT_STAGE.get(stage)
    if next_stage is None:
        return
    task = _TASK_BY_STAGE[next_stage]
    key = idempotency_key(scan_id, next_stage, domain)
    queue = next(
        (item.queue for item in SCAN_PIPELINE if item.stage == next_stage),
        "recon",
    )
    task.apply_async(args=[scan_id, user_id], task_id=key, queue=queue)
    logger.info(
        "chained scan %s: %s -> %s (%s enqueued)",
        scan_id,
        stage,
        next_stage,
        key,
    )
