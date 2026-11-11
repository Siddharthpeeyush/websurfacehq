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

Verification gate (docs/testing.md §4): a Celery task handed an
unverified target REFUSES to run — no outbound request is made at all.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from celery import Task  # type: ignore[import-untyped]

from app.db.store import Store, hash_resource_id
from app.workers.celery_app import celery_app
from app.workers.dlq import send_to_dlq

logger = logging.getLogger(__name__)

# A ``running`` job row whose heartbeat is younger than this is treated as
# still executing (a duplicate delivery is skipped). Older than this, the
# previous attempt is presumed dead and the stage may re-run.
HEARTBEAT_FRESH_SECONDS = 600


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
# verify_target is implemented. The rest are listed so dispatch can create
# their ``queued`` scan_jobs rows — they MUST NOT be enqueued yet.
# Queue note: ai_triage / enrichment / generate_report / notify_user are
# lightweight post-processing, not scanning; the architecture has only
# three queues, so they ride ``recon`` (10 workers) until a dedicated
# queue is justified. Flagged as an assumption in the Week 1 report.
SCAN_PIPELINE: list[PipelineStage] = [
    PipelineStage("verify_target", "recon", True),
    PipelineStage("dns_enum", "recon", False),
    PipelineStage("subdomain_enum", "recon", False),
    PipelineStage("port_scan", "recon", False),
    PipelineStage("http_probe", "recon", False),
    PipelineStage("tech_fingerprint", "recon", False),
    PipelineStage("crawl", "crawl", False),
    PipelineStage("js_secret_scan", "crawl", False),
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
    return {
        "status": "verified",
        "scan_id": scan_id,
        "target_id": str(target_id),
        "domain": domain,
    }
