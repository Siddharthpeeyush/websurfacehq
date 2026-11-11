"""Scan dispatch: create the pipeline's job rows and enqueue stage one.

``dispatch_scan(scan_id, user_id)`` is the only entry point that starts a
scan's work (called by the API layer, which has the authenticated
``user_id`` — the tenant-scoped store needs it for every call):

1. Load the scan (and its target, for the idempotency key).
2. Create one ``scan_jobs`` row per stage in :data:`SCAN_PIPELINE`
   (status ``queued`` — including stages that are not implemented yet.
   Unimplemented stages are rows only: no fake execution, no stubs that
   pretend to scan.
3. Enqueue ONLY ``verify_target`` (Week 1), with task id
   ``scan_id:verify_target:target_hash`` on the ``recon`` queue.

Idempotent: calling it twice for the same scan creates no duplicate job
rows and enqueues no duplicate task — existing rows are checked first
(the store's ``create_scan_job`` does NOT dedupe, so this check is the
only guard), and the task is enqueued only when its row is newly created.

The worker-side verification gate (not dispatch) is the enforcement
point for unverified targets: dispatch enqueues ``verify_target`` and
the task itself refuses an unverified target without any outbound
request (see ``app.workers.tasks.verify_target``).
"""

from __future__ import annotations

import logging
from typing import Any

from app.workers.tasks import (
    SCAN_PIPELINE,
    _coerce_uuid,
    _load_store,
    idempotency_key,
    target_hash_for,
    verify_target,
)

logger = logging.getLogger(__name__)


def dispatch_scan(scan_id: str, user_id: str) -> dict[str, Any]:
    """Create queued job rows for the full pipeline; enqueue verify_target.

    Returns a summary dict: the scan id, the owning user id, the
    verify_target task id (or ``None`` when nothing was enqueued),
    whether a task was enqueued by this call, and the per-stage rows
    that exist after the call.
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
    target_hash = target_hash_for(domain)

    stages: list[dict[str, Any]] = []
    verify_task_id: str | None = None
    enqueued = False
    for pipeline_stage in SCAN_PIPELINE:
        key = idempotency_key(scan_id, pipeline_stage.stage, domain)
        existing = store.get_scan_job_by_key(user_uuid, key)
        if existing is None:
            job = store.create_scan_job(user_uuid, scan_uuid, pipeline_stage.stage, key)
            status = job.status
        else:
            job = existing
            status = existing.status
        stages.append({"stage": pipeline_stage.stage, "status": status})

        if pipeline_stage.stage != "verify_target":
            continue
        verify_task_id = key
        if existing is None:
            # Fresh row: this is the first dispatch — enqueue the task.
            # Mark the scan "queued" BEFORE enqueueing: in eager mode the
            # task runs synchronously inside apply_async and moves the scan
            # to "recon"/"failed", which must not be clobbered afterwards.
            store.update_scan(user_uuid, scan_uuid, status="queued")
            verify_target.apply_async(
                args=[scan_id, user_id],
                task_id=key,
                queue="recon",
            )
            store.update_scan_job(user_uuid, job.id, celery_task_id=key)
            enqueued = True
            logger.info(
                "dispatched scan %s: verify_target %s enqueued",
                scan_id,
                key,
            )
        else:
            logger.info(
                "dispatch_scan called again for scan %s: verify_target "
                "already dispatched (job status %s), not re-enqueued",
                scan_id,
                status,
            )

    return {
        "scan_id": scan_id,
        "user_id": user_id,
        "target_hash": target_hash,
        "task_id": verify_task_id,
        "enqueued": enqueued,
        "stages": stages,
    }
