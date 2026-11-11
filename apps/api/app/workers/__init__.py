"""Celery workers for WebSurfaceHQ (Week 1 — Foundation).

- :mod:`app.workers.celery_app` — the Celery app (broker/backend from
  settings, JSON only, 3 routed queues).
- :mod:`app.workers.tasks` — the idempotent base task, the pipeline
  registry, and ``verify_target`` (the only implemented stage in Week 1).
- :mod:`app.workers.dispatch` — ``dispatch_scan``: create the pipeline's
  job rows and enqueue ``verify_target`` only.
- :mod:`app.workers.dlq` — dead-letter queue helpers (``dlq:scan:{id}``).
- :mod:`app.workers.locks` — the per-target vuln lock (used by vuln
  tasks in Week 2; helper + tests land now).
- :mod:`app.workers.redis_client` — the shared Redis client factory.
"""

from __future__ import annotations

from app.workers.celery_app import TASK_TIME_LIMITS, celery_app
from app.workers.dispatch import dispatch_scan
from app.workers.dlq import dlq_key, read_dlq, send_to_dlq
from app.workers.locks import (
    VULN_LOCK_TTL_SECONDS,
    acquire_vuln_lock,
    release_vuln_lock,
    vuln_lock_key,
)
from app.workers.tasks import (
    SCAN_PIPELINE,
    IdempotentTask,
    PipelineStage,
    idempotency_key,
    normalize_domain,
    target_hash_for,
    verify_target,
)

__all__ = [
    "IdempotentTask",
    "PipelineStage",
    "SCAN_PIPELINE",
    "TASK_TIME_LIMITS",
    "VULN_LOCK_TTL_SECONDS",
    "acquire_vuln_lock",
    "celery_app",
    "dispatch_scan",
    "dlq_key",
    "idempotency_key",
    "normalize_domain",
    "read_dlq",
    "release_vuln_lock",
    "send_to_dlq",
    "target_hash_for",
    "verify_target",
    "vuln_lock_key",
]
