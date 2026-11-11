"""Celery application for WebSurfaceHQ workers.

Broker + result backend come from settings (Upstash Redis in production,
local Redis in dev). Importing this module must NOT connect to the broker:
``Celery(...)`` only stores the URLs; the connection is opened lazily by the
worker / first ``apply_async`` call.

Queues (architecture §4 / blueprint §1.5 — never one big queue):

- ``recon`` — DNS, subdomains, httpx probe, TLS. 10 workers, 2 s/host
  (enforced per task, not as one task-wide limit), 50 tasks/min.
- ``crawl`` — Katana crawl, JS download, secret scan. 3 workers,
  10 min/scan, 5 tasks/min per domain.
- ``vuln`` — Nuclei, dalfox, nikto. 2 workers, 30 min/scan,
  10 tasks/min global, 1 per target.

Task serializer is JSON only — pickle is never accepted.
"""

from __future__ import annotations

from celery import Celery  # type: ignore[import-untyped]

from app.core.config import settings

# Per-queue task time limits in seconds (blueprint §1.5 / architecture §4).
# ``recon`` has no per-queue limit (None below) — recon tasks are bounded
# only by the global ``task_time_limit`` of 1800 s, which still applies
# to every queue including recon. The global limit is the ceiling for the
# longest queue (vuln, 30 min); individual tasks set tighter limits.
TASK_TIME_LIMITS: dict[str, int | None] = {
    "recon": None,
    "crawl": 600,
    "vuln": 1800,
}

celery_app = Celery(
    "websurfacehq",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],  # JSON only — never pickle.
    task_acks_late=True,  # re-queue if a worker dies mid-task.
    worker_prefetch_multiplier=1,  # one task at a time per worker process.
    task_routes={
        "*.recon.*": {"queue": "recon"},
        "*.crawl.*": {"queue": "crawl"},
        "*.vuln.*": {"queue": "vuln"},
    },
    task_time_limit=1800,  # global ceiling = vuln queue limit (30 min).
    # Per-queue time limits, built from TASK_TIME_LIMITS (L5 review fix:
    # the dict was dead code — nothing read it). Recon has no task-wide
    # limit by design (2 s/host inside each task; verify_target sets its
    # own 120 s); crawl and vuln get their queue ceilings here.
    task_annotations={
        f"*.{queue}.*": {"time_limit": limit}
        for queue, limit in TASK_TIME_LIMITS.items()
        if limit is not None
    },
)
