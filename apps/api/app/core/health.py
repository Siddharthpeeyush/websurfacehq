"""Component health checks for ``GET /health`` (Week 1).

The coordinator wires :func:`component_status` into ``/health`` in
``app/main.py`` — this module does NOT touch main.py. Every component is
checked with a short timeout and degrades gracefully: a component that is
not configured reports ``"not_configured"`` rather than failing the whole
check, and a component that errors reports ``"error"`` / ``"unreachable"``
with a safe detail string (never a secret, never a traceback).
"""

from __future__ import annotations

from typing import Any

from app.core.config import settings


def _check_database() -> dict[str, str]:
    if not settings.supabase_configured:
        # In-memory store in dev/test: reachable by construction.
        from app.db import get_store

        try:
            ok = get_store().ping()
        except Exception as exc:  # noqa: BLE001 — health must never raise
            return {"status": "error", "detail": f"store ping failed: {type(exc).__name__}"}
        return (
            {"status": "ok", "detail": "in-memory store"}
            if ok
            else {"status": "error", "detail": "in-memory store ping failed"}
        )
    from app.db import get_store

    try:
        ok = get_store().ping()
    except Exception as exc:  # noqa: BLE001 — health must never raise
        return {"status": "error", "detail": f"supabase ping failed: {type(exc).__name__}"}
    return (
        {"status": "ok", "detail": "supabase reachable"}
        if ok
        else {"status": "error", "detail": "supabase ping failed"}
    )


def _check_redis() -> dict[str, str]:
    broker = settings.celery_broker_url
    if not broker.startswith(("redis://", "rediss://")):
        return {"status": "not_configured", "detail": "no redis broker url configured"}
    try:
        import redis

        client = redis.Redis.from_url(broker, socket_connect_timeout=2.0, socket_timeout=2.0)
        client.ping()
        return {"status": "ok", "detail": "redis reachable"}
    except Exception as exc:  # noqa: BLE001 — health must never raise
        return {"status": "unreachable", "detail": f"redis ping failed: {type(exc).__name__}"}


def _check_queue() -> dict[str, str]:
    # The worker code exists (app/workers, Week 1) but there is no live
    # worker process or measurable queue depth in this environment — no
    # broker is reachable — so report not_configured rather than inventing
    # a depth of 0. When a broker is reachable, queue depth is measured
    # from the Celery queue lengths (a Week 2 wiring job).
    return {"status": "not_configured", "detail": "celery worker not wired yet (Week 1)"}


def component_status() -> dict[str, dict[str, str]]:
    """Per-component status: ``{"database": {...}, "redis": {...},
    "queue": {...}}`` — each ``{"status": ..., "detail": ...}``."""
    result: dict[str, dict[str, str]] = {
        "database": _check_database(),
        "redis": _check_redis(),
        "queue": _check_queue(),
    }
    return result


def overall_status(components: dict[str, dict[str, str]] | None = None) -> str:
    """``"ok"`` when every configured component is ok, else ``"degraded"``.
    ``not_configured`` components do not degrade the overall status."""
    components = components or component_status()
    for component in components.values():
        if component["status"] in ("error", "unreachable"):
            return "degraded"
    return "ok"


def health_payload() -> dict[str, Any]:
    """The full ``/health`` body the coordinator can return verbatim."""
    components = component_status()
    return {"status": overall_status(components), "components": components}
