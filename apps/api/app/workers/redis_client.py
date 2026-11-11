"""Shared Redis client factory for the workers (DLQ + locks).

One tiny module so ``dlq`` and ``locks`` do not each invent their own
connection logic. The client is built from the broker URL in settings
(Upstash Redis in production, local Redis in dev). No connection is made
at import time — ``redis-py`` connects lazily on first command.

Tests patch ``app.workers.redis_client.get_redis_client`` to return a
fakeredis client; production code never touches a real Redis in tests.
"""

from __future__ import annotations

from redis import Redis

from app.core.config import settings


def get_redis_client() -> Redis:
    """Return a redis-py client for the Celery broker URL.

    ``decode_responses=True`` so keys/values come back as ``str``, matching
    what the DLQ and lock helpers store. Socket timeouts are set (L6 review
    fix): without them a hung Redis can block a worker call indefinitely.
    """
    return Redis.from_url(
        settings.celery_broker_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
