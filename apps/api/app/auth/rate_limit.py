"""Fixed-window rate limiting for auth endpoints.

Contract (blueprint §1.6 / §0.4, config ``rate_limit_login_*``): 5 attempts
per 15 minutes per key. Keys are ``login:ip:{ip}`` and
``login:email:{email}`` — both are checked on every auth attempt.

Backends:
- In-memory (default): dev / tests. Per-process only — do not rely on it
  across replicas.
- Redis: used when a Redis client is provided. The window is a single key
  with ``INCR`` + ``EXPIRE NX`` in one pipeline, so the store is shared
  across processes and survives redeploys (Upstash in production).

``check(key)`` returns ``(allowed, retry_after_seconds)``; ``retry_after``
is 0 when allowed. A Redis outage fails OPEN (allows the attempt) and logs
a warning: a cache outage must not lock every user out of login. The
in-memory path never fails open — it has no external dependency.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from typing import TYPE_CHECKING, Any

import redis
from redis import Redis

from app.core.config import settings

if TYPE_CHECKING:
    from redis.client import Pipeline

logger = logging.getLogger("websurfacehq")


class RateLimiter:
    """Fixed-window limiter: ``max_attempts`` per ``window_seconds``."""

    def __init__(
        self,
        redis_client: Redis | None = None,
        max_attempts: int | None = None,
        window_seconds: int | None = None,
    ) -> None:
        self._redis = redis_client
        self._max_attempts = (
            max_attempts if max_attempts is not None else settings.rate_limit_login_attempts
        )
        self._window_seconds = (
            window_seconds
            if window_seconds is not None
            else settings.rate_limit_login_window_seconds
        )
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Return ``(allowed, retry_after_seconds)`` for ``key``."""
        if self._redis is not None:
            return self._check_redis(key)
        return self._check_memory(key)

    def _check_memory(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        window_start = now - self._window_seconds
        with self._lock:
            attempts = [t for t in self._attempts.get(key, []) if t > window_start]
            if len(attempts) >= self._max_attempts:
                retry_after = math.ceil(self._window_seconds - (now - attempts[0]))
                self._attempts[key] = attempts
                return False, max(retry_after, 1)
            attempts.append(now)
            self._attempts[key] = attempts
            # Bound the dict (M6 review fix): an attacker minting keys
            # (spoofed emails / IPs) must not grow process memory
            # indefinitely. Sweep out fully-stale keys once the dict is
            # large; the sweep itself is O(dict) but runs rarely.
            if len(self._attempts) > 10000:
                self._attempts = {
                    k: v for k, v in self._attempts.items() if any(t > window_start for t in v)
                }
            return True, 0

    def _check_redis(self, key: str) -> tuple[bool, int]:
        assert self._redis is not None  # noqa: S101 - guarded by check()
        try:
            pipe: Pipeline = self._redis.pipeline()
            pipe.incr(key)
            # Set the TTL only when the key is new (NX): the window is
            # fixed from the first attempt, not sliding.
            pipe.expire(key, self._window_seconds, nx=True)
            pipe.ttl(key)
            results: list[Any] = pipe.execute()  # type: ignore[no-untyped-call]
            count = int(results[0])
            ttl = int(results[2])
            if count > self._max_attempts:
                return False, max(ttl, 1)
            return True, 0
        except redis.RedisError:
            # Fail open on a Redis outage (see module docstring) — but say
            # so loudly in the logs so the outage is not silent.
            logger.warning("rate-limit Redis error; failing open", extra={"key": key})
            return True, 0


def redis_client_from_settings() -> Redis:
    """Build a Redis client from the configured broker URL (Upstash/local)."""
    return redis.Redis.from_url(
        settings.celery_broker_url,
        socket_connect_timeout=2,
        socket_timeout=2,
        decode_responses=True,
    )


# --- Module-level override (tests / explicit wiring) -----------------------
# Default limiter is in-memory. Production wiring passes a Redis client via
# ``set_rate_limiter(RateLimiter(redis_client_from_settings()))`` at startup
# (the coordinator's integration pass, not import time — importing this
# module must never open a network connection).

_default_limiter: RateLimiter | None = None
_limiter_override: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return the active limiter (test override wins, else the default)."""
    global _default_limiter
    if _limiter_override is not None:
        return _limiter_override
    if _default_limiter is None:
        _default_limiter = RateLimiter()
    return _default_limiter


def set_rate_limiter(limiter: RateLimiter | None) -> None:
    """Override the active limiter (tests only). ``None`` clears it."""
    global _limiter_override
    _limiter_override = limiter
