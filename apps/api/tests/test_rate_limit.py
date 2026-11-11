"""Unit tests for ``RateLimiter`` (fixed window, 5 attempts / 15 min).

Covers: the in-memory backend (5 allowed, 6th denied with a positive
``retry_after``; per-key independence; window expiry) and the Redis backend
(exercised against a minimal in-test fake implementing the ``incr`` /
``expire`` / ``ttl`` / ``pipeline`` surface the limiter uses, plus the
fail-open behaviour when Redis errors).
"""

from __future__ import annotations

import time
from typing import Any

from app.auth.rate_limit import RateLimiter
from app.core.config import settings


def test_defaults_match_configured_login_limits() -> None:
    limiter = RateLimiter()
    assert limiter._max_attempts == settings.rate_limit_login_attempts == 5
    assert limiter._window_seconds == settings.rate_limit_login_window_seconds == 900


def test_memory_five_allowed_sixth_denied_with_retry_after() -> None:
    limiter = RateLimiter(max_attempts=5, window_seconds=900)
    for _ in range(5):
        allowed, retry_after = limiter.check("login:ip:1.2.3.4")
        assert allowed is True
        assert retry_after == 0
    allowed, retry_after = limiter.check("login:ip:1.2.3.4")
    assert allowed is False
    assert 0 < retry_after <= 900


def test_memory_keys_are_independent() -> None:
    limiter = RateLimiter(max_attempts=5, window_seconds=900)
    for _ in range(5):
        assert limiter.check("login:ip:1.2.3.4")[0] is True
    assert limiter.check("login:ip:1.2.3.4")[0] is False
    # A different key (another IP, or the per-email key) is unaffected.
    assert limiter.check("login:ip:5.6.7.8")[0] is True
    assert limiter.check("login:email:user@example.com")[0] is True


def test_memory_window_expiry_allows_again() -> None:
    limiter = RateLimiter(max_attempts=2, window_seconds=1)
    assert limiter.check("k")[0] is True
    assert limiter.check("k")[0] is True
    assert limiter.check("k")[0] is False
    time.sleep(1.1)
    assert limiter.check("k")[0] is True


def test_memory_prunes_stale_keys() -> None:
    # M6 review fix: the in-memory dict must not grow unboundedly. With
    # more than 10,000 fully-stale keys, the next check sweeps them out.
    # NOTE (CI run #6 fix): every seeded entry must hold only genuinely
    # stale timestamps. The old fixture used [stale, 1]; the literal 1
    # is only "stale" when time.monotonic() > 901, so on a fresh CI
    # runner (monotonic < 901s) it counted as in-window and nothing was
    # pruned (10002 keys remained). [stale, stale] is stale on any clock.
    # The assertion below is unchanged.
    limiter = RateLimiter(max_attempts=5, window_seconds=900)
    stale = time.monotonic() - 10_000
    limiter._attempts = {f"login:ip:10.0.0.{i}": [stale, stale] for i in range(10_001)}
    assert limiter.check("login:ip:9.9.9.9")[0] is True
    assert len(limiter._attempts) <= 2


# --- Redis backend (in-test fake client) --------------------------------------


class _FakePipeline:
    """Minimal pipeline: records commands, runs them against the fake."""

    def __init__(self, client: "_FakeRedis") -> None:
        self._client = client
        self._commands: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def incr(self, key: str) -> "_FakePipeline":
        self._commands.append(("incr", (key,), {}))
        return self

    def expire(self, key: str, seconds: int, nx: bool = False) -> "_FakePipeline":
        self._commands.append(("expire", (key, seconds), {"nx": nx}))
        return self

    def ttl(self, key: str) -> "_FakePipeline":
        self._commands.append(("ttl", (key,), {}))
        return self

    def execute(self) -> list[Any]:
        results: list[Any] = []
        for name, args, kwargs in self._commands:
            method = getattr(self._client, name)
            results.append(method(*args, **kwargs))
        self._commands.clear()
        return results


class _FakeRedis:
    """In-memory stand-in for the redis-py surface the limiter uses."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._ttls: dict[str, int] = {}

    def pipeline(self) -> _FakePipeline:
        return _FakePipeline(self)

    def incr(self, key: str) -> int:
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    def expire(self, key: str, seconds: int, nx: bool = False) -> bool:
        if nx and key in self._ttls:
            return False
        self._ttls[key] = seconds
        return True

    def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)


def test_redis_five_allowed_sixth_denied() -> None:
    limiter = RateLimiter(redis_client=_FakeRedis(), max_attempts=5, window_seconds=900)  # type: ignore[arg-type]
    for _ in range(5):
        allowed, retry_after = limiter.check("login:ip:1.2.3.4")
        assert allowed is True
        assert retry_after == 0
    allowed, retry_after = limiter.check("login:ip:1.2.3.4")
    assert allowed is False
    assert retry_after == 900  # TTL set once, on the first attempt


def test_redis_window_is_fixed_not_sliding() -> None:
    """The TTL is set (NX) only on the first attempt of a window."""
    fake = _FakeRedis()
    limiter = RateLimiter(redis_client=fake, max_attempts=5, window_seconds=900)  # type: ignore[arg-type]
    limiter.check("k")
    assert fake.ttl("k") == 900
    limiter.check("k")
    assert fake.ttl("k") == 900  # not refreshed by the second attempt


class _FailingRedis:
    """A Redis client that errors on every call."""

    def pipeline(self) -> "_FailingPipeline":
        return _FailingPipeline()


class _FailingPipeline:
    def incr(self, key: str) -> "_FailingPipeline":
        return self

    def expire(self, key: str, seconds: int, nx: bool = False) -> "_FailingPipeline":
        return self

    def ttl(self, key: str) -> "_FailingPipeline":
        return self

    def execute(self) -> list[Any]:
        import redis

        raise redis.RedisError("connection refused")


def test_redis_error_fails_open() -> None:
    limiter = RateLimiter(redis_client=_FailingRedis(), max_attempts=5, window_seconds=900)  # type: ignore[arg-type]
    allowed, retry_after = limiter.check("login:ip:1.2.3.4")
    assert allowed is True
    assert retry_after == 0


def test_check_returns_typed_tuple() -> None:
    limiter = RateLimiter(max_attempts=5, window_seconds=900)
    result = limiter.check("k")
    assert isinstance(result, tuple) and len(result) == 2
    assert isinstance(result[0], bool) and isinstance(result[1], int)
