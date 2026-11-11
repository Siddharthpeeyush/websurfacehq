"""Per-target lock for the ``vuln`` queue (blueprint §1.5).

Rule: at most ONE vuln-queue task runs against a given target at a time
(``10 tasks/min global, 1 per target``). The lock is a Redis key
``vuln:target:{target_hash}`` set with NX + expiry, so a crashed worker
cannot hold the lock forever — it expires after the longest vuln task
(30 min) at the latest.

Ownership token (M7 review fix): acquiring returns a unique token, and
releasing requires that token (Lua compare-and-delete). A bare
``delete`` would let a slow task whose lock expired delete the NEXT
worker's lock — two vuln tasks against one target. The token makes
correct use possible: only the holder can release, and only while it
still holds the lock.

Week 1 ships the helper + its tests only; the vuln tasks that acquire the
lock land in Week 2. Any caller that cannot acquire the lock must NOT run
the task — ``acquire_vuln_lock`` returning ``None`` (including when Redis
is unreachable) means "do not scan this target now", never "proceed
without a lock".
"""

from __future__ import annotations

import logging
import secrets

import redis

from app.workers.redis_client import get_redis_client

logger = logging.getLogger(__name__)

# Longest vuln task is 30 min (blueprint §1.5); the lock must outlive it.
VULN_LOCK_TTL_SECONDS = 1800


def vuln_lock_key(target_hash: str) -> str:
    """Redis key for the per-target vuln lock."""
    return f"vuln:target:{target_hash}"


def acquire_vuln_lock(
    target_hash: str,
    timeout: int = VULN_LOCK_TTL_SECONDS,
) -> str | None:
    """Try to take the vuln lock for a target.

    Returns the ownership token when this caller now holds the lock, else
    ``None`` — when the lock is already held OR Redis is unreachable.
    Both mean "do not run the vuln task now". The caller must pass the
    token back to :func:`release_vuln_lock`.
    """
    token = secrets.token_hex(16)
    try:
        client = get_redis_client()
        acquired = client.set(vuln_lock_key(target_hash), token, nx=True, ex=timeout)
    except Exception:
        logger.exception(
            "vuln lock acquire failed for target %s; refusing to run",
            target_hash,
        )
        return None
    return token if acquired else None


def release_vuln_lock(target_hash: str, token: str) -> bool:
    """Release the vuln lock for a target — only if ``token`` still holds it.

    Returns ``True`` when this caller's lock was removed, ``False`` when
    the lock is held by someone else, already expired, or Redis is
    unreachable. A wrong token never deletes another worker's lock.

    Atomicity: WATCH + MULTI — the delete executes only if the key still
    holds this token at EXEC time. (A Lua compare-and-delete would be the
    usual form, but fakeredis — the test backend — has no EVAL, so the
    WATCH form is used; it is atomic on real Redis too.)
    """
    try:
        client = get_redis_client()
        key = vuln_lock_key(target_hash)
        # Bounded retry on contention (round-2 review finding): returning
        # False on the first WatchError left the lock held until its TTL
        # (up to 30 min), blocking that target's vuln queue. Three
        # attempts, then fail closed — a contended release is rare and
        # the lock expires on its own. Each attempt uses a fresh
        # pipeline: after a WatchError the old one must be reset.
        for _attempt in range(3):
            try:
                with client.pipeline() as pipe:
                    pipe.watch(key)  # type: ignore[no-untyped-call]
                    current = pipe.get(key)
                    if current != token:
                        pipe.unwatch()
                        return False
                    pipe.multi()
                    pipe.delete(key)
                    pipe.execute()  # type: ignore[no-untyped-call]
                    return True
            except redis.WatchError:
                continue
        return False
    except Exception:
        logger.exception("vuln lock release failed for target %s", target_hash)
        return False
