"""DLQ + vuln-lock tests.

Covers: a task that always fails exhausts its retries (4 executions:
initial + 3 retries), then lands in the DLQ and the scan is marked
failed; ``send_to_dlq``/``read_dlq`` round-trip; DLQ helpers never raise
when Redis is unreachable; the per-target vuln lock (second acquire
while held returns False, release lets a new acquire succeed).

Celery eager mode (no broker) + fakeredis (never a real Redis in tests)
+ Builder C's real ``InMemoryStore``.
"""

from __future__ import annotations

import uuid
from typing import Any

import fakeredis
import pytest

from app.db.memory import InMemoryStore
from app.services.verification import hash_token
from app.workers import celery_app
from app.workers.dlq import read_dlq, send_to_dlq
from app.workers.locks import acquire_vuln_lock, release_vuln_lock
from app.workers.tasks import IdempotentTask, idempotency_key

# ---------------------------------------------------------------------------
# Always-failing task (registered on the shared app, test-only name)
# ---------------------------------------------------------------------------

attempts: list[str] = []


@celery_app.task(  # type: ignore[untyped-decorator]
    base=IdempotentTask,
    bind=True,
    name="websurfacehq.vuln.boom_test",
    stage="boom_test",
)
def boom_task(self: IdempotentTask, scan_id: str, user_id: str) -> dict[str, Any]:
    """Always fails: exercises retries -> DLQ -> scan failed."""
    attempts.append(scan_id)
    raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _eager_celery() -> Any:
    """Run tasks eagerly (no broker) and restore the conf afterwards.

    NOTE: task_store_eager_result stays False on purpose. Setting it True
    makes eager execution store results in the Redis result backend, so a
    run with no Redis up fails with ConnectionError (Celery binds the
    task's store_eager_result flag from conf at first use, so the failure
    depends on bind timing). EagerResult already carries the return value
    for .get(); nothing here needs the backend store.
    """
    old_eager = celery_app.conf.task_always_eager
    old_store = celery_app.conf.task_store_eager_result
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_store_eager_result = False
    yield
    celery_app.conf.task_always_eager = old_eager
    celery_app.conf.task_store_eager_result = old_store


@pytest.fixture()
def fake_redis() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture()
def _patched_redis(
    fake_redis: fakeredis.FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> fakeredis.FakeRedis:
    """Point the DLQ + lock helpers at fakeredis (never a real Redis)."""
    monkeypatch.setattr("app.workers.dlq.get_redis_client", lambda: fake_redis)
    monkeypatch.setattr("app.workers.locks.get_redis_client", lambda: fake_redis)
    return fake_redis


@pytest.fixture()
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture()
def _patched_store(store: InMemoryStore, monkeypatch: pytest.MonkeyPatch) -> InMemoryStore:
    monkeypatch.setattr("app.workers.tasks._load_store", lambda: store)
    return store


# ---------------------------------------------------------------------------
# DLQ round-trip + failure safety
# ---------------------------------------------------------------------------


def test_send_and_read_dlq_round_trip(
    _patched_redis: fakeredis.FakeRedis,
) -> None:
    assert send_to_dlq("scan-1", "nuclei_scan", {"scan_id": "scan-1"}, "kaboom") is True
    entries = read_dlq("scan-1")
    assert len(entries) == 1
    assert entries[0]["scan_id"] == "scan-1"
    assert entries[0]["stage"] == "nuclei_scan"
    assert entries[0]["error"] == "kaboom"
    assert entries[0]["payload"] == {"scan_id": "scan-1"}
    assert entries[0]["failed_at"]
    assert read_dlq("scan-unknown") == []


def test_send_to_dlq_never_raises_when_redis_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _down() -> Any:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr("app.workers.dlq.get_redis_client", _down)
    assert send_to_dlq("scan-1", "nuclei_scan", {}, "kaboom") is False


def test_read_dlq_returns_empty_when_redis_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _down() -> Any:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr("app.workers.dlq.get_redis_client", _down)
    assert read_dlq("scan-1") == []


# ---------------------------------------------------------------------------
# Always-failing task -> retries exhausted -> DLQ + scan failed
# ---------------------------------------------------------------------------


def test_always_failing_task_goes_to_dlq_after_retries(
    _patched_redis: fakeredis.FakeRedis,
    _patched_store: InMemoryStore,
    store: InMemoryStore,
) -> None:
    user_id = uuid.uuid4()
    target = store.create_target(user_id, "example.com", hash_token("tok"))
    scan = store.create_scan(user_id, target.id, {})
    attempts.clear()

    with pytest.raises(RuntimeError, match="boom"):
        boom_task.apply_async(args=[str(scan.id), str(user_id)]).get()

    # Initial attempt + 3 retries (max_retries=3), then final failure.
    assert len(attempts) == 4
    assert boom_task.max_retries == 3

    entries = read_dlq(str(scan.id))
    assert len(entries) == 1
    assert entries[0]["stage"] == "boom_test"
    assert entries[0]["error"] == "boom"
    assert entries[0]["payload"]["scan_id"] == str(scan.id)

    reloaded = store.get_scan(user_id, scan.id)
    assert reloaded is not None and reloaded.status == "failed"
    assert reloaded.error is not None and "boom_test" in reloaded.error
    real_key = idempotency_key(str(scan.id), "boom_test", "example.com")
    job = store.get_scan_job_by_key(user_id, real_key)
    assert job is not None and job.status == "failed"


# ---------------------------------------------------------------------------
# Vuln lock
# ---------------------------------------------------------------------------


def test_vuln_lock_second_acquire_while_held_returns_none(
    _patched_redis: fakeredis.FakeRedis,
) -> None:
    target_hash = "a379a6f6eeaf"
    token = acquire_vuln_lock(target_hash)
    assert token is not None
    assert acquire_vuln_lock(target_hash) is None
    assert release_vuln_lock(target_hash, token) is True
    assert acquire_vuln_lock(target_hash) is not None
    assert release_vuln_lock(target_hash, token) is False  # token already spent


def test_vuln_lock_wrong_token_cannot_release(
    _patched_redis: fakeredis.FakeRedis,
) -> None:
    """M7 review fix: a stale/slow task must not delete the next worker's
    lock. Releasing with the wrong token leaves the lock held."""
    target_hash = "a379a6f6eeaf"
    token = acquire_vuln_lock(target_hash)
    assert token is not None
    assert release_vuln_lock(target_hash, "not-the-holder-token") is False
    # The real holder still holds it — a second acquire still fails.
    assert acquire_vuln_lock(target_hash) is None
    assert release_vuln_lock(target_hash, token) is True


def test_vuln_lock_release_without_hold_returns_false(
    _patched_redis: fakeredis.FakeRedis,
) -> None:
    assert release_vuln_lock("never-held-hash", "any-token") is False


def test_vuln_lock_is_per_target(
    _patched_redis: fakeredis.FakeRedis,
) -> None:
    token_one = acquire_vuln_lock("hash-one")
    token_two = acquire_vuln_lock("hash-two")
    assert token_one is not None and token_two is not None
    assert token_one != token_two
    assert release_vuln_lock("hash-one", token_one) is True
    assert release_vuln_lock("hash-two", token_two) is True


def test_vuln_lock_never_raises_when_redis_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _down() -> Any:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr("app.workers.locks.get_redis_client", _down)
    # Fail closed: no lock, no vuln run.
    assert acquire_vuln_lock("a379a6f6eeaf") is None
    assert release_vuln_lock("a379a6f6eeaf", "any-token") is False


def test_dlq_trims_to_newest_1000(
    _patched_redis: fakeredis.FakeRedis,
) -> None:
    # L6 review fix: the DLQ is capped at 1,000 entries (newest kept).
    scan_id = "trim-scan"
    for i in range(1_005):
        send_to_dlq(scan_id, f"websurfacehq.recon.stage-{i}", {"i": i}, RuntimeError("x"))
    entries = read_dlq(scan_id)
    assert len(entries) == 1000
    assert entries[0]["payload"]["i"] == 5
    assert entries[-1]["payload"]["i"] == 1004
