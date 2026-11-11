"""Idempotency tests for the worker base task.

Covers: running ``verify_target`` twice with the same task id (second
call returns the stored result, exactly one job row, no duplicate side
effects); a ``running`` row with a fresh heartbeat and a different task
id is skipped; a stale ``running`` row is re-run.

Celery eager mode (no broker) + Builder C's real ``InMemoryStore``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest

from app.db.memory import InMemoryStore
from app.services.verification import hash_token
from app.workers import celery_app
from app.workers.tasks import (
    idempotency_key,
    target_hash_for,
    verify_target,
)

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
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture()
def _patched_store(store: InMemoryStore, monkeypatch: pytest.MonkeyPatch) -> InMemoryStore:
    monkeypatch.setattr("app.workers.tasks._load_store", lambda: store)
    # Worker tests must not depend on network/DNS (see test_workers.py).
    monkeypatch.setattr("app.workers.tasks._assert_verification_url_safe", lambda domain: None)
    return store


def _verified_scan(store: InMemoryStore, domain: str = "example.com") -> tuple[str, str, UUID]:
    user_id = uuid.uuid4()
    target = store.create_target(user_id, domain, hash_token("tok-123"))
    store.update_target_verification(
        user_id,
        target.id,
        status="verified",
        method="file",
        verified_at=datetime.now(timezone.utc),
    )
    scan = store.create_scan(user_id, target.id, {"depth": "quick"})
    return str(scan.id), str(user_id), target.id


def _audit_count(store: InMemoryStore) -> int:
    # InMemoryStore has no list method; the dict is the test double's
    # only way to count audit entries.
    return len(store._audit)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_run_twice_same_task_id_returns_stored_result(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _verified_scan(store)
    check_calls: list[str] = []

    def _fake_recheck(domain: str, token_hash: str, method: str | None) -> bool:
        check_calls.append(domain)
        return True

    monkeypatch.setattr("app.workers.tasks._recheck_verification", _fake_recheck)
    task_id = idempotency_key(scan_id, "verify_target", "example.com")
    assert task_id == f"{scan_id}:verify_target:{target_hash_for('example.com')}"

    first = verify_target.apply_async(args=[scan_id, user_id], task_id=task_id).get()
    second = verify_target.apply_async(args=[scan_id, user_id], task_id=task_id).get()

    assert first["status"] == "verified"
    assert second["status"] == "verified"
    assert second["cached"] is True
    assert second["scan_id"] == scan_id
    # The live verification re-check ran exactly once: no duplicate
    # side effects on the second delivery.
    assert check_calls == ["example.com"]
    # Exactly one job row, done, holding the stored result.
    user_uuid = UUID(user_id)
    job = store.get_scan_job_by_key(user_uuid, task_id)
    assert job is not None
    assert job.status == "done"
    assert job.celery_task_id == task_id
    assert job.log is not None and '"verified"' in job.log
    assert len(store._scan_jobs) == 1


def test_run_twice_same_task_id_for_refusal_is_also_idempotent(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid.uuid4()
    target = store.create_target(user_id, "example.com", hash_token("tok"))
    scan = store.create_scan(user_id, target.id, {})

    def _must_not_be_called(domain: str, token_hash: str, method: str | None) -> bool:
        raise AssertionError("must not be called")

    monkeypatch.setattr("app.workers.tasks._recheck_verification", _must_not_be_called)
    task_id = idempotency_key(str(scan.id), "verify_target", "example.com")

    first = verify_target.apply_async(args=[str(scan.id), str(user_id)], task_id=task_id).get()
    second = verify_target.apply_async(args=[str(scan.id), str(user_id)], task_id=task_id).get()

    assert first["error"] == "TARGET_NOT_VERIFIED"
    assert second["error"] == "TARGET_NOT_VERIFIED"
    assert second["cached"] is True
    assert len(store._scan_jobs) == 1
    # The audit log was written once, not once per delivery.
    assert _audit_count(store) == 1


def test_running_row_with_fresh_heartbeat_and_other_task_id_skips(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _verified_scan(store)
    check_calls: list[str] = []

    def _fake_recheck(domain: str, token_hash: str, method: str | None) -> bool:
        check_calls.append(domain)
        return True

    monkeypatch.setattr("app.workers.tasks._recheck_verification", _fake_recheck)
    user_uuid = UUID(user_id)
    key = idempotency_key(scan_id, "verify_target", "example.com")
    # Simulate a concurrent worker already executing this stage: a
    # "running" row, fresh heartbeat, different task id.
    job = store.create_scan_job(user_uuid, UUID(scan_id), "verify_target", key)
    store.update_scan_job(
        user_uuid,
        job.id,
        status="running",
        celery_task_id="some-other-task-id",
        started_at=datetime.now(timezone.utc),
    )

    result = verify_target.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "skipped"
    assert result["reason"] == "already_running"
    assert result["cached"] is True
    assert check_calls == []  # nothing re-ran
    running_job = store.get_scan_job_by_key(user_uuid, key)
    assert running_job is not None and running_job.status == "running"


def test_running_row_with_stale_heartbeat_is_rerun(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _verified_scan(store)
    check_calls: list[str] = []

    def _fake_recheck(domain: str, token_hash: str, method: str | None) -> bool:
        check_calls.append(domain)
        return True

    monkeypatch.setattr("app.workers.tasks._recheck_verification", _fake_recheck)
    user_uuid = UUID(user_id)
    key = idempotency_key(scan_id, "verify_target", "example.com")
    # Simulate a crashed attempt: "running" row, heartbeat 1 hour old.
    job = store.create_scan_job(user_uuid, UUID(scan_id), "verify_target", key)
    stale = datetime.now(timezone.utc) - timedelta(hours=1)
    store.update_scan_job(
        user_uuid,
        job.id,
        status="running",
        celery_task_id="dead-task-id",
        started_at=stale,
    )

    result = verify_target.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "verified"
    assert check_calls == ["example.com"]
    done_job = store.get_scan_job_by_key(user_uuid, key)
    assert done_job is not None and done_job.status == "done"
