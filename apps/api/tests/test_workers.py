"""Worker wiring tests: Celery app config, pipeline registry, dispatch,
retry config, and the verify_target verification gate.

Everything runs in Celery eager mode (no broker) against Builder C's
real ``InMemoryStore`` (the delivered test double) — no fake store.
Network-touching helpers are patched: the verification re-check
(``_recheck_verification``) is a counting fake, and the SSRF pre-check
is a no-op (live DNS has no place in these tests; the guard itself is
covered by Builder C's ``test_ssrf.py``).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import pytest
from celery.utils.time import get_exponential_backoff_interval  # type: ignore[import-untyped]

from app.db.memory import InMemoryStore
from app.services.verification import hash_token
from app.workers import celery_app
from app.workers.dispatch import dispatch_scan
from app.workers.tasks import (
    SCAN_PIPELINE,
    idempotency_key,
    normalize_domain,
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
    """Point the workers at this test's real in-memory store."""
    monkeypatch.setattr("app.workers.tasks._load_store", lambda: store)
    monkeypatch.setattr("app.workers.dispatch._load_store", lambda: store)
    # Worker tests must not depend on network/DNS: the SSRF pre-check
    # does live DNS resolution in the real guard.
    monkeypatch.setattr("app.workers.tasks._assert_verification_url_safe", lambda domain: None)
    return store


def _verified_scan(store: InMemoryStore, domain: str = "example.com") -> tuple[str, str, UUID]:
    """Create a verified target + queued scan. Returns (scan_id, user_id,
    target_id) as strings the task args carry (UUIDs as strings)."""
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
# Celery app configuration
# ---------------------------------------------------------------------------


def test_celery_app_uses_json_only() -> None:
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"
    assert celery_app.conf.accept_content == ["json"]


def test_celery_app_reliability_settings() -> None:
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.worker_prefetch_multiplier == 1


def test_celery_app_routes_by_task_name() -> None:
    routes = celery_app.conf.task_routes
    assert routes is not None
    assert routes["*.recon.*"] == {"queue": "recon"}
    assert routes["*.crawl.*"] == {"queue": "crawl"}
    assert routes["*.vuln.*"] == {"queue": "vuln"}


def test_celery_app_time_limit_ceiling_is_vuln_30_min() -> None:
    assert celery_app.conf.task_time_limit == 1800


def test_verify_target_task_name_routes_to_recon() -> None:
    assert verify_target.name == "websurfacehq.recon.verify_target"


# ---------------------------------------------------------------------------
# Pipeline registry
# ---------------------------------------------------------------------------


def test_pipeline_has_all_13_stages_in_order() -> None:
    assert [s.stage for s in SCAN_PIPELINE] == [
        "verify_target",
        "dns_enum",
        "subdomain_enum",
        "port_scan",
        "http_probe",
        "tech_fingerprint",
        "crawl",
        "js_secret_scan",
        "nuclei_scan",
        "ai_triage",
        "enrichment",
        "generate_report",
        "notify_user",
    ]


def test_pipeline_only_verify_target_implemented_in_week_1() -> None:
    implemented = [s.stage for s in SCAN_PIPELINE if s.implemented]
    assert implemented == ["verify_target"]


def test_pipeline_queues_match_architecture() -> None:
    by_stage = {s.stage: s.queue for s in SCAN_PIPELINE}
    assert by_stage["verify_target"] == "recon"
    assert by_stage["dns_enum"] == "recon"
    assert by_stage["crawl"] == "crawl"
    assert by_stage["js_secret_scan"] == "crawl"
    assert by_stage["nuclei_scan"] == "vuln"


# ---------------------------------------------------------------------------
# Idempotency key / domain normalisation
# ---------------------------------------------------------------------------


def test_target_hash_normalises_domain_variants() -> None:
    expected = target_hash_for("example.com")
    assert target_hash_for("Example.COM/") == expected
    assert target_hash_for("https://example.com") == expected
    assert target_hash_for("example.com.") == expected
    assert target_hash_for("  EXAMPLE.com  ") == expected
    assert len(expected) == 12


def test_normalize_domain_strips_scheme_path_port() -> None:
    assert normalize_domain("https://Sub.Example.com:8443/a/b") == ("sub.example.com")


def test_idempotency_key_format() -> None:
    key = idempotency_key("scan-1", "verify_target", "example.com")
    assert key == f"scan-1:verify_target:{target_hash_for('example.com')}"


# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------


def test_retry_policy_is_configured() -> None:
    assert verify_target.max_retries == 3
    assert verify_target.autoretry_for == (Exception,)
    assert verify_target.retry_backoff == 60
    assert verify_target.retry_backoff_max == 900
    assert verify_target.retry_jitter is False


def test_realised_backoff_delays_are_60_120_240() -> None:
    """Celery's native exponential is min(900, 60 * 2**retries).

    The blueprint's nominal 60/300/900 s is not expressible as Celery's
    doubling formula; the configured values realise 60/120/240 s.
    """
    delays = [
        get_exponential_backoff_interval(factor=60, retries=r, maximum=900, full_jitter=False)
        for r in range(3)
    ]
    assert delays == [60, 120, 240]


# ---------------------------------------------------------------------------
# verify_target — verification gate
# ---------------------------------------------------------------------------


def test_verify_target_refuses_unverified_target(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid.uuid4()
    target = store.create_target(user_id, "example.com", hash_token("tok"))
    scan = store.create_scan(user_id, target.id, {})

    def _must_not_be_called(domain: str, token_hash: str, method: str | None) -> bool:
        raise AssertionError("verification re-check must not be called for an unverified target")

    monkeypatch.setattr("app.workers.tasks._recheck_verification", _must_not_be_called)

    result = verify_target.apply_async(args=[str(scan.id), str(user_id)]).get()

    assert result["status"] == "refused"
    assert result["error"] == "TARGET_NOT_VERIFIED"
    reloaded = store.get_scan(user_id, scan.id)
    assert reloaded is not None and reloaded.status == "failed"
    assert reloaded.error == "TARGET_NOT_VERIFIED"
    assert _audit_count(store) == 1
    # The refusal is a completed execution: its job row is done, so a
    # redelivery returns the stored refusal instead of re-running.
    key = idempotency_key(str(scan.id), "verify_target", "example.com")
    job = store.get_scan_job_by_key(user_id, key)
    assert job is not None and job.status == "done"


def test_verify_target_refusal_audit_hashes_scan_id(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Round-2 review (L3): worker audit metadata must carry the HASH of
    # the scan id, never the raw id (routers already do this).
    import hashlib

    user_id = uuid.uuid4()
    target = store.create_target(user_id, "example.com", hash_token("tok"))
    scan = store.create_scan(user_id, target.id, {})

    def _must_not_be_called(domain: str, token_hash: str, method: str | None) -> bool:
        raise AssertionError("verification re-check must not be called for an unverified target")

    monkeypatch.setattr("app.workers.tasks._recheck_verification", _must_not_be_called)

    result = verify_target.apply_async(args=[str(scan.id), str(user_id)]).get()
    assert result["status"] == "refused"
    entries = list(store._audit.values())
    assert len(entries) == 1
    assert entries[0].action == "scan_refused_unverified_target"
    assert entries[0].metadata["scan_id_hash"] == hashlib.sha256(str(scan.id).encode()).hexdigest()
    assert "scan_id" not in entries[0].metadata


def test_verify_target_accepts_verified_target(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, target_id = _verified_scan(store)
    calls: list[tuple[str, str, str | None]] = []

    def _fake_recheck(domain: str, token_hash: str, method: str | None) -> bool:
        calls.append((domain, token_hash, method))
        return True

    monkeypatch.setattr("app.workers.tasks._recheck_verification", _fake_recheck)

    result = verify_target.apply_async(args=[scan_id, user_id]).get()

    assert result == {
        "status": "verified",
        "scan_id": scan_id,
        "target_id": str(target_id),
        "domain": "example.com",
    }
    # Re-checked against the STORED HASH (raw token never stored), method
    # as recorded on the target.
    assert calls == [("example.com", hash_token("tok-123"), "file")]
    reloaded_target = store.get_target(UUID(user_id), target_id)
    assert reloaded_target is not None
    assert reloaded_target.verification_status == "verified"
    reloaded_scan = store.get_scan(UUID(user_id), UUID(scan_id))
    assert reloaded_scan is not None and reloaded_scan.status == "recon"
    assert _audit_count(store) == 0


def test_verify_target_live_recheck_failure_fails_scan(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _verified_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks._recheck_verification",
        lambda domain, token_hash, method: False,
    )

    result = verify_target.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "refused"
    assert result["error"] == "TARGET_VERIFICATION_FAILED"
    reloaded = store.get_scan(UUID(user_id), UUID(scan_id))
    assert reloaded is not None and reloaded.status == "failed"
    assert reloaded.error == "TARGET_VERIFICATION_FAILED"
    assert _audit_count(store) == 1


def test_verify_target_unknown_method_refuses_without_retries(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A target whose method is corrupt (None): the re-check raises
    # ValueError, which must become a clean refusal, not 3 retries.
    user_id = uuid.uuid4()
    target = store.create_target(user_id, "example.com", hash_token("tok"))
    store.update_target_verification(user_id, target.id, status="verified", method=None)
    scan = store.create_scan(user_id, target.id, {})
    calls: list[str] = []

    def _raising_recheck(domain: str, token_hash: str, method: str | None) -> bool:
        calls.append(domain)
        raise ValueError("Unknown verification method: ''")

    monkeypatch.setattr("app.workers.tasks._recheck_verification", _raising_recheck)

    result = verify_target.apply_async(args=[str(scan.id), str(user_id)]).get()

    assert result["status"] == "refused"
    assert result["error"] == "TARGET_VERIFICATION_FAILED"
    assert calls == ["example.com"]  # called once — no autoretry
    reloaded = store.get_scan(user_id, scan.id)
    assert reloaded is not None and reloaded.status == "failed"


# ---------------------------------------------------------------------------
# dispatch_scan
# ---------------------------------------------------------------------------


def test_dispatch_scan_twice_creates_no_duplicates(
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

    first = dispatch_scan(scan_id, user_id)
    assert first["enqueued"] is True
    assert first["task_id"] == (f"{scan_id}:verify_target:{target_hash_for('example.com')}")
    assert len(first["stages"]) == len(SCAN_PIPELINE)
    assert {s["stage"] for s in first["stages"]} == {s.stage for s in SCAN_PIPELINE}
    # Only verify_target ran (eager); every other stage is a queued row.
    key = idempotency_key(scan_id, "verify_target", "example.com")
    verify_job = store.get_scan_job_by_key(user_uuid, key)
    assert verify_job is not None and verify_job.status == "done"
    for stage in SCAN_PIPELINE:
        if stage.stage != "verify_target":
            row = store.get_scan_job_by_key(
                user_uuid,
                idempotency_key(scan_id, stage.stage, "example.com"),
            )
            assert row is not None and row.status == "queued"
    reloaded_scan = store.get_scan(user_uuid, UUID(scan_id))
    assert reloaded_scan is not None and reloaded_scan.status == "recon"

    second = dispatch_scan(scan_id, user_id)
    assert second["enqueued"] is False
    assert second["task_id"] == first["task_id"]
    # The store does not dedupe create_scan_job, so this count is the
    # proof dispatch's exists-check is the guard that works.
    assert len(store._scan_jobs) == len(SCAN_PIPELINE)
    assert check_calls == ["example.com"]  # verify_target ran exactly once
    reloaded_scan = store.get_scan(user_uuid, UUID(scan_id))
    assert reloaded_scan is not None and reloaded_scan.status == "recon"


def test_dispatch_scan_unknown_scan_raises(
    _patched_store: InMemoryStore,
) -> None:
    with pytest.raises(ValueError, match="scan not found"):
        dispatch_scan(str(uuid.uuid4()), str(uuid.uuid4()))
