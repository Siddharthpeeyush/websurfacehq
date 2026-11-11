"""Integration tests (coordinator): the wiring between builders.

Covers what no single builder owned: routers mounted by ``create_app()``
(auth + targets + scans + findings all answer 401 without a token), the
``/health`` component payload, CORS preflight, and the scan-create →
``dispatch_scan`` wiring (called once on success; broker failure leaves
the scan queued instead of failing creation).
"""

from __future__ import annotations

import hashlib
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.db.memory import TENANT_A_USER_ID, TENANT_B_USER_ID, InMemoryStore
from app.main import create_app
from app.routers.deps import User, get_current_user, get_store_dep

USER_A = User(id=TENANT_A_USER_ID, email="a@example.com")
USER_B = User(id=TENANT_B_USER_ID, email="b@example.com")


def _client(store: InMemoryStore, user: User | None) -> TestClient:
    app = create_app()
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_store_dep] = lambda: store
    return TestClient(app)


def _verified_target_id(store: InMemoryStore) -> UUID:
    target = store.create_target(
        TENANT_A_USER_ID, "shop.example.com", hashlib.sha256(b"seed-token").hexdigest()
    )
    store.update_target_verification(TENANT_A_USER_ID, target.id, status="verified", method="dns")
    return target.id


def test_all_routers_mounted_and_require_auth() -> None:
    store = InMemoryStore()
    client = _client(store, None)
    # Every product route answers 401 with no token (proves the routers are
    # mounted by create_app() — a missing router would answer 404 instead).
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/targets/").status_code == 401
    assert client.get("/api/v1/scans/").status_code == 401
    assert client.get("/api/v1/scans/00000000-0000-4000-8000-000000000000").status_code == 401
    assert (
        client.get("/api/v1/scans/00000000-0000-4000-8000-000000000000/findings").status_code == 401
    )


def test_health_payload_shape() -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"status", "components"}
    assert body["status"] in ("ok", "degraded")
    assert body["components"]["database"]["status"] == "ok"
    # No Redis runs in this environment: the component must report
    # unreachable (not crash the endpoint, not claim ok).
    assert body["components"]["redis"]["status"] == "unreachable"


def test_cors_preflight_allows_frontend_origin() -> None:
    store = InMemoryStore()
    client = _client(store, None)
    resp = client.options(
        "/api/v1/targets/",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_create_scan_dispatches_pipeline_once(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    target_id = _verified_target_id(store)
    calls: list[tuple[str, str]] = []

    def _fake_dispatch(scan_id: str, user_id: str) -> None:
        calls.append((scan_id, user_id))

    monkeypatch.setattr("app.workers.dispatch.dispatch_scan", _fake_dispatch)
    resp = client.post("/api/v1/scans/", json={"target_id": str(target_id)})
    assert resp.status_code == 202, resp.text
    assert len(calls) == 1
    assert calls[0][0] == resp.json()["id"]
    assert calls[0][1] == str(TENANT_A_USER_ID)


def test_create_scan_survives_broker_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    target_id = _verified_target_id(store)

    def _failing_dispatch(scan_id: str, user_id: str) -> None:
        raise ConnectionError("broker unreachable")

    monkeypatch.setattr("app.workers.dispatch.dispatch_scan", _failing_dispatch)
    resp = client.post("/api/v1/scans/", json={"target_id": str(target_id)})
    # Creation still succeeds; the scan stays queued for a later retry.
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "queued"


def test_cross_tenant_probe_is_audited_but_still_404() -> None:
    # M8 review fix: requesting another tenant's target answers 404 (no
    # existence oracle) AND leaves an audit entry, so cross-tenant
    # probing is visible to ops. A nonexistent id logs nothing.
    store = InMemoryStore()
    client_b = _client(store, USER_B)
    target_a_id = _verified_target_id(store)
    resp = client_b.get(f"/api/v1/targets/{target_a_id}")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"
    denied = [a for a in store._audit.values() if a.action == "cross_tenant_access_denied"]
    assert len(denied) == 1
    assert denied[0].user_id == TENANT_B_USER_ID
    # The audit metadata carries a HASH of the id, never the raw id.
    assert denied[0].metadata["resource"] == "target"
    assert denied[0].metadata["resource_id_hash"] != str(target_a_id)
    # A nonexistent id: 404, no audit entry.
    before = len(store._audit)
    assert client_b.get("/api/v1/targets/00000000-0000-4000-8000-000000000000").status_code == 404
    assert len(store._audit) == before
    store = InMemoryStore()
    client = _client(store, USER_A)
    target_id = _verified_target_id(store)
    resp = client.post("/api/v1/scans/", json={"target_id": str(target_id)})
    assert resp.status_code == 202, resp.text
    # No invented queue/dispatch fields — the scan object is the API shape.
    assert set(resp.json().keys()) == {
        "id",
        "user_id",
        "target_id",
        "status",
        "config",
        "progress",
        "started_at",
        "finished_at",
        "error",
        "created_at",
        "updated_at",
    }
