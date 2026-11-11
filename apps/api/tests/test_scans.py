"""Scans endpoint matrix (docs/testing.md §3): 401s, own 200/202, other
tenant -> 404, nonexistent -> 404, invalid body -> 422. Plus the
verification gate (409 TARGET_NOT_VERIFIED), the Free quota (4th scan in
the month -> 429 QUOTA_EXCEEDED, 2nd concurrent active scan -> 429), and
cancel rules (done -> 409 SCAN_CONFLICT).
"""

import hashlib
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from app.core.errors import ApiError
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


def _verified_target(store: InMemoryStore, user_id: UUID, domain: str) -> UUID:
    target = store.create_target(user_id, domain, hashlib.sha256(b"seed-token").hexdigest())
    store.update_target_verification(user_id, target.id, status="verified", method="dns")
    return target.id


def _pending_target(store: InMemoryStore, user_id: UUID, domain: str) -> UUID:
    target = store.create_target(user_id, domain, hashlib.sha256(b"seed-token").hexdigest())
    return target.id


def test_matrix_no_token_and_bad_token_401() -> None:
    store = InMemoryStore()
    client = _client(store, None)
    assert client.get("/api/v1/scans/").status_code == 401
    assert client.post("/api/v1/scans/", json={"target_id": str(uuid4())}).status_code == 401
    assert client.get(f"/api/v1/scans/{uuid4()}").status_code == 401
    assert client.get(f"/api/v1/scans/{uuid4()}/progress").status_code == 401
    assert client.post(f"/api/v1/scans/{uuid4()}/cancel").status_code == 401
    # Bad token: override with a 401 raiser.
    app = create_app()

    def _raise() -> User:
        raise ApiError(401, "UNAUTHORIZED", "Authentication required")

    app.dependency_overrides[get_current_user] = _raise
    app.dependency_overrides[get_store_dep] = lambda: store
    bad = TestClient(app)
    assert bad.get("/api/v1/scans/").status_code == 401


def test_create_scan_202_queued_and_progress() -> None:
    store = InMemoryStore()
    target_id = _verified_target(store, TENANT_A_USER_ID, "ok.example.com")
    client = _client(store, USER_A)
    resp = client.post(
        "/api/v1/scans/",
        json={"target_id": str(target_id), "config": {"depth": "quick", "max_urls": 50}},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "queued" and body["progress"] == 0
    assert body["config"] == {"depth": "quick", "max_urls": 50}
    progress = client.get(f"/api/v1/scans/{body['id']}/progress")
    assert progress.status_code == 200
    assert progress.json() == {
        "scan_id": body["id"],
        "status": "queued",
        "progress": 0,
    }
    assert client.get(f"/api/v1/scans/{body['id']}").status_code == 200


def test_create_scan_unverified_target_409() -> None:
    store = InMemoryStore()
    target_id = _pending_target(store, TENANT_A_USER_ID, "pending.example.com")
    client = _client(store, USER_A)
    resp = client.post("/api/v1/scans/", json={"target_id": str(target_id)})
    assert resp.status_code == 409
    assert resp.json()["code"] == "TARGET_NOT_VERIFIED"
    assert resp.json()["details"]["verification_status"] == "pending"


def test_create_scan_other_tenant_target_404_not_409() -> None:
    # Tenant check first: B's target is 404 for A even though it is also
    # unverified — state must never leak across tenants.
    store = InMemoryStore()
    target_b = _pending_target(store, TENANT_B_USER_ID, "b.example.com")
    client = _client(store, USER_A)
    resp = client.post("/api/v1/scans/", json={"target_id": str(target_b)})
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"


def test_create_scan_invalid_body_422() -> None:
    store = InMemoryStore()
    target_id = _verified_target(store, TENANT_A_USER_ID, "v.example.com")
    client = _client(store, USER_A)
    assert client.post("/api/v1/scans/", json={}).status_code == 422
    assert client.post("/api/v1/scans/", json={"target_id": "not-a-uuid"}).status_code == 422
    assert (
        client.post(
            "/api/v1/scans/",
            json={"target_id": str(target_id), "config": {"depth": "turbo"}},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/scans/",
            json={"target_id": str(target_id), "config": {"max_urls": 0}},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/scans/",
            json={"target_id": str(target_id), "config": {"max_urls": 501}},
        ).status_code
        == 422
    )
    # Nonexistent target -> 404.
    assert client.post("/api/v1/scans/", json={"target_id": str(uuid4())}).status_code == 404


def test_quota_fourth_scan_in_month_429() -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    # Three scans, each cancelled so the active-scan cap never trips;
    # the 4th must hit the monthly quota.
    for i in range(3):
        target_id = _verified_target(store, TENANT_A_USER_ID, f"q{i}.example.com")
        resp = client.post("/api/v1/scans/", json={"target_id": str(target_id)})
        assert resp.status_code == 202, resp.text
        assert client.post(f"/api/v1/scans/{resp.json()['id']}/cancel").status_code == 200
    target4 = _verified_target(store, TENANT_A_USER_ID, "q3.example.com")
    resp = client.post("/api/v1/scans/", json={"target_id": str(target4)})
    assert resp.status_code == 429
    assert resp.json()["code"] == "QUOTA_EXCEEDED"
    assert resp.headers.get("retry-after")  # Retry-After is always set on 429


def test_quota_second_active_scan_429() -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    t1 = _verified_target(store, TENANT_A_USER_ID, "a1.example.com")
    t2 = _verified_target(store, TENANT_A_USER_ID, "a2.example.com")
    assert client.post("/api/v1/scans/", json={"target_id": str(t1)}).status_code == 202
    resp = client.post("/api/v1/scans/", json={"target_id": str(t2)})
    assert resp.status_code == 429
    assert resp.json()["code"] == "QUOTA_EXCEEDED"


def test_get_scan_matrix_and_list_tenant_scoped() -> None:
    store = InMemoryStore()
    client_a = _client(store, USER_A)
    client_b = _client(store, USER_B)
    t_a = _verified_target(store, TENANT_A_USER_ID, "la.example.com")
    t_b = _verified_target(store, TENANT_B_USER_ID, "lb.example.com")
    scan_a = client_a.post("/api/v1/scans/", json={"target_id": str(t_a)}).json()
    scan_b = client_b.post("/api/v1/scans/", json={"target_id": str(t_b)}).json()
    # Cross-tenant reads -> 404 with no data.
    resp = client_b.get(f"/api/v1/scans/{scan_a['id']}")
    assert resp.status_code == 404
    assert "la.example.com" not in resp.text
    assert client_a.get(f"/api/v1/scans/{scan_b['id']}").status_code == 404
    assert client_a.get(f"/api/v1/scans/{uuid4()}").status_code == 404
    assert client_b.get(f"/api/v1/scans/{scan_a['id']}/progress").status_code == 404
    # Lists are tenant-scoped.
    assert [s["id"] for s in client_a.get("/api/v1/scans/").json()["data"]] == [scan_a["id"]]
    assert [s["id"] for s in client_b.get("/api/v1/scans/").json()["data"]] == [scan_b["id"]]


def test_cancel_scan_rules() -> None:
    store = InMemoryStore()
    client_a = _client(store, USER_A)
    client_b = _client(store, USER_B)
    t_a = _verified_target(store, TENANT_A_USER_ID, "c.example.com")
    scan = client_a.post("/api/v1/scans/", json={"target_id": str(t_a)}).json()
    # Other tenant cancel -> 404.
    assert client_b.post(f"/api/v1/scans/{scan['id']}/cancel").status_code == 404
    # Own cancel -> 200, status cancelled.
    resp = client_a.post(f"/api/v1/scans/{scan['id']}/cancel")
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"
    # Cancelling again (terminal) -> 409 SCAN_CONFLICT.
    resp = client_a.post(f"/api/v1/scans/{scan['id']}/cancel")
    assert resp.status_code == 409
    assert resp.json()["code"] == "SCAN_CONFLICT"
    # Cancelling a done scan -> 409 too.
    t2 = _verified_target(store, TENANT_A_USER_ID, "c2.example.com")
    scan2 = client_a.post("/api/v1/scans/", json={"target_id": str(t2)}).json()
    store.update_scan(TENANT_A_USER_ID, UUID(scan2["id"]), status="done")
    resp = client_a.post(f"/api/v1/scans/{scan2['id']}/cancel")
    assert resp.status_code == 409
    assert resp.json()["code"] == "SCAN_CONFLICT"
    assert client_a.post(f"/api/v1/scans/{uuid4()}/cancel").status_code == 404
