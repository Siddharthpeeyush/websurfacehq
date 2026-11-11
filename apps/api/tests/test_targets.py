"""Targets endpoint matrix (docs/testing.md §3): no token -> 401, bad
token -> 401, own -> 200/201, other tenant id in URL -> 404, nonexistent
id -> 404, invalid body -> 422. Plus duplicate 409, verify success /
failure / expiry, and soft-delete behaviour. Uses InMemoryStore + the
get_current_user dependency override (Builder B's FakeAuth pattern).
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.errors import ApiError
from app.db.memory import TENANT_A_USER_ID, TENANT_B_USER_ID, InMemoryStore
from app.main import create_app
from app.routers.deps import User, get_current_user, get_store_dep
from app.services import verification

USER_A = User(id=TENANT_A_USER_ID, email="a@example.com")
USER_B = User(id=TENANT_B_USER_ID, email="b@example.com")


def _client(store: InMemoryStore, user: User | None) -> TestClient:
    app = create_app()
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_store_dep] = lambda: store
    return TestClient(app)


def _bad_token_client(store: InMemoryStore) -> TestClient:
    app = create_app()

    def _raise() -> User:
        raise ApiError(401, "UNAUTHORIZED", "Authentication required")

    app.dependency_overrides[get_current_user] = _raise
    app.dependency_overrides[get_store_dep] = lambda: store
    return TestClient(app)


def _create_target(client: TestClient, domain: str = "example.com") -> dict[str, Any]:
    resp = client.post("/api/v1/targets/", json={"domain": domain})
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    return body


def test_matrix_no_token_401() -> None:
    store = InMemoryStore()
    client = _client(store, None)
    assert client.get("/api/v1/targets/").status_code == 401
    assert client.post("/api/v1/targets/", json={"domain": "x.com"}).status_code == 401
    assert client.get(f"/api/v1/targets/{uuid4()}").status_code == 401
    assert (
        client.post(f"/api/v1/targets/{uuid4()}/verify", json={"method": "dns"}).status_code == 401
    )
    assert client.delete(f"/api/v1/targets/{uuid4()}").status_code == 401


def test_matrix_bad_token_401() -> None:
    store = InMemoryStore()
    client = _bad_token_client(store)
    resp = client.get("/api/v1/targets/")
    assert resp.status_code == 401
    assert resp.json()["code"] == "UNAUTHORIZED"


def test_create_target_returns_raw_token_once() -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    body = _create_target(client, "shop.example.com")
    assert body["domain"] == "shop.example.com"
    assert body["verification_status"] == "pending"
    assert len(body["verification_token"]) == 43  # 32 bytes, urlsafe
    assert body["verification_token"] in body["verification_instructions"]["dns_txt_record"]
    assert body["verification_token"] in body["verification_instructions"]["file_content"]
    # The stored row keeps only the hash, never the raw token.
    stored = store.get_target(TENANT_A_USER_ID, UUID(body["id"]))
    assert stored is not None
    assert (
        stored.verification_token_hash
        == hashlib.sha256(body["verification_token"].encode()).hexdigest()
    )
    assert body["verification_token"] not in stored.verification_token_hash


def test_create_duplicate_409_and_invalid_domain_422() -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    _create_target(client, "dup.example.com")
    resp = client.post("/api/v1/targets/", json={"domain": "dup.example.com"})
    assert resp.status_code == 409
    # Same domain for tenant B is a different tenant — allowed.
    client_b = _client(store, USER_B)
    assert client_b.post("/api/v1/targets/", json={"domain": "dup.example.com"}).status_code == 201
    for bad in [
        "not a domain",
        "https://example.com",
        "example.com:8080",
        "user@example.com",
        "localhost",
        "a" * 254,
        "",
    ]:
        resp = client.post("/api/v1/targets/", json={"domain": bad})
        assert resp.status_code == 422, (bad, resp.text)
        assert resp.json()["code"] == "VALIDATION_ERROR"
    assert client.post("/api/v1/targets/", json={}).status_code == 422


def test_target_cap_second_domain_429() -> None:
    # M3 review fix: Free allows 1 domain. A second, different domain is
    # 429 QUOTA_EXCEEDED (with a Retry-After header). A duplicate of the
    # first domain is still 409 (the duplicate check runs before the cap).
    store = InMemoryStore()
    client = _client(store, USER_A)
    _create_target(client, "first.example.com")
    dup = client.post("/api/v1/targets/", json={"domain": "first.example.com"})
    assert dup.status_code == 409
    response = client.post("/api/v1/targets/", json={"domain": "second.example.com"})
    assert response.status_code == 429
    assert response.json()["code"] == "QUOTA_EXCEEDED"
    assert response.headers["retry-after"]
    # The other tenant still has their own slot.
    client_b = _client(store, USER_B)
    assert _create_target(client_b, "b-first.example.com")["domain"] == "b-first.example.com"


def test_get_target_matrix() -> None:
    store = InMemoryStore()
    client_a = _client(store, USER_A)
    client_b = _client(store, USER_B)
    body = _create_target(client_a, "mine.example.com")
    target_id = body["id"]
    # Own -> 200.
    assert client_a.get(f"/api/v1/targets/{target_id}").status_code == 200
    # Other tenant -> 404, and the body carries no data.
    resp = client_b.get(f"/api/v1/targets/{target_id}")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"
    assert "mine.example.com" not in resp.text
    # Nonexistent -> 404, indistinguishable from cross-tenant.
    assert client_a.get(f"/api/v1/targets/{uuid4()}").status_code == 404
    # Non-UUID id -> 422.
    assert client_a.get("/api/v1/targets/not-a-uuid").status_code == 422


def test_list_targets_tenant_scoped_and_paginated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The Free cap is 1 domain; this pagination test needs 3, so raise it
    # for the test only (the cap itself is covered by test_target_cap_*).
    monkeypatch.setattr("app.routers.targets.settings.max_targets_free", 10)
    store = InMemoryStore()
    client_a = _client(store, USER_A)
    client_b = _client(store, USER_B)
    for i in range(3):
        _create_target(client_a, f"a{i}.example.com")
    _create_target(client_b, "b.example.com")
    page1 = client_a.get("/api/v1/targets/?limit=2")
    assert page1.status_code == 200
    data1 = page1.json()
    assert len(data1["data"]) == 2 and data1["has_more"] is True
    assert data1["next_cursor"]
    page2 = client_a.get(f"/api/v1/targets/?limit=2&cursor={data1['next_cursor']}")
    assert len(page2.json()["data"]) == 1
    assert page2.json()["has_more"] is False
    assert all(d["domain"].startswith("a") for d in data1["data"])
    # B sees only B's target.
    listed_b = client_b.get("/api/v1/targets/").json()
    assert [d["domain"] for d in listed_b["data"]] == ["b.example.com"]


def test_verify_success_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    body = _create_target(client, "verify.example.com")
    token = body["verification_token"]
    # Mock the DNS lookup: publish exactly the right TXT value.
    monkeypatch.setattr(
        verification,
        "fetch_dns_txt_value",
        lambda domain: token if domain == "verify.example.com" else None,
    )
    resp = client.post(f"/api/v1/targets/{body['id']}/verify", json={"method": "dns"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["verification_status"] == "verified"
    assert resp.json()["checked"] == {"method": "dns", "record_found": True}
    # The expected token value is never echoed back.
    assert token not in resp.text
    stored = store.get_target(TENANT_A_USER_ID, UUID(body["id"]))
    assert stored is not None and stored.verification_method == "dns"


def test_verify_failure_returns_200_with_what_was_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    body = _create_target(client, "noverify.example.com")
    token = body["verification_token"]
    monkeypatch.setattr(verification, "fetch_dns_txt_value", lambda domain: None)
    resp = client.post(f"/api/v1/targets/{body['id']}/verify", json={"method": "dns"})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["verification_status"] == "pending"
    assert payload["checked"] == {"method": "dns", "record_found": False}
    assert token not in resp.text
    # Invalid method -> 422.
    assert (
        client.post(f"/api/v1/targets/{body['id']}/verify", json={"method": "meta"}).status_code
        == 422
    )


def test_verify_other_tenant_404_and_nonexistent_404() -> None:
    store = InMemoryStore()
    client_a = _client(store, USER_A)
    client_b = _client(store, USER_B)
    body = _create_target(client_a, "cross.example.com")
    assert (
        client_b.post(f"/api/v1/targets/{body['id']}/verify", json={"method": "dns"}).status_code
        == 404
    )
    assert (
        client_a.post(f"/api/v1/targets/{uuid4()}/verify", json={"method": "dns"}).status_code
        == 404
    )


def test_verify_expired_token_410() -> None:
    store = InMemoryStore()
    client = _client(store, USER_A)
    body = _create_target(client, "old.example.com")
    stored = store.get_target(TENANT_A_USER_ID, UUID(body["id"]))
    assert stored is not None
    # Move the expiry instant into the past.
    stored.verification_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    resp = client.post(f"/api/v1/targets/{body['id']}/verify", json={"method": "file"})
    assert resp.status_code == 410
    assert resp.json()["code"] == "VERIFICATION_EXPIRED"


def test_delete_target_soft_delete_204() -> None:
    store = InMemoryStore()
    client_a = _client(store, USER_A)
    client_b = _client(store, USER_B)
    body = _create_target(client_a, "del.example.com")
    # Other tenant cannot delete -> 404, target survives.
    assert client_b.delete(f"/api/v1/targets/{body['id']}").status_code == 404
    assert client_a.get(f"/api/v1/targets/{body['id']}").status_code == 200
    # Own delete -> 204, then the target reads as 404.
    assert client_a.delete(f"/api/v1/targets/{body['id']}").status_code == 204
    assert client_a.get(f"/api/v1/targets/{body['id']}").status_code == 404
    assert client_a.delete(f"/api/v1/targets/{body['id']}").status_code == 404
