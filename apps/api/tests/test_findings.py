"""Findings endpoint matrix (docs/testing.md §3): 401s, own 200, other
tenant -> 404, nonexistent -> 404, invalid body -> 422. Plus the severity
filter, cursor pagination, and the feedback rule (status changes, ai_*
fields untouched, audit logged).
"""

from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from app.core.errors import ApiError
from app.db.memory import (
    TENANT_A_USER_ID,
    TENANT_B_USER_ID,
    InMemoryStore,
    seed_two_tenants,
)
from app.main import create_app
from app.routers.deps import User, get_current_user, get_store_dep

USER_A = User(id=TENANT_A_USER_ID, email="a@example.com")
USER_B = User(id=TENANT_B_USER_ID, email="b@example.com")


def _seeded() -> tuple[InMemoryStore, dict[str, UUID]]:
    store = InMemoryStore()
    ids = seed_two_tenants(store)
    return store, ids


def _client(store: InMemoryStore, user: User | None) -> TestClient:
    app = create_app()
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_store_dep] = lambda: store
    return TestClient(app)


def test_matrix_no_token_401() -> None:
    store, ids = _seeded()
    client = _client(store, None)
    assert client.get(f"/api/v1/scans/{ids['scan_a_id']}/findings").status_code == 401
    assert client.get(f"/api/v1/findings/{ids['finding_a_id']}").status_code == 401
    assert (
        client.post(
            f"/api/v1/findings/{ids['finding_a_id']}/feedback",
            json={"verdict": "confirmed"},
        ).status_code
        == 401
    )


def test_matrix_bad_token_401() -> None:
    store, _ = _seeded()
    app = create_app()

    def _raise() -> User:
        raise ApiError(401, "UNAUTHORIZED", "Authentication required")

    app.dependency_overrides[get_current_user] = _raise
    app.dependency_overrides[get_store_dep] = lambda: store
    assert TestClient(app).get("/api/v1/findings/x").status_code == 401


def test_list_findings_own_200_and_severity_filter() -> None:
    store, ids = _seeded()
    client = _client(store, USER_A)
    # Add a high finding so the filter has something to split on.
    store.create_finding(
        TENANT_A_USER_ID,
        ids["scan_a_id"],
        ids["target_a_id"],
        "tpl-high",
        "High issue",
        "high",
        ai_verdict="likely_true",
        ai_confidence=90,
    )
    resp = client.get(f"/api/v1/scans/{ids['scan_a_id']}/findings")
    assert resp.status_code == 200
    assert len(resp.json()["data"]) == 2
    highs = client.get(f"/api/v1/scans/{ids['scan_a_id']}/findings?severity=high").json()
    assert len(highs["data"]) == 1
    assert highs["data"][0]["severity"] == "high"
    mediums = client.get(f"/api/v1/scans/{ids['scan_a_id']}/findings?severity=medium").json()
    assert len(mediums["data"]) == 1
    # Invalid severity -> 422; bad cursor -> 422.
    assert (
        client.get(f"/api/v1/scans/{ids['scan_a_id']}/findings?severity=bogus").status_code == 422
    )
    assert client.get(f"/api/v1/scans/{ids['scan_a_id']}/findings?cursor=nope").status_code == 422
    # Pagination: limit=1 walks both findings without repeats.
    p1 = client.get(f"/api/v1/scans/{ids['scan_a_id']}/findings?limit=1").json()
    assert len(p1["data"]) == 1 and p1["has_more"] is True
    p2 = client.get(
        f"/api/v1/scans/{ids['scan_a_id']}/findings?limit=1&cursor={p1['next_cursor']}"
    ).json()
    assert len(p2["data"]) == 1 and p2["has_more"] is False
    assert p1["data"][0]["id"] != p2["data"][0]["id"]


def test_list_findings_cross_tenant_and_nonexistent_404() -> None:
    store, ids = _seeded()
    client_b = _client(store, USER_B)
    # B asking for A's scan findings -> 404, no data leaked.
    resp = client_b.get(f"/api/v1/scans/{ids['scan_a_id']}/findings")
    assert resp.status_code == 404
    assert "example-a.com" not in resp.text
    assert "Missing security headers" not in resp.text
    client_a = _client(store, USER_A)
    assert client_a.get(f"/api/v1/scans/{uuid4()}/findings").status_code == 404


def test_get_finding_matrix() -> None:
    store, ids = _seeded()
    client_a = _client(store, USER_A)
    client_b = _client(store, USER_B)
    resp = client_a.get(f"/api/v1/findings/{ids['finding_a_id']}")
    assert resp.status_code == 200
    assert resp.json()["title"] == "Missing security headers"
    assert client_b.get(f"/api/v1/findings/{ids['finding_a_id']}").status_code == 404
    assert client_a.get(f"/api/v1/findings/{uuid4()}").status_code == 404
    assert client_a.get("/api/v1/findings/not-a-uuid").status_code == 422


def test_feedback_updates_status_only() -> None:
    store, ids = _seeded()
    client_a = _client(store, USER_A)
    client_b = _client(store, USER_B)
    finding_id = ids["finding_a_id"]
    # Cross-tenant feedback -> 404.
    assert (
        client_b.post(
            f"/api/v1/findings/{finding_id}/feedback",
            json={"verdict": "confirmed"},
        ).status_code
        == 404
    )
    # Invalid verdict -> 422.
    assert (
        client_a.post(
            f"/api/v1/findings/{finding_id}/feedback", json={"verdict": "maybe"}
        ).status_code
        == 422
    )
    # Seed finding has no ai fields; give it some, then verify feedback
    # leaves them alone. (Direct dict access: test setup only.)
    store._findings[finding_id].ai_verdict = "likely_true"
    store._findings[finding_id].ai_confidence = 75
    resp = client_a.post(
        f"/api/v1/findings/{finding_id}/feedback",
        json={"verdict": "false_positive"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "false_positive"
    assert body["ai_verdict"] == "likely_true"
    assert body["ai_confidence"] == 75
    # Nonexistent -> 404.
    assert (
        client_a.post(
            f"/api/v1/findings/{uuid4()}/feedback", json={"verdict": "confirmed"}
        ).status_code
        == 404
    )
