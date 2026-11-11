"""Real tests for the Phase 0 skeleton: health, liveness, error shape,
security headers. Uses fastapi.testclient.TestClient against the real app —
no mocks.
"""

import uuid
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.db import reset_store_for_tests
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def _in_memory_store(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Isolate /health from the environment (review fix F-M1).

    ``/health`` reads the database component through the module
    singleton ``app.db.get_store()``. Without this fixture the test
    asserts ``database.status == "ok"`` against whatever store an
    earlier test primed (``test_auth.py``'s logout test leaves an
    ``InMemoryStore`` cached) — and run alone with a real ``.env``
    present, ``get_store()`` selects ``SupabaseStore`` and the ping
    hits live PostgREST (403 pre-0005) and the test fails. So this
    fixture forces the in-memory store for every test in this file:
    it clears the Supabase credentials (``supabase_configured`` is a
    property derived from them, so no other switch is needed) and
    drops the cached singleton before AND after each test, so no
    primed store leaks in or out. There is deliberately NO assertion
    here about a live Supabase database — that belongs in an explicit
    integration test against a real project, not in this file.
    """
    monkeypatch.setattr(settings, "supabase_url", None)
    monkeypatch.setattr(settings, "supabase_anon_key", None)
    monkeypatch.setattr(settings, "supabase_service_role_key", None)
    reset_store_for_tests()
    yield
    reset_store_for_tests()


def test_health_returns_200_with_component_status() -> None:
    # Week 1 contract: /health returns {"status", "components"} — the
    # status is "ok" only when every configured component is up; in this
    # test environment Redis is not running, so "degraded" is the honest
    # answer and the test asserts the SHAPE, not a fixed status.
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"status", "components"}
    assert body["status"] in ("ok", "degraded")
    assert set(body["components"].keys()) == {"database", "redis", "queue"}
    assert body["components"]["database"]["status"] == "ok"


def test_live_returns_200_alive() -> None:
    response = client.get("/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_unknown_route_returns_404_in_standard_error_shape() -> None:
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert set(body.keys()) == {"code", "message", "details"}
    assert body["code"] == "NOT_FOUND"
    assert isinstance(body["message"], str) and body["message"]


def test_security_headers_present_on_health() -> None:
    response = client.get("/health")
    assert response.headers["strict-transport-security"].startswith("max-age=63072000")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_request_id_header_present() -> None:
    response = client.get("/health")
    assert response.headers["x-request-id"]


def test_request_id_header_rejects_non_uuid() -> None:
    # A client-supplied X-Request-ID must parse as a UUID; anything else is
    # replaced with a fresh server-generated UUID (never echoed back).
    response = client.get("/health", headers={"X-Request-ID": "not-a-uuid"})
    returned = response.headers["x-request-id"]
    assert returned != "not-a-uuid"
    uuid.UUID(returned)  # parses as a UUID or the test fails


def test_request_id_header_accepts_valid_uuid() -> None:
    sent = str(uuid.uuid4())
    response = client.get("/health", headers={"X-Request-ID": sent})
    assert response.headers["x-request-id"] == sent
