"""Real tests for the Phase 0 skeleton: health, liveness, error shape,
security headers. Uses fastapi.testclient.TestClient against the real app —
no mocks.
"""

import uuid

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_200_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


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
