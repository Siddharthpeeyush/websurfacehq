"""Tests for the auth endpoints (``/api/v1/auth``) and JWT verification.

Uses a test-only in-memory ``FakeAuthProvider`` (never shipped as a
production fallback) whose login tokens are real HS256 JWTs signed with
the test secret, so ``GET /me`` exercises the real ``verify_token`` path.

Matrix covered here: no token -> 401, bad token -> 401, good token -> 200;
rate limit: 6th login attempt within 15 min -> 429 with ``Retry-After``,
per IP AND per email; signup validation errors -> 422 without echoing the
password; callback with a bad code -> 401.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.auth.jwt import User
from app.auth.provider import (
    AuthSession,
    AuthUser,
    SupabaseAuthProvider,
    set_auth_provider,
)
from app.auth.rate_limit import RateLimiter, set_rate_limiter
from app.core.config import settings
from app.core.errors import ApiError
from app.main import create_app

TEST_SECRET = "test-jwt-secret-for-websurfacehq-week1"
USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery"


class FakeAuthProvider:
    """In-memory auth provider, TESTS ONLY.

    Passwords are stored as SHA-256 digests (test-only: no salt, no
    stretching — never a production pattern). Login tokens are real HS256
    JWTs so the real verification path is exercised end to end.
    """

    def __init__(self, secret: str = TEST_SECRET) -> None:
        self._secret = secret
        self._users: dict[str, dict[str, str]] = {}
        self._codes: dict[str, str] = {}
        self.revoked_tokens: set[str] = set()
        self.reset_requested: list[str] = []

    def _mint(self, user_id: str, email: str) -> AuthSession:
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": user_id,
                "email": email,
                "aud": "authenticated",
                "role": "authenticated",
                "iat": now,
                "exp": now + timedelta(hours=1),
            },
            self._secret,
            algorithm="HS256",
        )
        return AuthSession(
            access_token=token,
            token_type="bearer",
            expires_in=3600,
            user=AuthUser(id=uuid.UUID(user_id), email=email),
        )

    def sign_up(self, email: str, password: str) -> AuthUser | None:
        # Mirrors the real provider: already-registered returns None (the
        # router answers identically either way — no enumeration oracle).
        if email in self._users:
            return None
        user_id = str(uuid.uuid4())
        self._users[email] = {
            "id": user_id,
            "password_hash": hashlib.sha256(password.encode()).hexdigest(),
        }
        return AuthUser(id=uuid.UUID(user_id), email=email)

    def sign_in(self, email: str, password: str) -> AuthSession:
        record = self._users.get(email)
        digest = hashlib.sha256(password.encode()).hexdigest()
        if record is None or record["password_hash"] != digest:
            raise ApiError(401, "UNAUTHORIZED", "Invalid email or password")
        return self._mint(record["id"], email)

    def sign_out(self, access_token: str) -> None:
        self.revoked_tokens.add(access_token)

    def reset_password(self, email: str) -> None:
        self.reset_requested.append(email)

    def exchange_code(self, code: str) -> AuthSession:
        email = self._codes.get(code)
        if email is None:
            raise ApiError(401, "UNAUTHORIZED", "Invalid or expired code")
        record = self._users[email]
        return self._mint(record["id"], email)

    def issue_code(self, email: str) -> str:
        """Test helper: mint a valid PKCE code for ``email``."""
        code = uuid.uuid4().hex
        self._codes[code] = email
        return code


@pytest.fixture(autouse=True)
def _test_auth_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """JWT verification uses the test secret; no Supabase project exists."""
    monkeypatch.setattr(settings, "supabase_jwt_secret", SecretStr(TEST_SECRET))
    monkeypatch.setattr(settings, "supabase_url", None)


@pytest.fixture()
def auth_client() -> Generator[tuple[TestClient, FakeAuthProvider], None, None]:
    """Fresh app + fresh fake provider + fresh in-memory rate limiter."""
    fake = FakeAuthProvider()
    set_auth_provider(fake)
    set_rate_limiter(RateLimiter())
    app = create_app()
    client = TestClient(app)
    yield client, fake
    set_auth_provider(None)
    set_rate_limiter(None)


def _signup(client: TestClient, email: str = USER_EMAIL) -> dict[str, str]:
    response = client.post("/api/v1/auth/signup", json={"email": email, "password": USER_PASSWORD})
    assert response.status_code == 201, response.text
    body: dict[str, str] = response.json()
    return body


def _login_token(client: TestClient, email: str = USER_EMAIL) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": USER_PASSWORD})
    assert response.status_code == 200, response.text
    body: dict[str, object] = response.json()
    token = body["access_token"]
    assert isinstance(token, str)
    return token


# --- Signup -----------------------------------------------------------------


def test_signup_returns_201_with_message_and_no_user_data(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    body = _signup(client)
    assert "message" in body
    # No user id, email, or password is ever returned from signup.
    assert "id" not in body and "email" not in body and "password" not in body


def test_signup_duplicate_email_is_indistinguishable_from_fresh_signup(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    # H1 (review): a 409 on an existing email is an enumeration oracle.
    # Fresh and duplicate signups must answer identically (201 + same body).
    client, _fake = auth_client
    first = _signup(client)
    response = client.post(
        "/api/v1/auth/signup", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert response.status_code == 201
    assert response.json() == first


def test_signup_short_password_returns_422_without_echoing_it(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    response = client.post("/api/v1/auth/signup", json={"email": USER_EMAIL, "password": "short1"})
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert "short1" not in response.text
    # The validation handler strips Pydantic's echoed input/ctx.
    details = response.json()["details"]
    assert isinstance(details, list)
    for entry in details:
        assert "input" not in entry and "ctx" not in entry


def test_signup_bad_email_returns_422(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    response = client.post(
        "/api/v1/auth/signup",
        json={"email": "not-an-email", "password": USER_PASSWORD},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


# --- Login / me ---------------------------------------------------------------


def test_login_returns_session_and_token_works_at_me(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    _signup(client)
    response = client.post(
        "/api/v1/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600
    assert body["user"]["email"] == USER_EMAIL
    assert "password" not in response.text

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json() == {"id": body["user"]["id"], "email": USER_EMAIL}


def test_login_wrong_password_and_unknown_email_are_indistinguishable(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    _signup(client)
    wrong = client.post(
        "/api/v1/auth/login", json={"email": USER_EMAIL, "password": "wrong-password-1"}
    )
    unknown = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "wrong-password-1"},
    )
    assert wrong.status_code == 401
    assert unknown.status_code == 401
    assert wrong.json()["code"] == unknown.json()["code"] == "UNAUTHORIZED"
    assert wrong.json()["message"] == unknown.json()["message"]


def test_me_without_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_me_with_bad_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    response = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_me_with_wrong_secret_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "email": USER_EMAIL,
            "aud": "authenticated",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        "a-different-secret",
        algorithm="HS256",
    )
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_me_with_expired_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "email": USER_EMAIL,
            "aud": "authenticated",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=10),
        },
        TEST_SECRET,
        algorithm="HS256",
    )
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_me_with_tampered_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    _signup(client)
    token = _login_token(client)
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload[:-1]}{'A' if payload[-1] != 'A' else 'B'}.{signature}"
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered}"})
    assert response.status_code == 401


def test_me_with_malformed_authorization_header_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    response = client.get("/api/v1/auth/me", headers={"Authorization": "Token abc"})
    assert response.status_code == 401


# --- Logout / reset / callback --------------------------------------------------


def test_logout_returns_200_and_revokes_token(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, fake = auth_client
    _signup(client)
    token = _login_token(client)
    response = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert token in fake.revoked_tokens


def test_logout_without_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    response = client.post("/api/v1/auth/logout")
    assert response.status_code == 401


def test_reset_returns_200_for_known_and_unknown_emails(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, fake = auth_client
    _signup(client)
    known = client.post("/api/v1/auth/reset", json={"email": USER_EMAIL})
    unknown = client.post("/api/v1/auth/reset", json={"email": "nobody@example.com"})
    assert known.status_code == 200
    assert unknown.status_code == 200
    assert known.json() == unknown.json()
    assert fake.reset_requested == [USER_EMAIL, "nobody@example.com"]


def test_callback_with_valid_code_returns_session(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, fake = auth_client
    _signup(client)
    code = fake.issue_code(USER_EMAIL)
    response = client.post("/api/v1/auth/callback", json={"code": code})
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == USER_EMAIL
    assert body["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200


def test_callback_with_bad_code_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    response = client.post("/api/v1/auth/callback", json={"code": "bogus-code"})
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


# --- Rate limits ------------------------------------------------------------------


def test_login_rate_limit_6th_attempt_returns_429_with_retry_after(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, fake = auth_client
    # Create the user directly in the fake so no rate-limit budget is spent
    # on the signup request itself (signup shares the same 5/15 min keys).
    fake.sign_up(USER_EMAIL, USER_PASSWORD)
    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": USER_EMAIL, "password": "wrong-password-1"},
        )
        assert response.status_code == 401
    denied = client.post(
        "/api/v1/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert denied.status_code == 429
    assert denied.json()["code"] == "RATE_LIMITED"
    assert denied.headers["retry-after"]
    assert int(denied.headers["retry-after"]) > 0


def test_login_rate_limit_is_per_email_across_ips(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, fake = auth_client
    fake.sign_up(USER_EMAIL, USER_PASSWORD)
    for i in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": USER_EMAIL, "password": "wrong-password-1"},
            headers={"X-Forwarded-For": f"10.0.0.{i + 1}"},
        )
        assert response.status_code == 401
    # A sixth attempt from a brand-new IP is still denied: the email key hit.
    denied = client.post(
        "/api/v1/auth/login",
        json={"email": USER_EMAIL, "password": USER_PASSWORD},
        headers={"X-Forwarded-For": "10.0.0.99"},
    )
    assert denied.status_code == 429
    assert denied.headers["retry-after"]


def test_login_rate_limit_is_per_ip_across_emails(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    for i in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": f"user{i}@example.com", "password": "wrong-password-1"},
        )
        assert response.status_code == 401
    denied = client.post(
        "/api/v1/auth/login",
        json={"email": "someone-else@example.com", "password": "wrong-password-1"},
    )
    assert denied.status_code == 429
    assert denied.headers["retry-after"]


def test_spoofed_x_forwarded_for_does_not_bypass_ip_limit(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    # M1 review fix: X-Forwarded-For is untrusted by default. An attacker
    # sending a fresh XFF per request must NOT get a fresh IP bucket — all
    # five attempts still land on the direct peer's bucket, so the 6th is
    # 429 even with a brand-new spoofed address.
    client, _fake = auth_client
    for i in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": f"spoof{i}@example.com", "password": "wrong-password-1"},
            headers={"X-Forwarded-For": f"203.0.113.{i + 1}"},
        )
        assert response.status_code == 401
    denied = client.post(
        "/api/v1/auth/login",
        json={"email": "spoof5@example.com", "password": "wrong-password-1"},
        headers={"X-Forwarded-For": "203.0.113.99"},
    )
    assert denied.status_code == 429


def test_x_forwarded_for_honored_when_trust_is_configured(
    auth_client: tuple[TestClient, FakeAuthProvider],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The trusted-proxy escape hatch (Render prod behind its proxy): with
    # TRUST_X_FORWARDED_FOR=true the first XFF entry IS the client IP, so
    # five attempts from the SAME XFF address share one bucket and the
    # sixth from that address is denied.
    monkeypatch.setattr("app.routers.auth.settings.trust_x_forwarded_for", True)
    client, _fake = auth_client
    for i in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": f"trusted{i}@example.com", "password": "wrong-password-1"},
            headers={"X-Forwarded-For": "198.51.100.1"},
        )
        assert response.status_code == 401
    # Sixth attempt from the same XFF address -> 429.
    denied = client.post(
        "/api/v1/auth/login",
        json={"email": "trusted5@example.com", "password": "wrong-password-1"},
        headers={"X-Forwarded-For": "198.51.100.1"},
    )
    assert denied.status_code == 429
    # ...while a different XFF address still has its own fresh bucket.
    fresh = client.post(
        "/api/v1/auth/login",
        json={"email": "trusted6@example.com", "password": "wrong-password-1"},
        headers={"X-Forwarded-For": "198.51.100.2"},
    )
    assert fresh.status_code == 401


def test_signup_rate_limit_6th_attempt_returns_429(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    for i in range(5):
        response = client.post(
            "/api/v1/auth/signup",
            json={"email": f"new{i}@example.com", "password": USER_PASSWORD},
        )
        assert response.status_code == 201
    denied = client.post(
        "/api/v1/auth/signup",
        json={"email": "new5@example.com", "password": USER_PASSWORD},
    )
    assert denied.status_code == 429
    assert denied.json()["code"] == "RATE_LIMITED"


def test_supabase_sign_up_duplicate_detected_by_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Round-2 review: duplicate detection must match the stable
    # machine-readable code FIRST (gotrue AuthApiError.code), not only the
    # human message — a GoTrue rewording must not resurrect the oracle.
    from gotrue.errors import AuthApiError

    from app.auth.provider import SupabaseAuthProvider
    from app.core.config import Settings

    settings = Settings(
        supabase_url="https://example.supabase.co",
        supabase_anon_key="anon-key",
        supabase_service_role_key=SecretStr("service-key"),
        supabase_jwt_secret=SecretStr("jwt-secret"),
    )
    assert settings.supabase_configured is True

    class _FakeAuth:
        def __init__(self, exc: AuthApiError) -> None:
            self._exc = exc

        def sign_up(self, payload: dict[str, str]) -> None:
            raise self._exc

    class _FakeClient:
        def __init__(self, exc: AuthApiError) -> None:
            self.auth = _FakeAuth(exc)

    # Code match: message says something else entirely, code is the signal.
    monkeypatch.setattr(
        "app.auth.provider.create_client",
        lambda url, key: _FakeClient(
            AuthApiError("User already exists", 422, "user_already_exists")
        ),
    )
    assert SupabaseAuthProvider(settings).sign_up("dup@example.com", "password-1") is None

    # Message fallback: an unknown code but the known message still counts.
    monkeypatch.setattr(
        "app.auth.provider.create_client",
        lambda url, key: _FakeClient(AuthApiError("User already registered", 422, "conflict")),
    )
    assert SupabaseAuthProvider(settings).sign_up("dup@example.com", "password-1") is None

    # A genuinely different 422 (weak password) is NOT a duplicate: 502.
    monkeypatch.setattr(
        "app.auth.provider.create_client",
        lambda url, key: _FakeClient(AuthApiError("Password too weak", 422, "weak_password")),
    )
    with pytest.raises(ApiError) as excinfo:
        SupabaseAuthProvider(settings).sign_up("new@example.com", "weak")
    assert excinfo.value.code == "BAD_GATEWAY"


# --- Provider / JWT edge cases -------------------------------------------------------


def test_supabase_provider_raises_503_when_not_configured() -> None:
    provider = SupabaseAuthProvider()
    with pytest.raises(ApiError) as excinfo:
        provider.sign_up("a@example.com", "some-password-1")
    assert excinfo.value.status_code == 503
    assert excinfo.value.code == "SUPABASE_NOT_CONFIGURED"


def test_verify_token_without_configured_secret_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.auth.jwt import verify_token

    monkeypatch.setattr(settings, "supabase_jwt_secret", None)
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "email": USER_EMAIL,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        TEST_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(ApiError) as excinfo:
        verify_token(token)
    assert excinfo.value.status_code == 401


def test_user_dataclass_defaults_to_owner_role() -> None:
    user = User(id=uuid.uuid4(), email=USER_EMAIL)
    assert user.role == "owner"
