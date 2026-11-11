"""Tests for the auth endpoints (``/api/v1/auth``) and JWT verification.

Uses a test-only in-memory ``FakeAuthProvider`` (never shipped as a
production fallback) whose login tokens are real ES256 JWTs signed with a
test-only EC P-256 keypair, so ``GET /me`` exercises the real
``verify_token`` path against a stubbed JWKS (no network, no live keys).

Matrix covered here: no token -> 401, bad token -> 401, good token -> 200;
rate limit: 6th login attempt within 15 min -> 429 with ``Retry-After``,
per IP AND per email; signup validation errors -> 422 without echoing the
password; callback with a bad code -> 401. Plus the ES256/JWKS matrix:
wrong kid -> 401, HS256 token -> 401, expired -> 401, bad signature ->
401, unknown kid triggers a JWKS refresh (and still 401s when absent),
rotated kid verifies after refresh.
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.auth import jwt as jwt_module
from app.auth.jwt import User, _index_jwks, verify_token
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

# Test-only EC P-256 keypair (generated fresh per test session, never a
# live key). Tokens are ES256, signed with this key, ``kid`` TEST_KID —
# mirroring the live Supabase ES256/JWKS shape (ADR-0007).
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "test-key-1"
TEST_SUPABASE_URL = "https://example.supabase.co"
USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery"


def _b64url(value: int) -> str:
    """Base64url-encode a P-256 coordinate (32 bytes, no padding)."""
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode("ascii")


def _test_jwk() -> dict[str, Any]:
    """The public half of the test keypair, as a JWKS entry."""
    numbers = _TEST_PRIVATE_KEY.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": _TEST_KID,
        "x": _b64url(numbers.x),
        "y": _b64url(numbers.y),
    }


def _test_jwks() -> dict[str, Any]:
    return {"keys": [_test_jwk()]}


def _mint_es256(
    *,
    user_id: str | None = None,
    email: str = USER_EMAIL,
    key: Any = _TEST_PRIVATE_KEY,
    kid: str = _TEST_KID,
    algorithm: str = "ES256",
    claims: dict[str, Any] | None = None,
    omit: tuple[str, ...] = (),
) -> str:
    """Mint a test token (defaults: valid ES256, test key, test kid).

    ``omit`` drops claims from the payload after ``claims`` are applied —
    used to prove a missing ``iss`` / ``aud`` is rejected (F-L4).
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": user_id or str(uuid.uuid4()),
        "email": email,
        "iss": TEST_SUPABASE_URL + "/auth/v1",
        "aud": "authenticated",
        "role": "authenticated",
        "iat": now,
        "exp": now + timedelta(hours=1),
    }
    if claims:
        payload.update(claims)
    for name in omit:
        payload.pop(name, None)
    headers = {"kid": kid} if kid else None
    return jwt.encode(payload, key, algorithm=algorithm, headers=headers)


class FakeAuthProvider:
    """In-memory auth provider, TESTS ONLY.

    Passwords are stored as SHA-256 digests (test-only: no salt, no
    stretching — never a production pattern). Login tokens are real ES256
    JWTs so the real verification path is exercised end to end.
    """

    def __init__(self) -> None:
        self._users: dict[str, dict[str, str]] = {}
        self._codes: dict[str, str] = {}
        self.revoked_tokens: set[str] = set()
        self.reset_requested: list[str] = []

    def _mint(self, user_id: str, email: str) -> AuthSession:
        token = _mint_es256(user_id=user_id, email=email)
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
    """JWT verification uses the stubbed test JWKS; no Supabase project exists.

    ``verify_token`` fetches the JWKS from ``<supabase_url>/auth/v1/
    .well-known/jwks.json`` — here the fetch is stubbed to return the
    test keypair's public JWK, and the cache is cleared so no test sees
    another test's keys. The anon/service keys are forced to None so
    ``supabase_configured`` stays False (no real project, no real store
    or provider calls) even when a local .env carries real values — only
    the URL is set, because that is what locates the JWKS.
    """
    monkeypatch.setattr(settings, "supabase_url", TEST_SUPABASE_URL)
    monkeypatch.setattr(settings, "supabase_anon_key", None)
    monkeypatch.setattr(settings, "supabase_service_role_key", None)
    monkeypatch.setattr(jwt_module, "_fetch_jwks", _test_jwks)
    jwt_module.reset_jwks_cache()


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


def test_me_with_wrong_key_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    # Signed with a DIFFERENT EC key but the test kid: the JWKS lookup
    # succeeds, the signature check fails -> 401.
    client, _fake = auth_client
    other_key = ec.generate_private_key(ec.SECP256R1())
    token = _mint_es256(key=other_key)
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_me_with_expired_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    client, _fake = auth_client
    token = _mint_es256(claims={"exp": datetime.now(timezone.utc) - timedelta(seconds=10)})
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


def test_verify_token_without_supabase_url_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No project URL means no JWKS to verify against — every token 401s,
    # even one signed by the test key.
    monkeypatch.setattr(settings, "supabase_url", None)
    token = _mint_es256()
    with pytest.raises(ApiError) as excinfo:
        verify_token(token)
    assert excinfo.value.status_code == 401


def test_user_dataclass_defaults_to_owner_role() -> None:
    user = User(id=uuid.uuid4(), email=USER_EMAIL)
    assert user.role == "owner"


# --- ES256 / JWKS verification (ADR-0007) --------------------------------------


def test_verify_token_accepts_valid_es256_token() -> None:
    user = verify_token(_mint_es256(), jwks={_TEST_KID: _test_jwk()})
    assert user.email == USER_EMAIL
    assert isinstance(user.id, uuid.UUID)


def test_verify_token_unknown_kid_returns_401() -> None:
    token = _mint_es256(kid="no-such-kid")
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_missing_kid_returns_401() -> None:
    token = _mint_es256(kid="")
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_hs256_token_returns_401() -> None:
    # HS256 is rejected on the alg header alone — there is no
    # shared-secret fallback (ADR-0007).
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "email": USER_EMAIL,
            "aud": "authenticated",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        "any-shared-secret-that-is-long-enough",
        algorithm="HS256",
        headers={"kid": _TEST_KID},
    )
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_alg_none_returns_401() -> None:
    # F-L7: the alg != ES256 header check covers "none" by construction,
    # but pin it explicitly — an unsigned token must never verify, even
    # with the right kid and claims.
    token = _mint_es256(algorithm="none", key=None)
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_missing_iss_returns_401() -> None:
    # F-L4: iss is REQUIRED when a project URL is configured — a token
    # carrying no issuer is a foreign token, not a Supabase token.
    token = _mint_es256(omit=("iss",))
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_wrong_iss_returns_401() -> None:
    token = _mint_es256(claims={"iss": "https://other.supabase.co/auth/v1"})
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_missing_aud_returns_401() -> None:
    # F-L4: aud is REQUIRED — a token minted for no audience (or any
    # audience other than "authenticated") must never verify.
    token = _mint_es256(omit=("aud",))
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_wrong_aud_returns_401() -> None:
    token = _mint_es256(claims={"aud": "someone-else"})
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_missing_role_still_verifies() -> None:
    # F-L4 / ADR-0007: role stays "when present" — it is redundant with
    # aud (same "authenticated" value, same issuer), so a token without
    # the claim verifies; a present-but-wrong role still 401s (below).
    token = _mint_es256(omit=("role",))
    user = verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert user.email == USER_EMAIL


def test_verify_token_wrong_role_returns_401() -> None:
    token = _mint_es256(claims={"role": "service_role"})
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_index_jwks_filters_non_es256_entries() -> None:
    # F-L7: a JWKS entry whose alg is present and not ES256 (or whose
    # kty/crv is not EC P-256) must never enter the key index — it can
    # never be selected to verify a token.
    indexed = _index_jwks(
        {
            "keys": [
                _test_jwk(),
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "kid": "rsa-kid",
                    "n": "abc",
                    "e": "AQAB",
                },
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": "ES384",
                    "kid": "es384-kid",
                    "x": "abc",
                    "y": "def",
                },
                {"kty": "EC", "crv": "P-384", "alg": "ES256", "kid": "p384-kid"},
            ]
        }
    )
    assert set(indexed) == {_TEST_KID}


def test_verify_token_bad_signature_returns_401() -> None:
    # Same kid, but signed by a different EC key: the JWKS lookup
    # succeeds and the signature check fails.
    other_key = ec.generate_private_key(ec.SECP256R1())
    token = _mint_es256(key=other_key)
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_verify_token_expired_returns_401() -> None:
    token = _mint_es256(claims={"exp": datetime.now(timezone.utc) - timedelta(seconds=10)})
    with pytest.raises(ApiError) as excinfo:
        verify_token(token, jwks={_TEST_KID: _test_jwk()})
    assert excinfo.value.status_code == 401


def test_unknown_kid_triggers_jwks_refresh_and_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    def _counting_fetch() -> dict[str, Any]:
        calls["n"] += 1
        return _test_jwks()

    monkeypatch.setattr(jwt_module, "_fetch_jwks", _counting_fetch)
    jwt_module.reset_jwks_cache()
    # Prime the cache with a successful verification.
    assert verify_token(_mint_es256()).email == USER_EMAIL
    assert calls["n"] == 1
    # A token signed by another key under an unknown kid...
    other_key = ec.generate_private_key(ec.SECP256R1())
    token = _mint_es256(key=other_key, kid="rotated-kid")
    with pytest.raises(ApiError) as excinfo:
        verify_token(token)
    assert excinfo.value.status_code == 401
    # ...triggered exactly one JWKS refresh (the rotation path), and
    # still failed because the kid is absent from the refreshed JWKS.
    assert calls["n"] == 2


def test_rotated_kid_verifies_after_jwks_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A key rotation: the new kid is absent from the cached JWKS but
    # present in the JWKS the refresh returns — the token must verify.
    new_key = ec.generate_private_key(ec.SECP256R1())
    new_numbers = new_key.public_key().public_numbers()
    new_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": "rotated-kid",
        "x": _b64url(new_numbers.x),
        "y": _b64url(new_numbers.y),
    }
    calls = {"n": 0}

    def _rotating_fetch() -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            return _test_jwks()
        return {"keys": [_test_jwk(), new_jwk]}

    monkeypatch.setattr(jwt_module, "_fetch_jwks", _rotating_fetch)
    jwt_module.reset_jwks_cache()
    assert verify_token(_mint_es256()).email == USER_EMAIL
    assert calls["n"] == 1
    token = _mint_es256(key=new_key, kid="rotated-kid")
    user = verify_token(token)
    assert user.email == USER_EMAIL
    assert calls["n"] == 2


def test_stale_jwks_cache_within_24h_verifies_on_fetch_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # F-L3: a fetch failure falls back to the cached keys while the cache
    # is at most 24 hours old — a transient outage does not 401 every
    # authenticated request.
    def _failing_fetch() -> dict[str, Any]:
        raise jwt_module._JwksFetchError("network down")

    jwt_module.reset_jwks_cache()
    assert verify_token(_mint_es256()).email == USER_EMAIL  # primes cache
    monkeypatch.setattr(jwt_module, "_fetch_jwks", _failing_fetch)
    # Age the cache past the 1h TTL (so a fetch is attempted) but well
    # inside the 24h stale bound.
    jwt_module._JWKS_CACHE._fetched_at = time.monotonic() - 23 * 3600
    assert verify_token(_mint_es256()).email == USER_EMAIL


def test_stale_jwks_cache_beyond_24h_returns_401_on_fetch_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # F-L3: the same fetch failure with a cache older than 24 hours is
    # refused — a rotated-away key must not verify tokens indefinitely
    # during a fetch outage.
    def _failing_fetch() -> dict[str, Any]:
        raise jwt_module._JwksFetchError("network down")

    jwt_module.reset_jwks_cache()
    assert verify_token(_mint_es256()).email == USER_EMAIL  # primes cache
    monkeypatch.setattr(jwt_module, "_fetch_jwks", _failing_fetch)
    jwt_module._JWKS_CACHE._fetched_at = time.monotonic() - 25 * 3600
    with pytest.raises(ApiError) as excinfo:
        verify_token(_mint_es256())
    assert excinfo.value.status_code == 401


def test_me_with_hs256_token_returns_401(
    auth_client: tuple[TestClient, FakeAuthProvider],
) -> None:
    # End-to-end: an HS256 token (the old verification path) is rejected
    # by /me even when it carries the right claims and kid.
    client, _fake = auth_client
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "email": USER_EMAIL,
            "aud": "authenticated",
            "role": "authenticated",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        "any-shared-secret-that-is-long-enough",
        algorithm="HS256",
        headers={"kid": _TEST_KID},
    )
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
