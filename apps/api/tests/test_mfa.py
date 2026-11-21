"""Tests for staff MFA (``app/auth/mfa.py``).

Two layers:

1. :class:`FakeMfaBackend` — an in-memory backend (tests only) that
   mimics GoTrue's MFA semantics: enroll creates an UNVERIFIED factor,
   a code verifies only against a live challenge for that factor, the
   only correct code is ``123456``. The service layer is exercised
   through it (wrong code -> 401, malformed code -> same 401, factor
   lifecycle).
2. GoTrue-backend mapping tests with a stubbed httpx client — the
   production backend's status mapping is proven without network: a
   GoTrue 422 on verify becomes the generic 401, a transport error
   becomes 502, a good enroll response parses to qr_uri + secret.

No real TOTP secret appears here: the fake secret is assembled from
obviously-fake ``TEST``/``FAKE`` chunks (CI's gitleaks job flags
realistic-looking secrets, even in tests — see AGENTS.md, PR #1).
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from app.auth import mfa as mfa_module
from app.auth.mfa import (
    GoTrueMfaBackend,
    MfaChallenge,
    MfaEnrollment,
    MfaFactor,
    MfaService,
    MfaVerifiedSession,
)
from app.core.config import Environment, Settings
from app.core.errors import ApiError

ACCESS_TOKEN = "aal1-access-token"
USER_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
CORRECT_CODE = "123456"
AAL2_TOKEN = "aal2" + "-access-token"
WRONG_CODE = "000000"

# Obviously-fake TOTP secret (test-only): "TESTONLYFAKETOTP" built
# from labelled chunks so no scanner mistakes it for a real secret.
_FAKE_SECRET = "TEST" + "ONLY" + "FAKE" + "TOTP"


class FakeMfaBackend:
    """In-memory MFA backend, TESTS ONLY. Mimics GoTrue semantics."""

    def __init__(self) -> None:
        self._factors: dict[str, dict[str, Any]] = {}
        self._challenges: dict[str, str] = {}
        self._counter = 0

    def enroll(self, access_token: str, friendly_name: str) -> MfaEnrollment:
        self._counter += 1
        factor_id = f"factor-{self._counter}"
        self._factors[factor_id] = {"status": "unverified", "friendly_name": friendly_name}
        return MfaEnrollment(
            factor_id=factor_id,
            qr_uri=(
                "otpauth://totp/WebSurfaceHQ:staff@example.com"
                f"?secret={_FAKE_SECRET}&issuer=WebSurfaceHQ"
            ),
            secret=_FAKE_SECRET,
        )

    def challenge(self, access_token: str, factor_id: str) -> MfaChallenge:
        if factor_id not in self._factors:
            raise ApiError(401, "INVALID_MFA_CODE", "Invalid verification code")
        challenge_id = f"challenge-{factor_id}"
        self._challenges[challenge_id] = factor_id
        return MfaChallenge(challenge_id=challenge_id, expires_at=1_800_000_000)

    def verify(
        self, access_token: str, factor_id: str, challenge_id: str, code: str
    ) -> MfaVerifiedSession:
        if (
            self._challenges.get(challenge_id) != factor_id
            or code != CORRECT_CODE
            or factor_id not in self._factors
        ):
            raise ApiError(401, "INVALID_MFA_CODE", "Invalid verification code")
        self._factors[factor_id]["status"] = "verified"
        return MfaVerifiedSession(
            access_token=AAL2_TOKEN,
            token_type="bearer",
            expires_in=3600,
            user_id=USER_ID,
            email="staff@example.com",
        )

    def list_factors(self, access_token: str) -> list[MfaFactor]:
        return [
            MfaFactor(
                factor_id=factor_id,
                friendly_name=record["friendly_name"],
                factor_type="totp",
                status=record["status"],
            )
            for factor_id, record in self._factors.items()
        ]

    def unenroll(self, access_token: str, factor_id: str) -> None:
        self._factors.pop(factor_id, None)


@pytest.fixture
def service() -> MfaService:
    return MfaService(backend=FakeMfaBackend())


# --- Service layer (fake backend) ------------------------------------------


def test_enroll_returns_qr_uri_and_secret(service: MfaService) -> None:
    enrollment = service.enroll(ACCESS_TOKEN)
    assert enrollment.factor_id
    assert enrollment.qr_uri.startswith("otpauth://totp/")
    assert _FAKE_SECRET in enrollment.qr_uri
    assert enrollment.secret == _FAKE_SECRET


def test_enroll_twice_gives_distinct_factors(service: MfaService) -> None:
    first = service.enroll(ACCESS_TOKEN)
    second = service.enroll(ACCESS_TOKEN)
    assert first.factor_id != second.factor_id


def test_verify_correct_code_returns_aal2_session(service: MfaService) -> None:
    enrollment = service.enroll(ACCESS_TOKEN)
    challenge = service.challenge(ACCESS_TOKEN, enrollment.factor_id)
    verified = service.verify(
        ACCESS_TOKEN, enrollment.factor_id, challenge.challenge_id, CORRECT_CODE
    )
    assert verified.access_token == AAL2_TOKEN
    assert verified.user_id == USER_ID
    assert verified.email == "staff@example.com"


def test_verify_wrong_code_returns_401(service: MfaService) -> None:
    enrollment = service.enroll(ACCESS_TOKEN)
    challenge = service.challenge(ACCESS_TOKEN, enrollment.factor_id)
    with pytest.raises(ApiError) as exc_info:
        service.verify(ACCESS_TOKEN, enrollment.factor_id, challenge.challenge_id, WRONG_CODE)
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "INVALID_MFA_CODE"


@pytest.mark.parametrize("bad_code", ["12345", "1234567", "abcdef", "", "12 456"])
def test_verify_malformed_code_returns_same_401(service: MfaService, bad_code: str) -> None:
    """A malformed code is the SAME 401 as a wrong code — no oracle."""
    enrollment = service.enroll(ACCESS_TOKEN)
    challenge = service.challenge(ACCESS_TOKEN, enrollment.factor_id)
    with pytest.raises(ApiError) as exc_info:
        service.verify(ACCESS_TOKEN, enrollment.factor_id, challenge.challenge_id, bad_code)
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "INVALID_MFA_CODE"


def test_challenge_unknown_factor_returns_401(service: MfaService) -> None:
    with pytest.raises(ApiError) as exc_info:
        service.challenge(ACCESS_TOKEN, "no-such-factor")
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "INVALID_MFA_CODE"


def test_challenge_and_verify_wrong_code_returns_401(service: MfaService) -> None:
    enrollment = service.enroll(ACCESS_TOKEN)
    with pytest.raises(ApiError) as exc_info:
        service.challenge_and_verify(ACCESS_TOKEN, enrollment.factor_id, WRONG_CODE)
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "INVALID_MFA_CODE"


def test_has_verified_totp_factor_false_before_verify_true_after(
    service: MfaService,
) -> None:
    enrollment = service.enroll(ACCESS_TOKEN)
    assert service.has_verified_totp_factor(ACCESS_TOKEN) is False
    service.challenge_and_verify(ACCESS_TOKEN, enrollment.factor_id, CORRECT_CODE)
    assert service.has_verified_totp_factor(ACCESS_TOKEN) is True


def test_unenroll_removes_factor(service: MfaService) -> None:
    enrollment = service.enroll(ACCESS_TOKEN)
    service.challenge_and_verify(ACCESS_TOKEN, enrollment.factor_id, CORRECT_CODE)
    assert service.has_verified_totp_factor(ACCESS_TOKEN) is True
    service.unenroll(ACCESS_TOKEN, enrollment.factor_id)
    assert service.list_factors(ACCESS_TOKEN) == []
    assert service.has_verified_totp_factor(ACCESS_TOKEN) is False


def test_verify_step_up_wrong_code_returns_401(service: MfaService) -> None:
    enrollment = service.enroll(ACCESS_TOKEN)
    with pytest.raises(ApiError) as exc_info:
        service.verify_step_up(ACCESS_TOKEN, enrollment.factor_id, WRONG_CODE)
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "INVALID_MFA_CODE"


def test_verify_step_up_correct_code_succeeds(service: MfaService) -> None:
    enrollment = service.enroll(ACCESS_TOKEN)
    verified = service.verify_step_up(ACCESS_TOKEN, enrollment.factor_id, CORRECT_CODE)
    assert verified.access_token == AAL2_TOKEN


def test_enroll_with_empty_access_token_returns_401(service: MfaService) -> None:
    with pytest.raises(ApiError) as exc_info:
        service.enroll("")
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "UNAUTHORIZED"


# --- GoTrue backend mapping (stubbed httpx client, no network) -------------


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeHttpxClient:
    """Stands in for the proxy-safe httpx client in mfa.py."""

    def __init__(self, response: _FakeResponse | Exception) -> None:
        self._response = response
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []

    def __enter__(self) -> "_FakeHttpxClient":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def request(
        self, method: str, url: str, headers: dict[str, str] | None = None, json: Any = None
    ) -> _FakeResponse:
        self.requests.append((method, url, json))
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _backend_with_stub(
    monkeypatch: pytest.MonkeyPatch, response: _FakeResponse | Exception
) -> GoTrueMfaBackend:
    client = _FakeHttpxClient(response)
    monkeypatch.setattr(mfa_module, "proxy_safe_httpx_client", lambda timeout: client)
    return GoTrueMfaBackend(
        Settings(
            supabase_url="https://example.supabase.co",
            supabase_anon_key="anon-key",
        )
    )


def test_gotrue_verify_wrong_code_422_maps_to_401(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend_with_stub(monkeypatch, _FakeResponse(422, {"msg": "invalid code"}))
    with pytest.raises(ApiError) as exc_info:
        backend.verify(ACCESS_TOKEN, "factor-1", "challenge-1", WRONG_CODE)
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "INVALID_MFA_CODE"


def test_gotrue_verify_success_parses_aal2_session(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend_with_stub(
        monkeypatch,
        _FakeResponse(
            200,
            {
                "access_token": "new-aal2-token",
                "token_type": "bearer",
                "expires_in": 3600,
                "user": {"id": str(USER_ID), "email": "staff@example.com"},
            },
        ),
    )
    verified = backend.verify(ACCESS_TOKEN, "factor-1", "challenge-1", CORRECT_CODE)
    assert verified.access_token == "new-aal2-token"
    assert verified.user_id == USER_ID


def test_gotrue_enroll_parses_qr_uri_and_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend_with_stub(
        monkeypatch,
        _FakeResponse(
            200,
            {
                "id": "factor-9",
                "type": "totp",
                "totp": {
                    "qr_code": "<svg/>",
                    "secret": _FAKE_SECRET,
                    "uri": f"otpauth://totp/WebSurfaceHQ:x?secret={_FAKE_SECRET}",
                },
            },
        ),
    )
    enrollment = backend.enroll(ACCESS_TOKEN, "WebSurfaceHQ")
    assert enrollment.factor_id == "factor-9"
    assert enrollment.secret == _FAKE_SECRET
    assert enrollment.qr_uri.startswith("otpauth://totp/")


def test_gotrue_challenge_unknown_factor_404_maps_to_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _backend_with_stub(monkeypatch, _FakeResponse(404, {"msg": "not found"}))
    with pytest.raises(ApiError) as exc_info:
        backend.challenge(ACCESS_TOKEN, "no-such-factor")
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "INVALID_MFA_CODE"


def test_gotrue_transport_error_maps_to_502(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend_with_stub(monkeypatch, httpx.HTTPError("connection failed"))
    with pytest.raises(ApiError) as exc_info:
        backend.verify(ACCESS_TOKEN, "factor-1", "challenge-1", CORRECT_CODE)
    assert exc_info.value.status_code == 502
    assert exc_info.value.code == "BAD_GATEWAY"


def test_gotrue_backend_not_configured_returns_503() -> None:
    backend = GoTrueMfaBackend(
        Settings(supabase_url=None, supabase_anon_key=None),
    )
    with pytest.raises(ApiError) as exc_info:
        backend.enroll(ACCESS_TOKEN, "WebSurfaceHQ")
    assert exc_info.value.status_code == 503
    assert exc_info.value.code == "SUPABASE_NOT_CONFIGURED"


def test_gotrue_list_factors_parses_verified_totp(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend_with_stub(
        monkeypatch,
        _FakeResponse(
            200,
            {
                "id": str(USER_ID),
                "factors": [
                    {
                        "id": "factor-1",
                        "friendly_name": "WebSurfaceHQ",
                        "factor_type": "totp",
                        "status": "verified",
                    },
                    {
                        "id": "factor-2",
                        "friendly_name": "old phone",
                        "factor_type": "phone",
                        "status": "unverified",
                    },
                ],
            },
        ),
    )
    factors = backend.list_factors(ACCESS_TOKEN)
    assert len(factors) == 2
    assert factors[0].factor_type == "totp"
    assert factors[0].status == "verified"


def test_provider_mfa_hook_exposes_service() -> None:
    """provider.py MFA hook ONLY: SupabaseAuthProvider.mfa is an MfaService."""
    from app.auth.provider import SupabaseAuthProvider

    provider = SupabaseAuthProvider(
        Settings(supabase_url="https://example.supabase.co", supabase_anon_key="anon-key")
    )
    assert isinstance(provider.mfa, MfaService)


def test_settings_staff_defaults() -> None:
    """Config defaults (admin foundation, plan §3): step-up ON, 12h/60m."""
    fields = Settings.model_fields
    assert fields["staff_url_prefix"].default == ""
    assert fields["staff_step_up_mfa"].default is True
    assert fields["staff_session_absolute_hours"].default == 12
    assert fields["staff_session_idle_minutes"].default == 60


def test_production_requires_staff_url_prefix() -> None:
    """Production refuses to start without STAFF_URL_PREFIX."""
    from pydantic import ValidationError

    base: dict[str, Any] = {
        "environment": "production",
        "supabase_url": "https://example.supabase.co",
        "supabase_anon_key": "anon-key",
        "supabase_service_role_key": SecretStr("service-key"),
        "internal_signing_secret": SecretStr("internal-secret"),
        # Re-review #3, B1: staging/production now also fail fast
        # without API_PUBLIC_HOST / API_PUBLIC_URL, so the fixture
        # carries one (the new check is tested on its own below).
        "api_public_host": "api.websurfacehq.com",
    }
    with pytest.raises(ValidationError):
        Settings(**base)
    # A present-but-short prefix is still refused (N9 entropy floor:
    # 16+ chars of [A-Za-z0-9_-]; the setup generator issues 22).
    with pytest.raises(ValidationError):
        Settings(**base, staff_url_prefix="s3cr3t-prefix")
    ok = Settings(**base, staff_url_prefix="k7Qw9x2Zm4vR8tYp6sN1aB")
    assert ok.staff_url_prefix == "k7Qw9x2Zm4vR8tYp6sN1aB"


def test_staging_requires_api_public_host_or_url() -> None:
    """Staging refuses to start without API_PUBLIC_HOST / API_PUBLIC_URL
    (re-review #3, B1): the staff API host gate 404s every staff call
    when neither is set, so the missing var must fail fast here — the
    same fail-fast the repo already applies to STAFF_URL_PREFIX."""
    from pydantic import ValidationError

    base: dict[str, Any] = {
        "environment": "staging",
        "supabase_url": "https://example.supabase.co",
        "supabase_anon_key": "anon-key",
        "supabase_service_role_key": SecretStr("service-key"),
        "internal_signing_secret": SecretStr("internal-secret"),
        "staff_url_prefix": "k7Qw9x2Zm4vR8tYp6sN1aB",
    }
    with pytest.raises(ValidationError, match="API_PUBLIC_HOST or API_PUBLIC_URL"):
        Settings(**base)
    # Either variable alone is enough (the gate accepts the host
    # parsed from API_PUBLIC_URL too).
    assert (
        Settings(**base, api_public_host="api.websurfacehq.com").api_public_host
        == "api.websurfacehq.com"
    )
    assert (
        Settings(**base, api_public_url="https://api.websurfacehq.com").api_public_url
        == "https://api.websurfacehq.com"
    )
    # Dev is exempt: localhost is allowed there, so neither is needed.
    assert Settings(environment=Environment.DEVELOPMENT).api_public_host is None
    assert Settings(environment=Environment.DEVELOPMENT).api_public_url is None
