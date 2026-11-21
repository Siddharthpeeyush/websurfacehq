"""Tests for staff sessions (``app/auth/sessions.py``) + the iat-leeway
regression test for ``app/auth/jwt.py`` (Week 1 open item 3).

Session rules under test (DESIGN-LOCK.md "Staff sessions"): absolute
lifetime 12h, idle 60 min, revoked -> 401, stale ``prefix_version``
(prefix rotation) -> 401, step-up state per session, and the
``STAFF_STEP_UP_MFA`` flag (default ON).

Time is controlled with a fake clock injected into the SessionManager,
so expiry boundaries are exact, not wall-clock races. Every
validation failure must be the same generic 401 ``INVALID_SESSION``
— the tests assert the code, not just the status.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.auth import jwt as jwt_module
from app.auth.jwt import verify_token
from app.auth.sessions import (
    InMemoryStaffSessionStore,
    SessionManager,
)
from app.core.config import settings
from app.core.errors import ApiError

USER_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
OTHER_USER_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
START = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    """A movable clock for the SessionManager."""

    def __init__(self, now: datetime = START) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now = self.now + delta


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def manager(clock: FakeClock) -> SessionManager:
    return SessionManager(
        InMemoryStaffSessionStore(),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=1,
        clock=clock,
    )


def _expect_invalid_session(exc_info: pytest.ExceptionInfo[ApiError]) -> None:
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "INVALID_SESSION"


# --- Issue / validate ------------------------------------------------------


def test_issue_and_validate_slides_idle_window(manager: SessionManager, clock: FakeClock) -> None:
    session = manager.issue(USER_ID, ip="203.0.113.1", user_agent="test-agent")
    assert session.user_id == USER_ID
    assert session.prefix_version == 1
    clock.advance(timedelta(minutes=10))
    validated = manager.validate(session.id)
    # Validation slides last_seen_at to now.
    assert validated.last_seen_at == clock.now
    assert validated.revoked_at is None


def test_validate_unknown_session_returns_401(manager: SessionManager) -> None:
    with pytest.raises(ApiError) as exc_info:
        manager.validate(uuid.uuid4())
    _expect_invalid_session(exc_info)


def test_session_valid_just_before_absolute_expiry(
    manager: SessionManager, clock: FakeClock
) -> None:
    """Absolute boundary: alive at 11h59m (kept idle-fresh by periodic
    activity), dead at 12h00m."""
    session = manager.issue(USER_ID)
    for _ in range(23):
        clock.advance(timedelta(minutes=30))
        manager.validate(session.id)  # activity keeps the idle window fresh
    clock.advance(timedelta(minutes=29))
    assert manager.validate(session.id).id == session.id
    clock.advance(timedelta(minutes=1))
    with pytest.raises(ApiError) as exc_info:
        manager.validate(session.id)
    _expect_invalid_session(exc_info)


def test_absolute_expiry_returns_401(manager: SessionManager, clock: FakeClock) -> None:
    session = manager.issue(USER_ID)
    clock.advance(timedelta(hours=12))
    with pytest.raises(ApiError) as exc_info:
        manager.validate(session.id)
    _expect_invalid_session(exc_info)


def test_idle_expiry_returns_401(manager: SessionManager, clock: FakeClock) -> None:
    session = manager.issue(USER_ID)
    clock.advance(timedelta(minutes=60))
    with pytest.raises(ApiError) as exc_info:
        manager.validate(session.id)
    _expect_invalid_session(exc_info)


def test_idle_window_slides_on_activity(manager: SessionManager, clock: FakeClock) -> None:
    """Activity at 59 min resets the idle clock: 59 + 59 min is fine."""
    session = manager.issue(USER_ID)
    clock.advance(timedelta(minutes=59))
    manager.validate(session.id)  # slides last_seen_at to +59 min
    clock.advance(timedelta(minutes=59))
    assert manager.validate(session.id).id == session.id


def test_revoked_session_returns_401(manager: SessionManager) -> None:
    session = manager.issue(USER_ID)
    assert manager.revoke(session.id) is True
    # Logout is idempotent: a second revoke reports nothing revoked.
    assert manager.revoke(session.id) is False
    with pytest.raises(ApiError) as exc_info:
        manager.validate(session.id)
    _expect_invalid_session(exc_info)


def test_revoke_all_for_user(manager: SessionManager) -> None:
    first = manager.issue(USER_ID)
    second = manager.issue(USER_ID)
    other = manager.issue(OTHER_USER_ID)
    assert manager.revoke_all_for_user(USER_ID) == 2
    for session_id in (first.id, second.id):
        with pytest.raises(ApiError) as exc_info:
            manager.validate(session_id)
        _expect_invalid_session(exc_info)
    # The other user's session is untouched.
    assert manager.validate(other.id).id == other.id


def test_stale_prefix_version_returns_401(clock: FakeClock) -> None:
    """Prefix rotation invalidates all staff sessions (plan §1)."""
    version = {"current": 1}
    rotating = SessionManager(
        InMemoryStaffSessionStore(),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=lambda: version["current"],
        clock=clock,
    )
    session = rotating.issue(USER_ID)
    assert rotating.validate(session.id).id == session.id
    version["current"] = 2  # Owner rotated the secret prefix.
    with pytest.raises(ApiError) as exc_info:
        rotating.validate(session.id)
    _expect_invalid_session(exc_info)


def test_future_prefix_version_returns_401(clock: FakeClock) -> None:
    """C3 (`!=`, not `<`): a session stamped with a NEWER version
    than current is just as dead as an older one — only the CURRENT
    version validates. Under `<`, a version rolled back to 1 (a
    restart resetting the counter, or replica skew) would have let
    this session through."""
    version = {"current": 2}
    manager = SessionManager(
        InMemoryStaffSessionStore(),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=lambda: version["current"],
        clock=clock,
    )
    session = manager.issue(USER_ID)
    assert session.prefix_version == 2
    assert manager.validate(session.id).id == session.id
    version["current"] = 1  # counter rolled back (restart / skew)
    with pytest.raises(ApiError) as exc_info:
        manager.validate(session.id)
    _expect_invalid_session(exc_info)


def test_new_session_after_rotation_uses_new_version(clock: FakeClock) -> None:
    version = {"current": 1}
    rotating = SessionManager(
        InMemoryStaffSessionStore(),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=lambda: version["current"],
        clock=clock,
    )
    rotating.issue(USER_ID)
    version["current"] = 2
    fresh = rotating.issue(USER_ID)
    assert fresh.prefix_version == 2
    assert rotating.validate(fresh.id).id == fresh.id


def test_list_active_sessions_excludes_dead_ones(manager: SessionManager, clock: FakeClock) -> None:
    live = manager.issue(USER_ID)
    revoked = manager.issue(USER_ID)
    manager.revoke(revoked.id)
    manager.issue(USER_ID)  # goes idle-dead below; must be excluded
    clock.advance(timedelta(minutes=30))
    manager.validate(live.id)  # keep the live one fresh
    clock.advance(timedelta(minutes=45))  # idle_dead is now 75 min stale
    active = manager.list_active_sessions(USER_ID)
    assert [s.id for s in active] == [live.id]


# --- Step-up MFA -----------------------------------------------------------


def test_step_up_required_until_verified(manager: SessionManager) -> None:
    session = manager.issue(USER_ID)
    assert manager.step_up_required(session) is True
    marked = manager.mark_step_up_verified(session.id)
    assert manager.is_step_up_verified(marked) is True
    assert manager.step_up_required(marked) is False


def test_mark_step_up_on_dead_session_returns_401(manager: SessionManager) -> None:
    session = manager.issue(USER_ID)
    manager.revoke(session.id)
    with pytest.raises(ApiError) as exc_info:
        manager.mark_step_up_verified(session.id)
    _expect_invalid_session(exc_info)


def test_step_up_not_required_when_flag_off(clock: FakeClock) -> None:
    from app.core.config import Settings

    manager_no_step_up = SessionManager(
        InMemoryStaffSessionStore(),
        app_settings=Settings(staff_step_up_mfa=False),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=1,
        clock=clock,
    )
    session = manager_no_step_up.issue(USER_ID)
    assert manager_no_step_up.step_up_required(session) is False


# --- iat leeway regression (Week 1 open item 3) ---------------------------
# A token whose ``iat`` is a few seconds ahead of this VM's clock must
# verify (issuer/clock skew); one 30 s ahead must still 401.

_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "test-key-1"
TEST_SUPABASE_URL = "https://example.supabase.co"


def _b64url(value: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode("ascii")


def _test_jwks() -> dict[str, dict[str, Any]]:
    numbers = _TEST_PRIVATE_KEY.public_key().public_numbers()
    return {
        _TEST_KID: {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": _TEST_KID,
            "x": _b64url(numbers.x),
            "y": _b64url(numbers.y),
        }
    }


def _mint_with_iat_skew(iat_skew_seconds: int) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(USER_ID),
        "email": "user@example.com",
        "iss": TEST_SUPABASE_URL + "/auth/v1",
        "aud": "authenticated",
        "role": "authenticated",
        "iat": now + timedelta(seconds=iat_skew_seconds),
        "exp": now + timedelta(hours=1),
    }
    return jwt.encode(payload, _TEST_PRIVATE_KEY, algorithm="ES256", headers={"kid": _TEST_KID})


def test_iat_a_few_seconds_ahead_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """leeway=5: a token minted 3 s in our future verifies."""
    monkeypatch.setattr(settings, "supabase_url", TEST_SUPABASE_URL)
    jwt_module.reset_jwks_cache()
    user = verify_token(_mint_with_iat_skew(3), jwks=_test_jwks())
    assert user.id == USER_ID


def test_iat_far_ahead_still_401s(monkeypatch: pytest.MonkeyPatch) -> None:
    """leeway=5 does NOT bless a token 30 s in our future."""
    monkeypatch.setattr(settings, "supabase_url", TEST_SUPABASE_URL)
    jwt_module.reset_jwks_cache()
    with pytest.raises(ApiError) as exc_info:
        verify_token(_mint_with_iat_skew(30), jwks=_test_jwks())
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "UNAUTHORIZED"


def test_iat_in_the_past_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "supabase_url", TEST_SUPABASE_URL)
    jwt_module.reset_jwks_cache()
    user = verify_token(_mint_with_iat_skew(-10), jwks=_test_jwks())
    assert user.id == USER_ID
