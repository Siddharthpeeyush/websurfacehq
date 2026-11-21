"""Integration matrix (Child F, admin-foundation build, plan §4).

Cross-cutting checks the per-child suites do not make in one place:
one full app (``create_app`` — staff door + admin routers mounted
together), one client, both doors. Every case runs against the real
wiring: real ``get_current_staff`` / central ``can()`` on ``/admin``,
real staff-auth login + MFA + sessions, real invite claim, real
prefix-version counter.

- 401/403/404 per new endpoint: unauthenticated -> 401, wrong role
  -> 403, unknown / non-staff id -> 404.
- Customer account at the staff door -> the generic 401, byte-identical
  to a wrong password (no enumeration).
- Support on /founder -> 403; Admin on /founder -> 403 (Owner-only).
- Role-picker spoof: a wrong role card -> the SAME 401 as a wrong
  password (body-identical) AND the same timing (medians + ratio).
- Invite reuse + expired invite -> rejected indistinguishably (same 404).
- Session absolute (12h) + idle (60 min) expiry, observed on /admin/me.
- Prefix rotation invalidates sessions: the victim's AND the Owner's
  own session -> 401, then re-auth works (new version stamped).

Fixtures mirror ``tests.test_staff_auth`` (fake ES256 auth provider +
fake GoTrue MFA backend, movable clock) and ``tests.test_admin``
(``FakeAdminStore`` so the admin lists have real backing).
"""

from __future__ import annotations

import statistics
import time
import uuid
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import app.db as db_module
from app.auth import jwt as jwt_module
from app.auth.mfa import MfaService, set_mfa_service
from app.auth.provider import set_auth_provider
from app.auth.rate_limit import RateLimiter, set_rate_limiter
from app.auth.sessions import InMemoryStaffSessionStore, SessionManager
from app.core.config import settings
from app.core.staff_prefix import (
    bump_prefix_version,
    get_prefix_version,
    get_staff_host,
    reset_prefix_version_for_tests,
)
from app.db import reset_store_for_tests
from app.main import create_app
from app.services.invites import reset_invites_for_tests
from app.services.staff import (
    create_staff_invite,
    reset_staff_state_for_tests,
    set_staff_session_manager,
)
from tests.test_admin import FakeAdminStore, _seed_staff
from tests.test_admin import _client as _admin_client
from tests.test_auth import TEST_SUPABASE_URL, FakeAuthProvider, _test_jwks
from tests.test_mfa import CORRECT_CODE, FakeMfaBackend
from tests.test_staff_auth import (
    ADMIN_EMAIL,
    CUSTOMER_EMAIL,
    OWNER_EMAIL,
    PASSWORD,
    UNKNOWN_EMAIL,
    WRONG_PASSWORD,
    FakeClock,
    _login_with_mfa,
    _staff_login,
)
from tests.test_staff_auth import _seed_staff as _seed_auth_staff

START = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)

OWNER_ONLY_GETS = [
    "/admin/users",
    "/admin/scans",
    "/admin/scans/queue",
    "/admin/billing",
    "/admin/security",
    "/admin/system/audit",
    "/admin/settings",
    "/admin/founder",
]

OWNER_ONLY_POSTS = [
    ("/admin/users/invite", {"email": "matrix-x@example.com", "role": "support"}),
    (f"/admin/users/invites/{uuid.uuid4()}/revoke", None),
    (f"/admin/users/{uuid.uuid4()}/suspend", None),
    (f"/admin/users/{uuid.uuid4()}/delete", {"confirm": True}),
    (f"/admin/users/{uuid.uuid4()}/role", {"role": "admin"}),
    (f"/admin/users/{uuid.uuid4()}/revoke-sessions", None),
    (f"/admin/users/{uuid.uuid4()}/force-reset", None),
    (f"/admin/users/{uuid.uuid4()}/mfa-re-enroll", None),
    ("/admin/settings", {"staff_step_up_mfa": False}),
    ("/admin/settings/rotate-prefix", {"confirm": True}),
]

GENERIC_401 = {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid role, email, or password",
    "details": None,
}


@pytest.fixture(autouse=True)
def _test_jwt_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """JWT verification uses the stubbed test JWKS (tests.test_auth)."""
    monkeypatch.setattr(settings, "supabase_url", TEST_SUPABASE_URL)
    monkeypatch.setattr(settings, "supabase_anon_key", None)
    monkeypatch.setattr(settings, "supabase_service_role_key", None)
    monkeypatch.setattr(jwt_module, "_fetch_jwks", _test_jwks)
    jwt_module.reset_jwks_cache()


@pytest.fixture(autouse=True)
def _reset_matrix_state(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    # Null the Supabase keys FIRST (same ordering trap as
    # tests.test_staff_auth / tests.test_admin: this fixture's setup
    # runs before _test_jwt_settings, and reset_prefix_version_for_
    # tests() resolves the store — with real keys that caches a live
    # SupabaseStore and fires a PostgREST call per test).
    monkeypatch.setattr(settings, "supabase_anon_key", None)
    monkeypatch.setattr(settings, "supabase_service_role_key", None)
    reset_store_for_tests()
    reset_staff_state_for_tests()
    reset_invites_for_tests()
    reset_prefix_version_for_tests()
    yield
    reset_store_for_tests()
    reset_staff_state_for_tests()
    reset_invites_for_tests()
    reset_prefix_version_for_tests()
    set_mfa_service(None)
    set_auth_provider(None)
    set_staff_session_manager(None)
    set_rate_limiter(None)


@pytest.fixture()
def matrix() -> Generator[
    tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    None,
    None,
]:
    """Full app + fake auth + fake MFA + clocked session manager + admin store."""
    fake = FakeAdminStore()
    db_module._STORE = fake
    fake_auth = FakeAuthProvider()
    fake_mfa = FakeMfaBackend()
    mfa_service = MfaService(backend=fake_mfa)
    set_auth_provider(fake_auth)
    set_mfa_service(mfa_service)
    clock = FakeClock(START)
    manager = SessionManager(
        InMemoryStaffSessionStore(),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=get_prefix_version,
        clock=clock,
    )
    set_staff_session_manager(manager)
    set_rate_limiter(RateLimiter(max_attempts=10_000, window_seconds=900))
    client = TestClient(create_app(), base_url=f"http://{get_staff_host()}")
    yield client, fake_auth, mfa_service, manager, clock
    set_auth_provider(None)
    set_mfa_service(None)
    set_staff_session_manager(None)
    set_rate_limiter(None)


def _seed_enrolled_owner_admin(
    fake_auth: FakeAuthProvider, mfa_service: MfaService
) -> tuple[Any, Any]:
    """Enrolled Owner + Admin via the real login/MFA seam (test_staff_auth)."""
    owner, _ = _seed_auth_staff(fake_auth, mfa_service, OWNER_EMAIL, "owner", mfa=True)
    admin, _ = _seed_auth_staff(
        fake_auth, mfa_service, ADMIN_EMAIL, "admin", mfa=True, invited_by=owner.user_id
    )
    return owner, admin


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 401 / 403 / 404 matrix per new endpoint
# ---------------------------------------------------------------------------


def test_matrix_no_token_401_on_every_admin_route(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, _a, _m, _s, _c = matrix
    _seed_staff()  # staff exist so the 401 is about the caller, not the data
    for path in ["/admin/me", *OWNER_ONLY_GETS]:
        assert client.get(path).status_code == 401, path
    for path, body in OWNER_ONLY_POSTS:
        assert client.post(path, json=body).status_code == 401, path


def test_matrix_wrong_role_403(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, _a, _m, manager, _c = matrix
    ids = _seed_staff()
    # Support: only /admin/me + support/abuse read; everything else 403.
    support = _admin_client(manager, ids["support"])
    assert support.get("/admin/me").status_code == 200
    assert support.get("/admin/support/tickets").status_code == 200
    assert support.get("/admin/abuse").status_code == 200
    for path in OWNER_ONLY_GETS:
        assert support.get(path).status_code == 403, path
    for path, body in OWNER_ONLY_POSTS:
        assert support.post(path, json=body).status_code == 403, path
    # Admin: Owner-only mutations are 403 (reads are allowed).
    admin = _admin_client(manager, ids["admin"])
    assert admin.get("/admin/users").status_code == 200
    for path, body in OWNER_ONLY_POSTS:
        assert admin.post(path, json=body).status_code == 403, path


def test_matrix_other_tenant_404(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, _m, manager, _c = matrix
    ids = _seed_staff()
    customer = fake_auth.sign_up(CUSTOMER_EMAIL, PASSWORD)
    assert customer is not None
    owner = _admin_client(manager, ids["owner"])
    # Unknown staff id and a real customer id are both plain 404s —
    # no existence oracle for non-staff accounts.
    assert owner.get(f"/admin/users/{uuid.uuid4()}").status_code == 404
    assert owner.get(f"/admin/users/{customer.id}").status_code == 404
    assert owner.post(f"/admin/users/{uuid.uuid4()}/suspend").status_code == 404
    assert owner.post(f"/admin/users/{customer.id}/suspend").status_code == 404


def test_matrix_customer_session_403_on_admin(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, _a, _m, manager, _c = matrix
    _seed_staff()
    # A valid session for a user with no staff row is 403 everywhere.
    customer_client = _admin_client(manager, uuid.uuid4())
    for path in ["/admin/me", *OWNER_ONLY_GETS]:
        assert customer_client.get(path).status_code == 403, path
    for path, body in OWNER_ONLY_POSTS:
        assert customer_client.post(path, json=body).status_code == 403, path


# ---------------------------------------------------------------------------
# Founder: Support 403, Admin 403 (Owner-only + step-up)
# ---------------------------------------------------------------------------


def test_founder_support_and_admin_403(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, _a, _m, manager, _c = matrix
    ids = _seed_staff()
    assert _admin_client(manager, ids["support"]).get("/admin/founder").status_code == 403
    admin_resp = _admin_client(manager, ids["admin"]).get("/admin/founder")
    assert admin_resp.status_code == 403
    assert admin_resp.json()["code"] == "FORBIDDEN"
    # Owner without step-up is refused too — but with STEP_UP_REQUIRED,
    # proving the Founder gate runs after the role check.
    owner_resp = _admin_client(manager, ids["owner"]).get("/admin/founder")
    assert owner_resp.status_code == 403
    assert owner_resp.json()["code"] == "STEP_UP_REQUIRED"


# ---------------------------------------------------------------------------
# Staff door: customer account + role-picker spoof + timing
# ---------------------------------------------------------------------------


def test_customer_at_staff_door_is_generic_401(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = matrix
    _seed_enrolled_owner_admin(fake_auth, mfa_service)
    fake_auth.sign_up(CUSTOMER_EMAIL, PASSWORD)  # customer, no staff row
    wrong_password = _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
    customer = _staff_login(client, "admin", CUSTOMER_EMAIL)
    unknown = _staff_login(client, "admin", UNKNOWN_EMAIL)
    assert customer.status_code == 401
    assert customer.content == wrong_password.content == unknown.content
    assert customer.json() == GENERIC_401


def test_role_picker_spoof_is_generic_401(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = matrix
    _seed_enrolled_owner_admin(fake_auth, mfa_service)
    wrong_password = _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
    spoof = _staff_login(client, "owner", ADMIN_EMAIL)  # admin account, owner card
    assert spoof.status_code == 401
    assert spoof.content == wrong_password.content
    assert spoof.json() == GENERIC_401


def test_role_spoof_timing_matches_wrong_password(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """Anti-enumeration timing probe (re-run, Child F): wrong-password
    vs wrong-role medians must stay ~1x with byte-identical
    bodies. Bound is the absolute gap < 50 ms + byte-identical
    bodies only — the ratio bound was removed (re-review #3, B2):
    both medians are ~2 ms, so a 1.5x ratio is scheduling noise,
    not a gate (~1 failure in 10). Measured ~1.04x / ~0.7 ms on
    this VM."""
    client, fake_auth, mfa_service, _manager, _clock = matrix
    _seed_enrolled_owner_admin(fake_auth, mfa_service)
    iterations = 25
    for _ in range(3):  # warm-up, not measured
        _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
        _staff_login(client, "owner", ADMIN_EMAIL)

    def median_ms(calls: list[float]) -> float:
        return statistics.median(calls) * 1000.0

    pw_times: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        resp = _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
        pw_times.append(time.perf_counter() - started)
        assert resp.json() == GENERIC_401
    role_times: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        resp = _staff_login(client, "owner", ADMIN_EMAIL)
        role_times.append(time.perf_counter() - started)
        assert resp.json() == GENERIC_401
    pw_median = median_ms(pw_times)
    role_median = median_ms(role_times)
    ratio = max(pw_median, role_median) / min(pw_median, role_median)
    print(
        f"[timing-matrix] medians over {iterations}: wrong-password={pw_median:.2f}ms "
        f"wrong-role={role_median:.2f}ms ratio={ratio:.2f}x "
        f"abs-gap={abs(pw_median - role_median):.2f}ms"
    )
    # Ratio bound removed (re-review #3, B2): both medians are ~2 ms,
    # so the 1.5x ratio is scheduling noise, not a gate (~1 failure
    # in 10). The absolute gap + byte-identical bodies stay.
    assert abs(pw_median - role_median) < 50.0


# ---------------------------------------------------------------------------
# Invites: reuse + expired -> indistinguishable 404s
# ---------------------------------------------------------------------------


def test_invite_reuse_and_expired_are_same_404(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = matrix
    owner, _admin = _seed_enrolled_owner_admin(fake_auth, mfa_service)
    invite, token = create_staff_invite(owner, "reuse@websurfacehq.com", "support")
    first = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
    assert first.status_code == 201, first.text
    assert first.json()["user"]["email"] == "reuse@websurfacehq.com"
    reuse = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
    invalid = client.post(
        "/staff/auth/invite/accept", json={"token": "nonsense-token", "password": PASSWORD}
    )
    # Expired: created 73h ago, so created + 72h is already past.
    _expired_invite, expired_token = create_staff_invite(
        owner,
        "expired@websurfacehq.com",
        "support",
        now=START - timedelta(hours=73),
    )
    expired = client.post(
        "/staff/auth/invite/accept", json={"token": expired_token, "password": PASSWORD}
    )
    assert reuse.status_code == 404 and invalid.status_code == 404
    assert expired.status_code == 404
    assert reuse.content == invalid.content == expired.content
    assert reuse.json()["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# Sessions: absolute 12h + idle 60min expiry, observed on /admin/me
# ---------------------------------------------------------------------------


def test_session_absolute_expiry_on_admin_me(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, clock = matrix
    _seed_enrolled_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    assert client.get("/admin/me", headers=_headers(token)).status_code == 200
    clock.advance(timedelta(hours=12))
    resp = client.get("/admin/me", headers=_headers(token))
    assert resp.status_code == 401
    assert resp.json()["code"] == "INVALID_SESSION"


def test_session_idle_expiry_on_admin_me(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, clock = matrix
    _seed_enrolled_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    assert client.get("/admin/me", headers=_headers(token)).status_code == 200
    clock.advance(timedelta(minutes=61))
    resp = client.get("/admin/me", headers=_headers(token))
    assert resp.status_code == 401
    assert resp.json()["code"] == "INVALID_SESSION"


# ---------------------------------------------------------------------------
# Prefix rotation invalidates sessions (victim + Owner's own), re-auth works
# ---------------------------------------------------------------------------


def test_prefix_rotation_invalidates_victim_and_owner_then_reauth_works(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = matrix
    _seed_enrolled_owner_admin(fake_auth, mfa_service)
    victim_token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    owner_token = _login_with_mfa(client, "owner", OWNER_EMAIL)
    assert client.get("/admin/me", headers=_headers(victim_token)).status_code == 200
    assert client.get("/admin/me", headers=_headers(owner_token)).status_code == 200
    assert get_prefix_version() == 1
    assert bump_prefix_version() == 2
    for token in (victim_token, owner_token):
        resp = client.get("/admin/me", headers=_headers(token))
        assert resp.status_code == 401
        assert resp.json()["code"] == "INVALID_SESSION"
    # Re-auth after rotation works (fresh sessions stamp the new version).
    fresh = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    assert client.get("/admin/me", headers=_headers(fresh)).status_code == 200


def test_invite_accept_response_shape_is_user_and_message(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """Contract pin (Child C): /invite/accept returns {user, message} —
    no MFA material, no session. Enrollment starts at first login."""
    client, fake_auth, mfa_service, _manager, _clock = matrix
    owner, _admin = _seed_enrolled_owner_admin(fake_auth, mfa_service)
    _invite, token = create_staff_invite(owner, "shaped@websurfacehq.com", "admin")
    resp = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    assert set(body.keys()) == {"user", "message"}
    assert body["user"] == {
        "id": body["user"]["id"],
        "email": "shaped@websurfacehq.com",
        "role": "admin",
    }
    assert "session" not in body and "supabase_access_token" not in body
    # The new account's first login is the enroll_required flow.
    login = _staff_login(client, "admin", "shaped@websurfacehq.com")
    assert login.json()["enroll_required"] is True


def test_mfa_verify_takes_code_only(
    matrix: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """Contract pin (Child C): /mfa/verify body is {code} — the
    challenge is server-side; the AAL1 token rides in Authorization."""
    client, fake_auth, mfa_service, _manager, _clock = matrix
    _seed_enrolled_owner_admin(fake_auth, mfa_service)
    login = _staff_login(client, "admin", ADMIN_EMAIL)
    assert login.status_code == 200
    aal1 = login.json()["supabase_access_token"]
    verify = client.post(
        "/staff/auth/mfa/verify",
        json={"code": CORRECT_CODE},
        headers=_headers(aal1),
    )
    assert verify.status_code == 200, verify.text
    assert UUID(verify.json()["access_token"])  # the staff session token
