"""Tests for the staff-door auth endpoints (``/staff/auth``) and the
staff account service (``app.services.staff``) + secret-prefix guard.

Built on Child B's interfaces (no duplicated MFA/session logic here):

- ``FakeAuthProvider`` (``tests.test_auth``) mints REAL ES256 JWTs,
  so ``/mfa/verify`` / ``/mfa/enroll`` / ``/mfa/confirm`` exercise
  the real ``get_current_user`` path against a stubbed JWKS.
- ``FakeMfaBackend`` (``tests.test_mfa``) mimics GoTrue MFA: the
  only correct code is ``123456``; factors start unverified.
- ``SessionManager`` on a fresh ``InMemoryStaffSessionStore`` per
  test, with a movable ``FakeClock`` (exact expiry boundaries) and
  the LIVE prefix-version counter (rotation tests).

Covers the plan §3 contracts and the anti-enumeration rule:

- Role-first login: correct role + password + MFA -> staff session;
  a role card that is not the account's real role -> the SAME 401
  as a wrong password (body-identical, timing measured + reported).
- The four indistinguishable 401 cases: wrong password, wrong role,
  unknown email, suspended account (+ customer account at the staff
  door) — identical status + identical response bodies.
- Invite accept: happy path, reuse -> 404, expired -> 404, invalid ->
  404 (all the same 404).
- Forgot-password: always 200, identical bodies for known/unknown.
- MFA: verify, wrong code, unenrolled account, deleted factor,
  enroll/confirm (incl. pending-factor rotation), step-up verify.
- Sessions: logout revokes, idle 60 min expiry, absolute 12h expiry,
  prefix rotation invalidates, only-that-session revocation.
- Staff service Owner-only ops: suspend / delete / re-role /
  revoke-sessions / force-reset / MFA re-enrollment (incl. the
  re-enrollment actually retiring the old factor), non-Owner
  refusals, exactly-one-Owner rule.
- Secret prefix: path matrix (unit) + mounted-client proof.
- Store seam (Child D's ``Store.get_staff_role``, not landed yet):
  login resolves platform role/status store-first with registry
  fallback; ``ensure_staff_account`` synthesizes a registry row
  from an authoritative store row.
"""

from __future__ import annotations

import asyncio
import hashlib
import statistics
import time
import uuid
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

import app.routers.staff_auth as staff_auth_module
from app.auth import jwt as jwt_module
from app.auth.mfa import MfaService, get_mfa_service, set_mfa_service
from app.auth.provider import AuthSession, AuthUser, set_auth_provider
from app.auth.rate_limit import RateLimiter, set_rate_limiter
from app.auth.sessions import InMemoryStaffSessionStore, SessionManager
from app.core.config import Environment, settings
from app.core.errors import ApiError
from app.core.staff_prefix import (
    bump_prefix_version,
    check_staff_prefix,
    get_prefix_version,
    get_staff_host,
    require_staff_prefix,
    reset_prefix_version_for_tests,
)
from app.db import get_store, reset_store_for_tests
from app.main import _HTTP_STATUS_CODES, _error_body, create_app
from app.routers.staff_auth import router as staff_auth_router
from app.services.invites import reset_invites_for_tests
from app.services.staff import (
    DuplicateOwnerError,
    StaffAccount,
    StaffNotOwnerError,
    create_staff_account,
    create_staff_invite,
    delete_staff,
    ensure_staff_account,
    force_password_reset,
    get_staff_account,
    get_staff_account_by_email,
    mfa_re_enroll_staff,
    re_role_staff,
    reset_staff_state_for_tests,
    resolve_staff_role,
    revoke_staff_sessions,
    set_staff_pending_factor,
    set_staff_session_manager,
    suspend_staff,
)
from tests.test_auth import TEST_SUPABASE_URL, FakeAuthProvider, _test_jwks
from tests.test_mfa import CORRECT_CODE, FakeMfaBackend

OWNER_EMAIL = "owner@websurfacehq.com"
ADMIN_EMAIL = "admin@websurfacehq.com"
SUPPORT_EMAIL = "support@websurfacehq.com"
CUSTOMER_EMAIL = "customer@example.com"
UNKNOWN_EMAIL = "ghost@websurfacehq.com"
PASSWORD = "correct-horse-battery"
WRONG_PASSWORD = "wrong-password-123"
WRONG_CODE = "000000"
START = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    """A movable clock for the SessionManager (mirrors tests.test_sessions)."""

    def __init__(self, now: datetime = START) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now = self.now + delta


@pytest.fixture(autouse=True)
def _test_jwt_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """JWT verification uses the stubbed test JWKS (same as tests.test_auth)."""
    monkeypatch.setattr(settings, "supabase_url", TEST_SUPABASE_URL)
    monkeypatch.setattr(settings, "supabase_anon_key", None)
    monkeypatch.setattr(settings, "supabase_service_role_key", None)
    monkeypatch.setattr(jwt_module, "_fetch_jwks", _test_jwks)
    jwt_module.reset_jwks_cache()


@pytest.fixture(autouse=True)
def _reset_staff_state(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Fresh staff/invite/prefix state + the in-memory store (F-M1 pattern).

    The store singleton is process-global and Supabase-configured in
    this environment: any earlier module that resolved it (e.g. via
    ``create_app()``) caches a live ``SupabaseStore``. The Supabase
    keys are nulled HERE (not only in ``_test_jwt_settings``):
    this fixture's setup runs before ``_test_jwt_settings`` despite
    being defined after it, and ``reset_prefix_version_for_tests()``
    resolves the store while resetting the persisted version — with
    the real keys still active that caches a live ``SupabaseStore``
    and every staff mutation then hits real PostgREST (C2 fix made
    the store the source of truth, so the reset path touches it).
    Nulling first makes the reset re-select the in-memory store.
    Reset again on teardown so no cached store leaks to later modules.
    """
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


@pytest.fixture()
def staff_client() -> Generator[
    tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    None,
    None,
]:
    """Fresh app + fake auth + fake MFA + fresh session manager (fake clock)."""
    fake_auth = FakeAuthProvider()
    fake_mfa = FakeMfaBackend()
    mfa_service = MfaService(backend=fake_mfa)
    set_auth_provider(fake_auth)
    set_mfa_service(mfa_service)
    # The FakeClock must start at (approximately) the real wall-clock
    # time, NOT the frozen START default: SessionManager.issue() stamps
    # issued_at from this clock, but the router computes expires_in
    # from the REAL wall clock (staff_auth._now() /
    # _build_session_response). With the frozen 2026-11-20 start the
    # 12h absolute expiry passed on 2026-11-21 00:00 UTC, so the
    # remaining time clamps to 0 and the expires_in assertion fails on
    # every run since. Starting at real now keeps remaining ~= 43200
    # forever. Boundary tests advance this clock relatively, so they
    # are unaffected by the start value.
    clock = FakeClock(datetime.now(timezone.utc))
    manager = SessionManager(
        InMemoryStaffSessionStore(),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=get_prefix_version,
        clock=clock,
    )
    set_staff_session_manager(manager)
    set_rate_limiter(RateLimiter(max_attempts=10_000, window_seconds=900))
    # N-NEW2: NO duplicate mount here — create_app() already mounts
    # the staff router (at root while the prefix is empty, under
    # /<prefix> when one is set). The old unguarded duplicate mount
    # meant a request to /staff/auth/login with a prefix set hit
    # only the duplicate, so the suite could never catch a
    # production-mount regression. The real mount is exercised by
    # test_staff_login_uses_real_create_app_mount_with_prefix.
    app = create_app()
    # M3 host gate: the staff mounts reject any Host that is not the
    # staff host (TestClient defaults to "testserver"), so the client
    # speaks as the staff host. Tests that need a customer host pass
    # an explicit full URL.
    client = TestClient(app, base_url=f"http://{get_staff_host()}")
    yield client, fake_auth, mfa_service, manager, clock
    set_auth_provider(None)
    set_mfa_service(None)
    set_staff_session_manager(None)
    set_rate_limiter(None)


def _seed_staff(
    fake_auth: FakeAuthProvider,
    mfa_service: MfaService,
    email: str,
    role: str,
    *,
    password: str = PASSWORD,
    suspended: bool = False,
    mfa: bool = False,
    invited_by: uuid.UUID | None = None,
) -> tuple[StaffAccount, str | None]:
    """Create a provider user + staff row. Returns (account, factor_id).

    Enrolled seeds go through the REAL MFA service flow (enroll +
    challenge_and_verify with the fake backend), so the stored factor
    id is a genuinely verified factor.
    """
    auth_user = fake_auth.sign_up(email, password)
    assert auth_user is not None
    account = create_staff_account(auth_user.id, email, role, invited_by)
    if suspended:
        account.status = "suspended"
    factor_id: str | None = None
    if mfa:
        enrollment = mfa_service.enroll("seed-access-token")
        mfa_service.challenge_and_verify("seed-access-token", enrollment.factor_id, CORRECT_CODE)
        account.current_factor_id = enrollment.factor_id
        account.mfa_enrolled = True
        factor_id = enrollment.factor_id
    return account, factor_id


def _seed_owner_admin(
    fake_auth: FakeAuthProvider, mfa_service: MfaService
) -> tuple[StaffAccount, StaffAccount, str]:
    """Seed an enrolled Owner + an enrolled Admin. Returns (owner, admin, admin_factor_id)."""
    owner, _ = _seed_staff(fake_auth, mfa_service, OWNER_EMAIL, "owner", mfa=True)
    admin, admin_factor_id = _seed_staff(
        fake_auth, mfa_service, ADMIN_EMAIL, "admin", mfa=True, invited_by=owner.user_id
    )
    assert admin_factor_id is not None
    return owner, admin, admin_factor_id


def _staff_login(client: TestClient, role: str, email: str, password: str = PASSWORD) -> Any:
    return client.post(
        "/staff/auth/login", json={"role": role, "email": email, "password": password}
    )


def _aal1_token(client: TestClient, role: str, email: str) -> str:
    """Log in and return the AAL1 token from the login response."""
    response = _staff_login(client, role, email)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert body["mfa_required"] is True
    token = body["supabase_access_token"]
    assert isinstance(token, str) and token
    return token


def _login_with_mfa(client: TestClient, role: str, email: str) -> str:
    """Full login + MFA verify. Returns the staff session token (UUID)."""
    aal1 = _aal1_token(client, role, email)
    verify = client.post(
        "/staff/auth/mfa/verify",
        json={"code": CORRECT_CODE},
        headers={"Authorization": f"Bearer {aal1}"},
    )
    assert verify.status_code == 200, verify.text
    body: dict[str, Any] = verify.json()
    assert body["supabase_access_token"]  # transitional AAL2 token present
    token = body["access_token"]
    assert isinstance(token, str)
    uuid.UUID(token)  # the staff session token IS a UUID
    return token


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- Login: happy path + MFA ---------------------------------------------------


def test_login_mfa_happy_path_then_logout_revoke(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _owner, _admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    response = _staff_login(client, "admin", ADMIN_EMAIL)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert body["mfa_required"] is True
    assert body["enroll_required"] is False
    assert body["supabase_access_token"]
    assert "session" not in body  # no staff session before MFA verifies
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    # The token opens an authed staff endpoint (logout) ...
    logout = client.post("/staff/auth/logout", headers=_auth_headers(token))
    assert logout.status_code == 200, logout.text
    # ... and is dead afterwards.
    again = client.post("/staff/auth/logout", headers=_auth_headers(token))
    assert again.status_code == 401
    assert again.json()["code"] == "INVALID_SESSION"


def test_login_unenrolled_account_starts_mfa_enrollment(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_staff(fake_auth, mfa_service, SUPPORT_EMAIL, "support", mfa=False)
    response = _staff_login(client, "support", SUPPORT_EMAIL)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert body["mfa_required"] is True
    assert body["enroll_required"] is True
    aal1 = body["supabase_access_token"]
    assert isinstance(aal1, str) and aal1
    # The AAL1 token enrolls MFA ...
    enroll = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1))
    assert enroll.status_code == 200, enroll.text
    enroll_body: dict[str, Any] = enroll.json()
    assert enroll_body["qr_uri"].startswith("otpauth://totp/")
    assert enroll_body["secret"] and enroll_body["factor_id"]
    # ... and confirming the pending factor completes the sign-in.
    confirm = client.post(
        "/staff/auth/mfa/confirm",
        json={"factor_id": enroll_body["factor_id"], "code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert confirm.status_code == 200, confirm.text
    session_body: dict[str, Any] = confirm.json()
    assert session_body["user"]["role"] == "support"
    assert session_body["expires_in"] > 0
    account = get_staff_account_by_email(SUPPORT_EMAIL)
    assert account is not None and account.mfa_enrolled is True
    assert account.current_factor_id == enroll_body["factor_id"]
    # The next login goes through the challenge flow, not enrollment.
    assert _staff_login(client, "support", SUPPORT_EMAIL).json()["enroll_required"] is False


def test_login_unenrolled_account_verify_without_enrolling_is_401(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_staff(fake_auth, mfa_service, SUPPORT_EMAIL, "support", mfa=False)
    aal1 = _aal1_token(client, "support", SUPPORT_EMAIL)
    verify = client.post(
        "/staff/auth/mfa/verify",
        json={"code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert verify.status_code == 401
    assert verify.json()["code"] == "INVALID_MFA_CODE"


# --- Login: anti-enumeration ---------------------------------------------------


def test_login_wrong_role_spoof_is_generic_401(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    spoof = _staff_login(client, "owner", ADMIN_EMAIL)  # admin account, owner card
    assert spoof.status_code == 401
    assert spoof.json() == {
        "code": "INVALID_CREDENTIALS",
        "message": "Invalid role, email, or password",
        "details": None,
    }


def test_login_four_failure_cases_are_byte_identical(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _owner, _admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    _seed_staff(fake_auth, mfa_service, SUPPORT_EMAIL, "support", suspended=True)
    fake_auth.sign_up(CUSTOMER_EMAIL, PASSWORD)  # customer account, no staff row
    wrong_password = _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
    wrong_role = _staff_login(client, "owner", ADMIN_EMAIL)
    unknown_email = _staff_login(client, "admin", UNKNOWN_EMAIL)
    suspended = _staff_login(client, "support", SUPPORT_EMAIL)
    customer = _staff_login(client, "admin", CUSTOMER_EMAIL)
    cases = (wrong_password, wrong_role, unknown_email, suspended, customer)
    assert [r.status_code for r in cases] == [401, 401, 401, 401, 401]
    assert (
        cases[0].content
        == cases[1].content
        == cases[2].content
        == cases[3].content
        == cases[4].content
    )
    assert wrong_password.json() == {
        "code": "INVALID_CREDENTIALS",
        "message": "Invalid role, email, or password",
        "details": None,
    }


def test_failed_login_writes_exactly_one_audit_row(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """F4 fix (red-team): a failed staff login writes exactly ONE
    audit row — previously ``_audit_staff_auth`` skipped the store
    write whenever ``user_id`` was None, and ``staff.login_failed``
    was always called with None, so 0 rows were written.

    Known account: the row's actor is the account's real user id.
    Unknown email: the row's actor is the deterministic synthetic
    UUID derived from the email hash (never the plaintext email —
    asserted below, and the two failures for the same unknown
    address share one actor)."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    owner, admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    store = get_store()

    def _failed_rows() -> list[Any]:
        rows, _ = store.list_audit_logs(action="staff.login_failed", limit=100)
        return rows

    wrong = _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
    assert wrong.status_code == 401
    rows = _failed_rows()
    assert len(rows) == 1
    assert rows[0].user_id == admin.user_id
    assert rows[0].metadata == {"email_hash": hashlib.sha256(ADMIN_EMAIL.encode()).hexdigest()}
    assert ADMIN_EMAIL not in str(rows[0].metadata)

    unknown = _staff_login(client, "admin", UNKNOWN_EMAIL)
    assert unknown.status_code == 401
    rows = _failed_rows()
    assert len(rows) == 2
    unknown_hash = hashlib.sha256(UNKNOWN_EMAIL.encode()).hexdigest()
    unknown_rows = [r for r in rows if r.metadata.get("email_hash") == unknown_hash]
    assert len(unknown_rows) == 1
    assert unknown_rows[0].user_id not in (owner.user_id, admin.user_id)
    assert UNKNOWN_EMAIL not in str(unknown_rows[0].metadata)
    # Deterministic actor: the same unknown address maps to the same
    # synthetic actor on a second failure.
    assert _staff_login(client, "admin", UNKNOWN_EMAIL).status_code == 401
    rows = _failed_rows()
    assert len(rows) == 3
    repeat = [r for r in rows if r.metadata.get("email_hash") == unknown_hash]
    assert len(repeat) == 2
    assert repeat[0].user_id == repeat[1].user_id == unknown_rows[0].user_id


def test_login_timing_wrong_password_vs_wrong_role(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """Timing probe: wrong-password vs wrong-role medians.

    The password check runs in both paths (the dominant cost in
    production is GoTrue bcrypt); the role check adds only a dict
    lookup. Bound is the absolute gap < 50 ms + byte-identical
    bodies (H1 fix) — the ratio bound was removed (re-review #3,
    B2): both medians are ~2 ms, so a 1.5x ratio is scheduling
    noise, not a gate (~1 failure in 10). Measured on this VM at
    ~1.04x / ~0.7 ms over 25 iterations, so 50 ms leaves headroom
    for a loaded CI runner while still failing loudly if a future
    change short-circuits one path — the old 3x/100 ms bound would
    have passed a 2.9x leak.
    """
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    iterations = 25
    for _ in range(3):  # warm-up (JIT / connection setup, not measured)
        _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
        _staff_login(client, "owner", ADMIN_EMAIL)

    def median_ms(calls: list[float]) -> float:
        return statistics.median(calls) * 1000.0

    wrong_password_times: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
        wrong_password_times.append(time.perf_counter() - started)
    wrong_role_times: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        _staff_login(client, "owner", ADMIN_EMAIL)
        wrong_role_times.append(time.perf_counter() - started)
    pw_median = median_ms(wrong_password_times)
    role_median = median_ms(wrong_role_times)
    ratio = max(pw_median, role_median) / min(pw_median, role_median)
    print(
        f"[timing] staff login medians over {iterations} iterations: "
        f"wrong-password={pw_median:.2f}ms wrong-role={role_median:.2f}ms "
        f"ratio={ratio:.2f}x abs-gap={abs(pw_median - role_median):.2f}ms"
    )
    # Ratio bound removed (re-review #3, B2): both medians are ~2 ms,
    # so the 1.5x ratio is scheduling noise, not a gate (~1 failure
    # in 10). The absolute gap + byte-identical bodies stay.
    assert abs(pw_median - role_median) < 50.0


class _BcryptSimulatingProvider:
    """Test-only AuthProvider wrapper: a failed sign-in burns
    ``target_ms`` (a sleep standing in for GoTrue bcrypt) — but
    ONLY when the user exists, exactly like GoTrue, which runs
    bcrypt only for an existing user and answers fast for an
    unknown email. The plain fake answers instantly on every
    path, so without this no timing bound between the paths could
    hold in-process; with it, the unknown-email dummy and the
    known-email bcrypt are both ~``target_ms`` and the tightened
    bound below is meaningful. All other calls delegate."""

    def __init__(self, inner: FakeAuthProvider, target_ms: float) -> None:
        self._inner = inner
        self._target_ms = target_ms

    def sign_up(self, email: str, password: str) -> AuthUser | None:
        return self._inner.sign_up(email, password)

    def sign_in(self, email: str, password: str) -> AuthSession:
        try:
            return self._inner.sign_in(email, password)
        except ApiError as exc:
            if exc.status_code == 401 and self._inner.user_exists(email):
                time.sleep(self._target_ms / 1000.0)
            raise

    def user_exists(self, email: str) -> bool:
        return self._inner.user_exists(email)

    def disable_password(self, user_id: uuid.UUID) -> None:
        self._inner.disable_password(user_id)

    def sign_out(self, access_token: str) -> None:
        self._inner.sign_out(access_token)

    def reset_password(self, email: str) -> None:
        self._inner.reset_password(email)

    def exchange_code(self, code: str) -> AuthSession:
        return self._inner.exchange_code(code)


def test_login_unknown_email_runs_dummy_hash(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H1 (retuned): the unknown-email path runs the time-based
    dummy for ~``STAFF_DUMMY_HASH_TARGET_MS`` (default 75 ms,
    the measured GoTrue bcrypt component) — and the tightened
    bound holds: unknown-email median within 1.5x / 50 ms of the
    wrong-password median.

    The bcrypt-simulating provider (above) makes the fake's
    wrong-password path cost what GoTrue bcrypt costs, so the two
    paths can be compared in-process. A spy on
    ``_dummy_password_verification`` proves the dummy itself ran
    on the unknown path (call count == iterations) and did NOT run
    on the wrong-password path — the old assertion (``unknown >
    100 ms``) could pass with the dummy replaced by a sleep, and
    could not catch a miscalibration; the bound + the spy can.
    """
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    target_ms = float(settings.staff_dummy_hash_target_ms)
    set_auth_provider(_BcryptSimulatingProvider(fake_auth, target_ms))
    calls: list[int] = []
    original = staff_auth_module._dummy_password_verification

    def _counting(password: str, *, target_ms: float | None = None) -> None:
        calls.append(1)
        original(password, target_ms=target_ms)

    monkeypatch.setattr(staff_auth_module, "_dummy_password_verification", _counting)
    iterations = 10
    for _ in range(2):  # warm-up (dummy loop + sleep path, not measured)
        _staff_login(client, "admin", UNKNOWN_EMAIL, WRONG_PASSWORD)
        _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
    calls.clear()

    def _median_ms(times: list[float]) -> float:
        return statistics.median(times) * 1000.0

    unknown_times: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        resp = _staff_login(client, "admin", UNKNOWN_EMAIL, WRONG_PASSWORD)
        unknown_times.append(time.perf_counter() - started)
        assert resp.status_code == 401
        assert resp.json() == {
            "code": "INVALID_CREDENTIALS",
            "message": "Invalid role, email, or password",
            "details": None,
        }
    assert len(calls) == iterations  # the dummy ran on every unknown attempt
    unknown_median = _median_ms(unknown_times)
    calls.clear()
    wrong_password_times: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
        wrong_password_times.append(time.perf_counter() - started)
    assert calls == []  # no dummy on the known-email path (bcrypt ran)
    pw_median = _median_ms(wrong_password_times)
    ratio = max(unknown_median, pw_median) / min(unknown_median, pw_median)
    print(
        f"[timing] unknown-email median={unknown_median:.2f}ms "
        f"wrong-password median={pw_median:.2f}ms target={target_ms:.0f}ms "
        f"ratio={ratio:.2f}x abs-gap={abs(unknown_median - pw_median):.2f}ms "
        f"over {iterations} iterations"
    )
    # The dummy burned ~its target (not just "slow"): the unknown
    # median is at least 80% of the target.
    assert unknown_median >= 0.8 * target_ms
    # Tightened bound (same as the wrong-password/wrong-role probe).
    assert ratio < 1.5
    assert abs(unknown_median - pw_median) < 50.0


def test_login_customer_email_wrong_password_skips_dummy(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H1 double-count fix: a CUSTOMER email (Auth user, no staff
    row) with a wrong password pays bcrypt in GoTrue — so the dummy
    must NOT run there. Before the fix the handler ran the dummy
    whenever no staff row existed, so this path cost bcrypt AND
    the dummy (~one dummy-hash slower than a staff wrong-password,
    the same order as the original gap, inverted). The spy proves
    the dummy is skipped here and runs on the unknown path, and the
    medians stay within the tightened bound."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    fake_auth.sign_up(CUSTOMER_EMAIL, PASSWORD)  # customer account, no staff row
    target_ms = float(settings.staff_dummy_hash_target_ms)
    set_auth_provider(_BcryptSimulatingProvider(fake_auth, target_ms))
    calls: list[int] = []
    original = staff_auth_module._dummy_password_verification

    def _counting(password: str, *, target_ms: float | None = None) -> None:
        calls.append(1)
        original(password, target_ms=target_ms)

    monkeypatch.setattr(staff_auth_module, "_dummy_password_verification", _counting)
    iterations = 10
    for _ in range(2):  # warm-up, not measured
        _staff_login(client, "admin", CUSTOMER_EMAIL, WRONG_PASSWORD)
        _staff_login(client, "admin", UNKNOWN_EMAIL, WRONG_PASSWORD)
    calls.clear()
    customer_times: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        resp = _staff_login(client, "admin", CUSTOMER_EMAIL, WRONG_PASSWORD)
        customer_times.append(time.perf_counter() - started)
        assert resp.status_code == 401
        assert resp.json()["code"] == "INVALID_CREDENTIALS"
    assert calls == []  # bcrypt ran (Auth user exists) — no dummy
    unknown_times: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        resp = _staff_login(client, "admin", UNKNOWN_EMAIL, WRONG_PASSWORD)
        unknown_times.append(time.perf_counter() - started)
        assert resp.status_code == 401
    assert len(calls) == iterations  # no Auth user — the dummy ran
    customer_median = statistics.median(customer_times) * 1000.0
    unknown_median = statistics.median(unknown_times) * 1000.0
    ratio = max(customer_median, unknown_median) / min(customer_median, unknown_median)
    print(
        f"[timing] customer-wrong-password median={customer_median:.2f}ms "
        f"unknown-email median={unknown_median:.2f}ms ratio={ratio:.2f}x "
        f"abs-gap={abs(customer_median - unknown_median):.2f}ms "
        f"over {iterations} iterations"
    )
    assert ratio < 1.5
    assert abs(customer_median - unknown_median) < 50.0


def test_login_invalid_role_value_is_422_without_account_info(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, _fake_auth, _fake_mfa, _manager, _clock = staff_client
    response = _staff_login(client, "superuser", ADMIN_EMAIL)
    assert response.status_code == 422
    # 422 details never echo the submitted password (main.py strips input/ctx).
    assert WRONG_PASSWORD not in response.text
    assert PASSWORD not in response.text


def test_login_rate_limited_after_five_attempts() -> None:
    """Default limiter (5 / 15 min): the 6th attempt is 429 with Retry-After."""
    fake_auth = FakeAuthProvider()
    set_auth_provider(fake_auth)
    set_rate_limiter(RateLimiter())
    app = create_app()
    # M3 host gate: speak as the staff host (see staff_client).
    client = TestClient(app, base_url=f"http://{get_staff_host()}")
    try:
        for _ in range(5):
            response = _staff_login(client, "admin", UNKNOWN_EMAIL)
            assert response.status_code == 401, response.text
        limited = _staff_login(client, "admin", UNKNOWN_EMAIL)
        assert limited.status_code == 429
        assert limited.json()["code"] == "RATE_LIMITED"
        assert limited.headers.get("Retry-After")
    finally:
        set_auth_provider(None)
        set_rate_limiter(None)


# --- MFA verify / enroll / confirm ----------------------------------------------


def test_mfa_verify_wrong_code_and_deleted_factor(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _owner, admin, admin_factor = _seed_owner_admin(fake_auth, mfa_service)
    aal1 = _aal1_token(client, "admin", ADMIN_EMAIL)
    wrong = client.post(
        "/staff/auth/mfa/verify",
        json={"code": WRONG_CODE},
        headers=_auth_headers(aal1),
    )
    assert wrong.status_code == 401
    assert wrong.json()["code"] == "INVALID_MFA_CODE"
    # The factor is unenrolled in GoTrue: the same code now fails the
    # factor lookup, with the identical generic error.
    get_mfa_service().unenroll(aal1, admin_factor)
    deleted = client.post(
        "/staff/auth/mfa/verify",
        json={"code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert deleted.status_code == 401
    assert deleted.json()["code"] == "INVALID_MFA_CODE"


def test_mfa_enroll_rotates_pending_factor(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_staff(fake_auth, mfa_service, SUPPORT_EMAIL, "support", mfa=False)
    aal1 = _aal1_token(client, "support", SUPPORT_EMAIL)
    first = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1)).json()
    second = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1)).json()
    assert first["factor_id"] != second["factor_id"]
    # The fake backend returns one constant secret for every
    # enrollment (a clearly-fake stand-in), so secret rotation is
    # not assertable here; the rotation property is the factor id,
    # proven below by the stale factor no longer confirming.
    # The FIRST factor id no longer confirms (the pending factor rotated).
    stale = client.post(
        "/staff/auth/mfa/confirm",
        json={"factor_id": first["factor_id"], "code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert stale.status_code == 401
    assert stale.json()["code"] == "INVALID_MFA_CODE"
    ok = client.post(
        "/staff/auth/mfa/confirm",
        json={"factor_id": second["factor_id"], "code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert ok.status_code == 200, ok.text


def test_mfa_enroll_rejects_customer_token_with_403(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    fake_auth.sign_up(CUSTOMER_EMAIL, PASSWORD)
    customer_login = client.post(
        "/api/v1/auth/login", json={"email": CUSTOMER_EMAIL, "password": PASSWORD}
    )
    assert customer_login.status_code == 200, customer_login.text
    customer_token = customer_login.json()["access_token"]
    enroll = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(customer_token))
    assert enroll.status_code == 403
    assert enroll.json()["code"] == "FORBIDDEN"


# --- Forgot password / invite accept / step-up -------------------------------------


def test_forgot_password_always_200_identical_bodies(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    known = client.post("/staff/auth/forgot-password", json={"email": ADMIN_EMAIL})
    unknown = client.post("/staff/auth/forgot-password", json={"email": UNKNOWN_EMAIL})
    assert known.status_code == 200 and unknown.status_code == 200
    assert known.content == unknown.content
    assert known.json()["message"].startswith("If an account exists")
    assert ADMIN_EMAIL in fake_auth.reset_requested


def test_invite_accept_happy_path_then_login(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    owner, _admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    invite, token = create_staff_invite(owner, "newhire@websurfacehq.com", "support")
    assert len(token) == 43  # 32 random bytes, URL-safe
    assert invite.token_hash != token
    accept = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
    assert accept.status_code == 201, accept.text
    body: dict[str, Any] = accept.json()
    assert body["user"]["email"] == "newhire@websurfacehq.com"
    assert body["user"]["role"] == "support"
    assert "check your inbox" in body["message"].lower()
    # The new account logs in and enrolls MFA (enroll_required flow).
    pending = _staff_login(client, "support", "newhire@websurfacehq.com")
    assert pending.json()["enroll_required"] is True
    aal1 = pending.json()["supabase_access_token"]
    enroll = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1))
    assert enroll.status_code == 200, enroll.text
    factor_id = enroll.json()["factor_id"]
    confirm = client.post(
        "/staff/auth/mfa/confirm",
        json={"factor_id": factor_id, "code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert confirm.status_code == 200, confirm.text


def test_invite_accept_reuse_and_invalid_are_same_404(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    owner, _admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    invite, token = create_staff_invite(owner, "reuse@websurfacehq.com", "support")
    first = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
    assert first.status_code == 201, first.text
    reuse = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
    invalid = client.post(
        "/staff/auth/invite/accept", json={"token": "nonsense-token", "password": PASSWORD}
    )
    assert reuse.status_code == 404 and invalid.status_code == 404
    assert reuse.content == invalid.content
    assert reuse.json()["code"] == "NOT_FOUND"


def test_step_up_verify_marks_session(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, manager, _clock = staff_client
    _owner, _admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    wrong_code = client.post(
        "/staff/auth/step-up/verify",
        json={"password": PASSWORD, "code": WRONG_CODE},
        headers=_auth_headers(token),
    )
    assert wrong_code.status_code == 401
    assert wrong_code.json()["code"] == "INVALID_MFA_CODE"
    wrong_password = client.post(
        "/staff/auth/step-up/verify",
        json={"password": WRONG_PASSWORD, "code": CORRECT_CODE},
        headers=_auth_headers(token),
    )
    assert wrong_password.status_code == 401
    assert wrong_password.json()["code"] == "INVALID_CREDENTIALS"
    ok = client.post(
        "/staff/auth/step-up/verify",
        json={"password": PASSWORD, "code": CORRECT_CODE},
        headers=_auth_headers(token),
    )
    assert ok.status_code == 200
    assert ok.json() == {"step_up_verified": True}
    live = manager.list_active_sessions(_admin.user_id)
    assert len(live) == 1
    assert live[0].step_up_verified_at is not None
    assert manager.step_up_required(live[0]) is False


def test_step_up_wrong_password_is_generic_401(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """F8 fix (red-team): a wrong password at step-up answers the
    BYTE-IDENTICAL generic login 401 — previously it answered
    "Invalid password", a different body from the login failure."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    login_failure = _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
    assert login_failure.status_code == 401
    step_up_failure = client.post(
        "/staff/auth/step-up/verify",
        json={"password": WRONG_PASSWORD, "code": CORRECT_CODE},
        headers=_auth_headers(token),
    )
    assert step_up_failure.status_code == 401
    assert step_up_failure.content == login_failure.content
    assert step_up_failure.json() == {
        "code": "INVALID_CREDENTIALS",
        "message": "Invalid role, email, or password",
        "details": None,
    }


# --- Sessions: idle / absolute / prefix rotation -----------------------------------


def test_session_idle_expiry(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    clock.advance(timedelta(minutes=61))
    response = client.post("/staff/auth/logout", headers=_auth_headers(token))
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_SESSION"


def test_session_absolute_expiry(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    clock.advance(timedelta(hours=12))
    response = client.post("/staff/auth/logout", headers=_auth_headers(token))
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_SESSION"


def test_prefix_rotation_invalidates_sessions(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    assert get_prefix_version() == 1
    assert bump_prefix_version() == 2
    response = client.post("/staff/auth/logout", headers=_auth_headers(token))
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_SESSION"
    # A fresh login after rotation works (stamped with the new version).
    assert _staff_login(client, "admin", ADMIN_EMAIL).status_code == 200


def test_rotate_prefix_revokes_sessions_under_overridden_store(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """F6 fix (red-team): ``POST /admin/settings/rotate-prefix``
    revokes sessions through the OVERRIDE-AWARE manager
    (``app.services.staff.get_staff_session_manager``) — it used
    ``app.auth.sessions.get_session_manager()`` (default store),
    so under an overridden store the explicit revoke silently ran
    against the wrong store (``sessions_revoked: 0``, rows
    unrevoked) and only the version check killed the sessions.
    This fixture's manager IS the override, and
    ``admin_ops.get_session_manager`` is NOT patched here, so the
    old wiring answers ``sessions_revoked: 0``."""
    client, fake_auth, mfa_service, manager, _clock = staff_client
    owner, admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    owner_session = manager.issue(owner.user_id)
    admin_session = manager.issue(admin.user_id)
    resp = client.post(
        "/admin/settings/rotate-prefix",
        json={"confirm": True},
        headers=_auth_headers(str(owner_session.id)),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["prefix_version"] == 2
    assert resp.json()["sessions_revoked"] == 2
    assert manager.list_active_sessions(owner.user_id) == []
    assert manager.list_active_sessions(admin.user_id) == []
    # Both pre-rotation sessions are dead (revoked rows, not just
    # version-stale): neither validates anymore.
    assert (
        client.post("/staff/auth/logout", headers=_auth_headers(str(owner_session.id))).status_code
        == 401
    )
    assert (
        client.post("/staff/auth/logout", headers=_auth_headers(str(admin_session.id))).status_code
        == 401
    )


def test_logout_revokes_only_that_session(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    token_a = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    token_b = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    assert client.post("/staff/auth/logout", headers=_auth_headers(token_a)).status_code == 200
    assert client.post("/staff/auth/logout", headers=_auth_headers(token_a)).status_code == 401
    assert client.post("/staff/auth/logout", headers=_auth_headers(token_b)).status_code == 200


def test_staff_session_bearer_rejects_garbage(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, _fake_auth, _fake_mfa, _manager, _clock = staff_client
    for bad in ("not-a-uuid", str(uuid.uuid4())):
        response = client.post("/staff/auth/logout", headers=_auth_headers(bad))
        assert response.status_code == 401
        assert response.json()["code"] == "INVALID_SESSION"
    missing = client.post("/staff/auth/logout")
    assert missing.status_code == 401
    assert missing.json()["code"] == "INVALID_SESSION"


# --- Staff service: Owner-only ops ---------------------------------------------------


def test_owner_only_ops_reject_non_owner(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    _client, fake_auth, mfa_service, _manager, _clock = staff_client
    owner, admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    with pytest.raises(StaffNotOwnerError):
        suspend_staff(admin, owner.user_id)
    with pytest.raises(StaffNotOwnerError):
        delete_staff(admin, owner.user_id)
    with pytest.raises(StaffNotOwnerError):
        re_role_staff(admin, owner.user_id, "support")
    with pytest.raises(StaffNotOwnerError):
        revoke_staff_sessions(admin, owner.user_id)
    with pytest.raises(StaffNotOwnerError):
        force_password_reset(admin, owner.user_id)
    with pytest.raises(StaffNotOwnerError):
        mfa_re_enroll_staff(admin, owner.user_id)
    with pytest.raises(StaffNotOwnerError):
        create_staff_invite(admin, "x@websurfacehq.com", "support")


def test_owner_cannot_suspend_delete_or_rerole_owner(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    _client, fake_auth, mfa_service, _manager, _clock = staff_client
    owner, _admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    from app.services.staff import OwnerProtectedError

    with pytest.raises(OwnerProtectedError):
        suspend_staff(owner, owner.user_id)
    with pytest.raises(OwnerProtectedError):
        delete_staff(owner, owner.user_id)
    with pytest.raises(OwnerProtectedError):
        re_role_staff(owner, owner.user_id, "admin")
    with pytest.raises(DuplicateOwnerError):
        create_staff_invite(owner, "second-owner@websurfacehq.com", "owner")


def test_suspend_delete_rerole_take_effect_at_login(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, manager, _clock = staff_client
    owner, admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    # Suspend: session dies instantly, login answers the generic 401.
    suspend_staff(owner, admin.user_id)
    assert manager.list_active_sessions(admin.user_id) == []
    assert client.post("/staff/auth/logout", headers=_auth_headers(token)).status_code == 401
    suspended_login = _staff_login(client, "admin", ADMIN_EMAIL)
    assert suspended_login.status_code == 401
    assert suspended_login.json()["code"] == "INVALID_CREDENTIALS"
    # Re-role while suspended is allowed; unsuspend via direct status
    # reset is a test-only shortcut (no unsuspend endpoint in the plan).
    re_role_staff(owner, admin.user_id, "support")
    account = get_staff_account(admin.user_id)
    assert account is not None
    account.status = "active"
    assert _staff_login(client, "support", ADMIN_EMAIL).status_code == 200
    assert _staff_login(client, "admin", ADMIN_EMAIL).status_code == 401
    # Delete: the account is gone; login answers the generic 401.
    delete_staff(owner, admin.user_id)
    assert get_staff_account(admin.user_id) is None
    assert _staff_login(client, "support", ADMIN_EMAIL).status_code == 401


def test_force_reset_and_mfa_reenroll_revoke_sessions(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, manager, _clock = staff_client
    owner, admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    force_password_reset(owner, admin.user_id)
    assert ADMIN_EMAIL in fake_auth.reset_requested
    assert client.post("/staff/auth/logout", headers=_auth_headers(token)).status_code == 401
    # F2 fix: the old password is dead after a force-reset — the
    # admin cannot sign in again until the reset link sets a new
    # password (see test_force_reset_invalidates_old_password).
    assert _staff_login(client, "admin", ADMIN_EMAIL).status_code == 401
    # MFA re-enroll: enrolled flag + stored factor cleared, sessions
    # revoked; the next login asks for enrollment even though GoTrue
    # still holds the old verified factor (it is retired from the
    # staff flow by the cleared factor id). A second admin stands in
    # here — the first admin's password is dead (force-reset above),
    # so it cannot log in again to demonstrate the re-enroll flow.
    admin2, _factor2 = _seed_staff(
        fake_auth,
        mfa_service,
        "admin2@websurfacehq.com",
        "admin",
        mfa=True,
        invited_by=owner.user_id,
    )
    token2 = _login_with_mfa(client, "admin", "admin2@websurfacehq.com")
    assert len(manager.list_active_sessions(admin2.user_id)) >= 1
    mfa_re_enroll_staff(owner, admin2.user_id)
    assert client.post("/staff/auth/logout", headers=_auth_headers(token2)).status_code == 401
    account = get_staff_account(admin2.user_id)
    assert account is not None
    assert account.mfa_enrolled is False
    assert account.current_factor_id is None
    assert (
        _staff_login(client, "admin", "admin2@websurfacehq.com").json()["enroll_required"] is True
    )


def test_force_reset_invalidates_old_password(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """F2 fix (red-team): after an Owner force-reset, the OLD password
    no longer signs in — previously force-reset only sent the reset
    email, and old password + correct TOTP still minted a brand-new
    staff session. The reset email is still requested (the reset link
    is the only way back in), and the live session is revoked as
    before."""
    client, fake_auth, mfa_service, manager, _clock = staff_client
    owner, admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    force_password_reset(owner, admin.user_id)
    assert ADMIN_EMAIL in fake_auth.reset_requested
    # The pre-reset session is dead.
    assert client.post("/staff/auth/logout", headers=_auth_headers(token)).status_code == 401
    assert manager.list_active_sessions(admin.user_id) == []
    # The old password is dead at the provider AND at the door:
    # no new login, no new session even with the correct TOTP.
    with pytest.raises(ApiError) as exc:
        fake_auth.sign_in(ADMIN_EMAIL, PASSWORD)
    assert exc.value.status_code == 401
    assert _staff_login(client, "admin", ADMIN_EMAIL).status_code == 401


def test_revoke_sessions_owner_op(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    client, fake_auth, mfa_service, manager, _clock = staff_client
    owner, admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    token_a = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    token_b = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    assert revoke_staff_sessions(owner, admin.user_id) == 2
    assert manager.list_active_sessions(admin.user_id) == []
    assert client.post("/staff/auth/logout", headers=_auth_headers(token_a)).status_code == 401
    assert client.post("/staff/auth/logout", headers=_auth_headers(token_b)).status_code == 401


# --- Secret prefix -------------------------------------------------------------------


def test_staff_prefix_path_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "staff_url_prefix", "s3cr3t-prefix")
    # Staff host, outside the prefix -> 404.
    with pytest.raises(ApiError) as exc:
        check_staff_prefix("admin.websurfacehq.com", "/staff/auth/login")
    assert exc.value.status_code == 404 and exc.value.code == "NOT_FOUND"
    with pytest.raises(ApiError):
        check_staff_prefix("admin.websurfacehq.com:443", "/other")
    with pytest.raises(ApiError):
        check_staff_prefix("admin.websurfacehq.com", "/s3cr3t-prefix-evil/login")
    # Staff host, inside the prefix -> passes (exact root + subtree).
    check_staff_prefix("admin.websurfacehq.com", "/s3cr3t-prefix")
    check_staff_prefix("admin.websurfacehq.com", "/s3cr3t-prefix/staff/auth/login")
    check_staff_prefix("admin.websurfacehq.com", "/s3cr3t-prefix/")
    # Customer host is never gated by the prefix.
    check_staff_prefix("websurfacehq.com", "/staff/auth/login")
    check_staff_prefix("websurfacehq.com", "/s3cr3t-prefix/staff/auth/login")
    # Empty prefix (local dev): enforcement off everywhere.
    monkeypatch.setattr(settings, "staff_url_prefix", "")
    check_staff_prefix("admin.websurfacehq.com", "/staff/auth/login")


def test_require_staff_prefix_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "staff_url_prefix", "s3cr3t-prefix")

    def _request(path: str, host: str) -> Any:
        from starlette.requests import Request as StarletteRequest

        scope: dict[str, Any] = {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "query_string": b"",
            "headers": [(b"host", host.encode())],
        }
        return StarletteRequest(scope)

    with pytest.raises(ApiError):
        asyncio.run(require_staff_prefix(_request("/staff/auth/login", "admin.websurfacehq.com")))
    asyncio.run(require_staff_prefix(_request("/s3cr3t-prefix/login", "admin.websurfacehq.com")))
    asyncio.run(require_staff_prefix(_request("/staff/auth/login", "websurfacehq.com")))


def test_staff_prefix_mounted_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Router mounted under the prefix: outside -> 404, inside -> handler.

    Built on a bare FastAPI app (not ``create_app()``): the bare app
    isolates the guarded mount — the shape the plan requires
    ("everything outside the prefix answers a generic 404"). The
    error handlers are the app's own (``_error_body`` +
    ``_HTTP_STATUS_CODES``), so the 404/401 bodies match production.
    The REAL production mount is proven separately by
    ``test_staff_login_uses_real_create_app_mount_with_prefix``,
    which builds ``create_app()`` with a prefix set: ``main.py``
    mounts the staff router UNDER the prefix with the
    ``require_staff_prefix`` + ``require_staff_host`` guards, so
    there is no unguarded root mount in production (an earlier
    draft of this docstring claimed otherwise — it was false for
    the current ``main.py`` and is corrected here, N-NEW2).
    """
    monkeypatch.setattr(settings, "staff_url_prefix", "s3cr3t-prefix")
    fake_auth = FakeAuthProvider()
    set_auth_provider(fake_auth)
    set_rate_limiter(RateLimiter(max_attempts=10_000, window_seconds=900))
    app = FastAPI()

    @app.exception_handler(ApiError)
    async def _api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.status_code, exc.code, exc.message, exc.details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _HTTP_STATUS_CODES.get(exc.status_code, "HTTP_ERROR")
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.status_code, code, str(exc.detail)),
        )

    app.include_router(
        staff_auth_router,
        prefix="/s3cr3t-prefix",
        dependencies=[Depends(require_staff_prefix)],
    )
    client = TestClient(app)
    try:
        body = {"role": "admin", "email": UNKNOWN_EMAIL, "password": PASSWORD}
        outside = client.post("http://admin.websurfacehq.com/staff/auth/login", json=body)
        assert outside.status_code == 404
        assert outside.json()["code"] == "NOT_FOUND"
        inside = client.post(
            "http://admin.websurfacehq.com/s3cr3t-prefix/staff/auth/login", json=body
        )
        assert inside.status_code == 401
        assert inside.json()["code"] == "INVALID_CREDENTIALS"
    finally:
        set_auth_provider(None)
        set_rate_limiter(None)


def test_staff_login_uses_real_create_app_mount_with_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NEW1: the staff login flow through ``create_app()``'s REAL
    mount with a prefix set — not a fixture double-mount, not a
    bare app.

    With ``STAFF_URL_PREFIX`` set, the production mount serves
    ``/<prefix>/staff/auth/login`` and the bare path answers the
    generic 404. This test FAILS if the mount guard is ever
    removed (a root mount would answer the bare path with the
    login 401 instead of 404) — the re-review proved the mount
    correct by hand but the suite never exercised it (N-NEW2).
    The prefix is set BEFORE ``create_app()`` (the mount reads it
    at build time); the client speaks as the staff host (M3 gate).
    """
    prefix = "s3cr3t-prefix-12345678"
    monkeypatch.setattr(settings, "staff_url_prefix", prefix)
    fake_auth = FakeAuthProvider()
    fake_mfa = FakeMfaBackend()
    mfa_service = MfaService(backend=fake_mfa)
    set_auth_provider(fake_auth)
    set_mfa_service(mfa_service)
    manager = SessionManager(
        InMemoryStaffSessionStore(),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=get_prefix_version,
    )
    set_staff_session_manager(manager)
    set_rate_limiter(RateLimiter(max_attempts=10_000, window_seconds=900))
    app = create_app()
    client = TestClient(app, base_url=f"http://{get_staff_host()}")
    try:
        _owner, _admin, _factor = _seed_owner_admin(fake_auth, mfa_service)

        def _prefixed_login(password: str) -> Any:
            return client.post(
                f"/{prefix}/staff/auth/login",
                json={"role": "admin", "email": ADMIN_EMAIL, "password": password},
            )

        # Inside the prefix, through the real mount: correct
        # password -> 200 with the MFA challenge (no session yet).
        ok = _prefixed_login(PASSWORD)
        assert ok.status_code == 200, ok.text
        assert ok.json()["mfa_required"] is True
        # ... and a wrong password -> the generic 401.
        wrong = _prefixed_login(WRONG_PASSWORD)
        assert wrong.status_code == 401
        assert wrong.json()["code"] == "INVALID_CREDENTIALS"
        # Outside the prefix, same body -> the generic 404.
        bare = client.post(
            "/staff/auth/login",
            json={"role": "admin", "email": ADMIN_EMAIL, "password": WRONG_PASSWORD},
        )
        assert bare.status_code == 404
        assert bare.json()["code"] == "NOT_FOUND"
    finally:
        set_auth_provider(None)
        set_mfa_service(None)
        set_staff_session_manager(None)
        set_rate_limiter(None)


def test_openapi_json_404_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """F1 fix (red-team): ``/openapi.json`` is 404 in production —
    it used to serve 200 (66 KB) enumerating every staff route WITH
    the secret prefix in the path, from any host, with no auth,
    while ``/docs`` and ``/redoc`` were already gated. ``/docs``
    and ``/redoc`` stay 404 too, and the prefix appears in none of
    the three responses."""
    prefix = "s3cr3t-prefix-12345678"
    monkeypatch.setattr(settings, "staff_url_prefix", prefix)
    monkeypatch.setattr(settings, "environment", Environment.PRODUCTION)
    client = TestClient(create_app())
    for path in ("/openapi.json", "/docs", "/redoc"):
        resp = client.get(path)
        assert resp.status_code == 404, path
        assert prefix not in resp.text, path


def test_openapi_schema_never_lists_staff_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    """F1 defence in depth: the staff routers are excluded from the
    OpenAPI schema (``include_in_schema=False``) in EVERY
    environment — in dev, where the schema IS served, it must not
    enumerate the secret-prefixed staff routes either. The routes
    themselves still serve (proven by the prefix tests above); only
    the schema omits them."""
    prefix = "s3cr3t-prefix-12345678"
    monkeypatch.setattr(settings, "staff_url_prefix", prefix)
    client = TestClient(create_app())
    resp = client.get("/openapi.json")
    assert resp.status_code == 200, resp.text
    assert prefix not in resp.text
    assert "/staff/auth/login" not in resp.text
    assert "/admin/users/invite" not in resp.text


def test_public_staff_profile_never_leaks_mfa_material(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    from app.services.staff import public_staff_profile

    _client, fake_auth, mfa_service, _manager, _clock = staff_client
    _owner, admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    profile = public_staff_profile(admin)
    assert "mfa_secret" not in profile and "pending_mfa_secret" not in profile
    assert "secret" not in str(profile).lower()
    assert "factor" not in str(profile).lower()
    assert profile["role"] == "admin" and profile["mfa_enrolled"] is True


# --- Store seam: Store.get_staff_role (Child D landed it) -------------------
# The InMemoryStore implementation reads this registry, so it can
# never disagree with it — these tests patch the method on the live
# store instance to simulate a store that DOES disagree (the
# production SupabaseStore reading staff_roles), proving the login
# flow takes the store's answer.


def _patch_store_role(monkeypatch: pytest.MonkeyPatch, result: tuple[str, str] | None) -> None:
    """Simulate a landed ``Store.get_staff_role`` on the store instance."""
    monkeypatch.setattr(get_store(), "get_staff_role", lambda user_id: result, raising=False)


def test_resolve_staff_role_store_first_registry_fallback(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _client, fake_auth, mfa_service, _manager, _clock = staff_client
    account, _ = _seed_staff(fake_auth, mfa_service, ADMIN_EMAIL, "admin", mfa=True)
    # A store WITHOUT the method (pre-D shape): the registry answers.
    assert resolve_staff_role(account.user_id, store=cast(Any, object())) == (
        "admin",
        "active",
    )
    # Store disagrees with the registry: the store wins.
    _patch_store_role(monkeypatch, ("support", "active"))
    assert resolve_staff_role(account.user_id) == ("support", "active")
    # Store does not know the user: the registry answers.
    _patch_store_role(monkeypatch, None)
    assert resolve_staff_role(account.user_id) == ("admin", "active")

    # Store failure: the registry answers (resolver never raises).
    def _store_down(user_id: uuid.UUID) -> tuple[str, str] | None:
        raise RuntimeError("store down")

    monkeypatch.setattr(get_store(), "get_staff_role", _store_down, raising=False)
    assert resolve_staff_role(account.user_id) == ("admin", "active")
    # Neither knows the user.
    _patch_store_role(monkeypatch, None)
    assert resolve_staff_role(uuid.uuid4()) is None


def test_ensure_staff_account_synthesizes_from_store(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _client, _fake_auth, _mfa_service, _manager, _clock = staff_client
    user_id = uuid.uuid4()
    _patch_store_role(monkeypatch, ("admin", "suspended"))
    account = ensure_staff_account(user_id, ADMIN_EMAIL)
    assert account is not None
    assert account.role == "admin" and account.status == "suspended"
    assert account.email == ADMIN_EMAIL
    # Second call returns the same registry row (cache-fill, not a duplicate).
    assert ensure_staff_account(user_id, ADMIN_EMAIL) is account
    # Neither the store nor the registry knows the user.
    _patch_store_role(monkeypatch, None)
    assert ensure_staff_account(uuid.uuid4(), UNKNOWN_EMAIL) is None


def test_login_role_resolved_from_store(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Store says admin; registry says support -> the store decides: 200."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_staff(fake_auth, mfa_service, SUPPORT_EMAIL, "support", mfa=True)
    _patch_store_role(monkeypatch, ("admin", "active"))
    response = _staff_login(client, "admin", SUPPORT_EMAIL)
    assert response.status_code == 200, response.text
    assert response.json()["enroll_required"] is False


def test_login_store_suspended_overrides_registry_active(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Store says suspended; registry says active -> the generic 401."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_staff(fake_auth, mfa_service, ADMIN_EMAIL, "admin", mfa=True)
    _patch_store_role(monkeypatch, ("admin", "suspended"))
    response = _staff_login(client, "admin", ADMIN_EMAIL)
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_CREDENTIALS"
    wrong_password = _staff_login(client, "admin", ADMIN_EMAIL, WRONG_PASSWORD)
    assert wrong_password.status_code == 401
    assert wrong_password.json() == response.json()


def test_login_store_returns_none_falls_back_to_registry(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Store knows nobody yet -> the registry decides, as today."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_staff(fake_auth, mfa_service, ADMIN_EMAIL, "admin", mfa=True)
    _patch_store_role(monkeypatch, None)
    response = _staff_login(client, "admin", ADMIN_EMAIL)
    assert response.status_code == 200, response.text
    assert response.json()["enroll_required"] is False


# --- C1 / C2 / C3 / M2 regression tests (security-review fix round) ---------


def test_c1_enrolled_account_enroll_is_409_and_victim_factor_survives(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """C1: a password-only attacker holding the victim's AAL1 token
    cannot enroll a new factor over the victim's, and cannot confirm
    one either — the victim's factor stays live."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _owner, _admin, admin_factor = _seed_owner_admin(fake_auth, mfa_service)
    attacker_aal1 = _aal1_token(client, "admin", ADMIN_EMAIL)
    enroll = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(attacker_aal1))
    assert enroll.status_code == 409
    assert enroll.json()["code"] == "MFA_ALREADY_ENROLLED"
    # No pending factor exists, so confirm is impossible too — even
    # presenting the victim's own factor id is not a pending factor.
    confirm = client.post(
        "/staff/auth/mfa/confirm",
        json={"factor_id": admin_factor, "code": CORRECT_CODE},
        headers=_auth_headers(attacker_aal1),
    )
    assert confirm.status_code == 401
    assert confirm.json()["code"] == "INVALID_MFA_CODE"
    # The victim's factor is undisplaced: the victim still signs in.
    victim_session = _login_with_mfa(client, "admin", ADMIN_EMAIL)
    assert uuid.UUID(victim_session)
    account = get_staff_account_by_email(ADMIN_EMAIL)
    assert account is not None and account.current_factor_id == admin_factor


def test_c1_confirm_replacement_requires_existing_factor_code(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """C1 defense-in-depth: when a replacement pending factor exists
    alongside the verified factor, confirming it requires a code
    against the EXISTING factor first."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _owner, admin, _admin_factor = _seed_owner_admin(fake_auth, mfa_service)
    pending = mfa_service.enroll("seed-access-token")
    set_staff_pending_factor(admin.user_id, pending.factor_id)
    aal1 = _aal1_token(client, "admin", ADMIN_EMAIL)
    no_code = client.post(
        "/staff/auth/mfa/confirm",
        json={"factor_id": pending.factor_id, "code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert no_code.status_code == 401
    assert no_code.json()["code"] == "INVALID_MFA_CODE"
    wrong_code = client.post(
        "/staff/auth/mfa/confirm",
        json={"factor_id": pending.factor_id, "code": CORRECT_CODE, "existing_code": WRONG_CODE},
        headers=_auth_headers(aal1),
    )
    assert wrong_code.status_code == 401
    assert wrong_code.json()["code"] == "INVALID_MFA_CODE"
    ok = client.post(
        "/staff/auth/mfa/confirm",
        json={
            "factor_id": pending.factor_id,
            "code": CORRECT_CODE,
            "existing_code": CORRECT_CODE,
        },
        headers=_auth_headers(aal1),
    )
    assert ok.status_code == 200, ok.text
    account = get_staff_account_by_email(ADMIN_EMAIL)
    assert account is not None and account.current_factor_id == pending.factor_id


def test_c2_login_survives_restart_simulation(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """C2: staff accounts live in the STORE (the DB), not in any
    process-memory registry — a fresh app + fresh session manager
    (a restart) logs the seeded account in with no re-seeding.

    The in-memory store stands in for Postgres here: dropping its
    singleton would be dropping the database, not restarting the app.
    The Supabase-backed half is proven by the migration validator
    (G17b staff_roles INSERT/SELECT round-trip) and the live-proof
    bootstrap SQL, which INSERTs the Owner row into the real table.
    """
    client, fake_auth, mfa_service, manager, clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    fresh_manager = SessionManager(
        InMemoryStaffSessionStore(),
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=get_prefix_version,
        clock=clock,
    )
    set_staff_session_manager(fresh_manager)
    fresh_app = create_app()
    fresh_client = TestClient(fresh_app, base_url=f"http://{get_staff_host()}")
    try:
        assert get_staff_account_by_email(ADMIN_EMAIL) is not None
        session = _login_with_mfa(fresh_client, "admin", ADMIN_EMAIL)
        assert uuid.UUID(session)
    finally:
        set_staff_session_manager(manager)


def test_c3_rotated_session_stays_dead_after_restart(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """C3: the prefix version is persisted — after a rotation, a
    simulated restart (fresh process: local counter back at 1, fresh
    app + session manager over the SAME session rows) must NOT
    resurrect the rotated-out session. The old process-local counter
    + `<` comparison let it validate again."""
    _client, fake_auth, mfa_service, manager, clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    session_store = InMemoryStaffSessionStore()
    live_manager = SessionManager(
        session_store,
        absolute_hours=12,
        idle_minutes=60,
        current_prefix_version=get_prefix_version,
        clock=clock,
    )
    set_staff_session_manager(live_manager)
    app = create_app()
    live_client = TestClient(app, base_url=f"http://{get_staff_host()}")
    try:
        token = _login_with_mfa(live_client, "admin", ADMIN_EMAIL)
        assert bump_prefix_version() == 2
        assert get_prefix_version() == 2
        assert (
            live_client.post("/staff/auth/logout", headers=_auth_headers(token)).status_code == 401
        )
        # --- simulated restart: local counter resets, store does not.
        import app.core.staff_prefix as staff_prefix_module

        staff_prefix_module._prefix_version = 1
        fresh_manager = SessionManager(
            session_store,
            absolute_hours=12,
            idle_minutes=60,
            current_prefix_version=get_prefix_version,
            clock=clock,
        )
        set_staff_session_manager(fresh_manager)
        fresh_app = create_app()
        fresh_client = TestClient(fresh_app, base_url=f"http://{get_staff_host()}")
        assert get_prefix_version() == 2  # persisted version survived
        assert (
            fresh_client.post("/staff/auth/logout", headers=_auth_headers(token)).status_code == 401
        )
        # ... and a fresh login works on the new version.
        assert uuid.UUID(_login_with_mfa(fresh_client, "admin", ADMIN_EMAIL))
    finally:
        set_staff_session_manager(manager)


def test_m2_mfa_verify_per_account_bucket_bites(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """M2: MFA verify is per-account rate-limited (5 / 15 min) — the
    6th attempt is 429 even with the CORRECT code."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    aal1 = _aal1_token(client, "admin", ADMIN_EMAIL)
    for _ in range(5):
        resp = client.post(
            "/staff/auth/mfa/verify",
            json={"code": WRONG_CODE},
            headers=_auth_headers(aal1),
        )
        assert resp.status_code == 401
    limited = client.post(
        "/staff/auth/mfa/verify",
        json={"code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert limited.status_code == 429
    assert limited.json()["code"] == "RATE_LIMITED"
    assert limited.headers.get("Retry-After")


def test_m2_mfa_enroll_per_account_bucket_bites(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """M2: MFA enroll is per-account rate-limited — the 6th enroll
    (each of which would rotate the pending factor) is 429."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_staff(fake_auth, mfa_service, SUPPORT_EMAIL, "support", mfa=False)
    aal1 = _aal1_token(client, "support", SUPPORT_EMAIL)
    for _ in range(5):
        resp = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1))
        assert resp.status_code == 200, resp.text
    limited = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1))
    assert limited.status_code == 429
    assert limited.json()["code"] == "RATE_LIMITED"


def test_mfa_enroll_per_ip_bucket_bites() -> None:
    """F5 fix (red-team): ``/mfa/enroll`` enforces the per-IP bucket
    like its siblings — it used to skip ``_enforce_staff_rate_limit``,
    so only the per-account bucket braked it. Two unenrolled accounts
    isolate the IP bucket: 5 enrolls as A fill the shared IP bucket
    (and A's own per-account bucket); B's FIRST enroll then 429s —
    only the shared IP bucket can deny a first attempt for a fresh
    account. The AAL1 tokens are minted directly from the provider
    (no HTTP login), so the IP bucket is spent ONLY by enroll calls."""
    fake_auth = FakeAuthProvider()
    fake_mfa = FakeMfaBackend()
    mfa_service = MfaService(backend=fake_mfa)
    set_auth_provider(fake_auth)
    set_mfa_service(mfa_service)
    set_rate_limiter(RateLimiter())
    app = create_app()
    client = TestClient(app, base_url=f"http://{get_staff_host()}")
    try:
        _seed_staff(fake_auth, mfa_service, SUPPORT_EMAIL, "support", mfa=False)
        _seed_staff(fake_auth, mfa_service, "second@websurfacehq.com", "support", mfa=False)
        aal1_a = fake_auth.sign_in(SUPPORT_EMAIL, PASSWORD).access_token
        aal1_b = fake_auth.sign_in("second@websurfacehq.com", PASSWORD).access_token
        for _ in range(5):
            resp = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1_a))
            assert resp.status_code == 200, resp.text
        limited = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1_b))
        assert limited.status_code == 429
        assert limited.json()["code"] == "RATE_LIMITED"
        assert limited.headers.get("Retry-After")
    finally:
        set_auth_provider(None)
        set_mfa_service(None)
        set_rate_limiter(None)


def test_m2_mfa_confirm_per_account_bucket_bites(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """M2: MFA confirm is per-account rate-limited — the 6th confirm
    is 429 even with the CORRECT code."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_staff(fake_auth, mfa_service, SUPPORT_EMAIL, "support", mfa=False)
    aal1 = _aal1_token(client, "support", SUPPORT_EMAIL)
    enroll = client.post("/staff/auth/mfa/enroll", headers=_auth_headers(aal1))
    assert enroll.status_code == 200, enroll.text
    factor_id = enroll.json()["factor_id"]
    for _ in range(5):
        resp = client.post(
            "/staff/auth/mfa/confirm",
            json={"factor_id": factor_id, "code": WRONG_CODE},
            headers=_auth_headers(aal1),
        )
        assert resp.status_code == 401
    limited = client.post(
        "/staff/auth/mfa/confirm",
        json={"factor_id": factor_id, "code": CORRECT_CODE},
        headers=_auth_headers(aal1),
    )
    assert limited.status_code == 429
    assert limited.json()["code"] == "RATE_LIMITED"


def test_m2_step_up_per_account_bucket_bites(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """M2: step-up verify is per-account rate-limited — the 6th
    attempt is 429 even with the correct password + correct code."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    _seed_owner_admin(fake_auth, mfa_service)
    token = _login_with_mfa(client, "owner", OWNER_EMAIL)
    for _ in range(5):
        resp = client.post(
            "/staff/auth/step-up/verify",
            json={"password": PASSWORD, "code": WRONG_CODE},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 401, resp.text
    limited = client.post(
        "/staff/auth/step-up/verify",
        json={"password": PASSWORD, "code": CORRECT_CODE},
        headers=_auth_headers(token),
    )
    assert limited.status_code == 429
    assert limited.json()["code"] == "RATE_LIMITED"


def test_m2_invite_accept_per_token_bucket_bites(
    staff_client: tuple[TestClient, FakeAuthProvider, MfaService, SessionManager, FakeClock],
) -> None:
    """M2: invite-accept is per-invite-token rate-limited — after 5
    attempts against one token (the first consumes it, the rest 404),
    the 6th is 429."""
    client, fake_auth, mfa_service, _manager, _clock = staff_client
    owner, _admin, _factor = _seed_owner_admin(fake_auth, mfa_service)
    _invite, token = create_staff_invite(owner, "newhire@websurfacehq.com", "support")
    first = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
    assert first.status_code == 201, first.text
    for _ in range(4):
        resp = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
        assert resp.status_code == 404, resp.text
    limited = client.post("/staff/auth/invite/accept", json={"token": token, "password": PASSWORD})
    assert limited.status_code == 429
    assert limited.json()["code"] == "RATE_LIMITED"


def test_invite_accept_ip_rate_limit_is_429_not_404() -> None:
    """N-NEW5: invite-accept under the per-IP bucket answers 429
    RATE_LIMITED (not the generic invalid-link 404), so the client
    can show "Too many attempts — try again shortly". Distinct
    invalid tokens per attempt (the per-token bucket never bites)
    isolate the IP bucket: 5x 404, then the 6th is 429."""
    fake_auth = FakeAuthProvider()
    set_auth_provider(fake_auth)
    set_rate_limiter(RateLimiter())
    app = create_app()
    client = TestClient(app, base_url=f"http://{get_staff_host()}")
    try:
        for i in range(5):
            resp = client.post(
                "/staff/auth/invite/accept",
                json={"token": f"nonsense-token-{i}", "password": PASSWORD},
            )
            assert resp.status_code == 404, resp.text
            assert resp.json()["code"] == "NOT_FOUND"
        limited = client.post(
            "/staff/auth/invite/accept",
            json={"token": "nonsense-token-5", "password": PASSWORD},
        )
        assert limited.status_code == 429
        assert limited.json()["code"] == "RATE_LIMITED"
        assert limited.headers.get("Retry-After")
    finally:
        set_auth_provider(None)
        set_rate_limiter(None)


def test_invite_accept_token_bucket_only_for_well_formed_tokens() -> None:
    """N-NEW5: the per-token bucket applies ONLY to well-formed
    tokens — a garbage string never earns a 429 from that bucket,
    so the 429 fires only after the token was already validated
    as well-formed. (The per-IP bucket is disabled here with a
    huge limiter so only the token bucket can bite.) A well-formed
    but never-issued token still hits the bucket on the 6th
    attempt, while a malformed token answers 404 every time."""
    fake_auth = FakeAuthProvider()
    set_auth_provider(fake_auth)
    set_rate_limiter(RateLimiter(max_attempts=10_000, window_seconds=900))
    app = create_app()
    client = TestClient(app, base_url=f"http://{get_staff_host()}")
    try:
        for _ in range(6):
            resp = client.post(
                "/staff/auth/invite/accept",
                json={"token": "nonsense-token", "password": PASSWORD},
            )
            assert resp.status_code == 404, resp.text
            assert resp.json()["code"] == "NOT_FOUND"
        well_formed_never_issued = "A" * 43  # right shape, never issued
        for _ in range(5):
            resp = client.post(
                "/staff/auth/invite/accept",
                json={"token": well_formed_never_issued, "password": PASSWORD},
            )
            assert resp.status_code == 404, resp.text
        limited = client.post(
            "/staff/auth/invite/accept",
            json={"token": well_formed_never_issued, "password": PASSWORD},
        )
        assert limited.status_code == 429
        assert limited.json()["code"] == "RATE_LIMITED"
    finally:
        set_auth_provider(None)
        set_rate_limiter(None)
