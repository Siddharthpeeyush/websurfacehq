"""Admin API matrix (Child D, admin-foundation build, plan §3).

401/403/404 matrix per endpoint (unauthenticated -> 401, wrong role ->
403, other tenant / unknown staff id -> 404, Support on /founder ->
403, customer-role account on /admin/* -> 403), plus happy paths
against the real landed services (staff registry, invites, audit,
sessions, prefix version) and the honest 503s where Child A's store
backing has not landed yet.

Wiring: tests issue REAL staff sessions through the SessionManager
fixture (Child B) — the bearer is the session UUID; no JWT is
accepted on /admin/* since the session switch (20 Nov 2026), so
there is no ``get_current_user`` override here at all. The real
``get_current_staff`` runs against Child C's staff registry, seeded
via ``create_staff_account``. The store is installed as the ``app.db``
singleton (``FakeAdminStore`` below) so the routes AND Child A's
audit service (which writes via ``get_store()``) share one store.
The singleton is reset per test; the staff/invite/prefix registries
are reset per test too.
"""

from __future__ import annotations

import hashlib
from collections.abc import Generator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import fakeredis
import pytest
from fastapi.testclient import TestClient

import app.db as db_module
from app.auth.sessions import InMemoryStaffSessionStore, SessionManager, StaffSession
from app.core.config import settings
from app.core.errors import ApiError
from app.core.staff_prefix import get_prefix_version, get_staff_host, reset_prefix_version_for_tests
from app.db import reset_store_for_tests
from app.db.memory import InMemoryStore, _paginate
from app.db.store import AuditLog
from app.main import create_app
from app.services.invites import claim_invite, get_invite, reset_invites_for_tests
from app.services.staff import (
    create_staff_account,
    reset_staff_state_for_tests,
    set_staff_session_manager,
)

# ---------------------------------------------------------------------------
# Fake store: InMemoryStore + the admin list methods Child A has not
# implemented yet (the list_all_*/list_abuse_reports/count_all_scans
# methods are the contract this router relies on). Production
# implementations land with Child A; the router is tested against the
# protocol here. list_audit_logs / get_staff_role use the REAL
# InMemoryStore implementations (added with the protocol methods).
# ---------------------------------------------------------------------------


@dataclass
class AbuseRow:
    id: UUID
    user_id: UUID | None
    subject: str
    status: str = "open"
    created_at: datetime | None = None


@dataclass
class TicketRow:
    id: UUID
    user_id: UUID
    subject: str
    status: str = "open"
    priority: str = "medium"
    scan_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FakeAdminStore(InMemoryStore):
    """InMemoryStore plus the admin list methods (protocol contract)."""

    def __init__(self) -> None:
        super().__init__()
        self._abuse: list[AbuseRow] = []
        self._tickets: list[TicketRow] = []

    def list_all_scans(self, cursor: str | None, limit: int) -> tuple[list[Any], str | None]:
        rows = [s for s in self._scans.values() if s.deleted_at is None]
        return _paginate(rows, cursor, limit)

    def list_all_subscriptions(
        self, cursor: str | None, limit: int
    ) -> tuple[list[Any], str | None]:
        return _paginate(list(self._subscriptions.values()), cursor, limit)

    def list_all_support_tickets(
        self, cursor: str | None, limit: int
    ) -> tuple[list[Any], str | None]:
        return _paginate(self._tickets, cursor, limit)

    def list_abuse_reports(self, cursor: str | None, limit: int) -> tuple[list[Any], str | None]:
        return _paginate(self._abuse, cursor, limit)

    def count_all_scans(self) -> int:
        return sum(1 for s in self._scans.values() if s.deleted_at is None)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_admin_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    # Null the Supabase keys FIRST: reset_prefix_version_for_tests()
    # resolves the store while resetting the persisted version, and
    # with the real keys active that caches a live SupabaseStore and
    # fires a PostgREST call per test (migration 0007 is not applied
    # live). Same ordering trap as tests.test_staff_auth: this
    # fixture's setup runs before any key-nulling fixture.
    monkeypatch.setattr(settings, "supabase_anon_key", None)
    monkeypatch.setattr(settings, "supabase_service_role_key", None)
    reset_staff_state_for_tests()
    reset_invites_for_tests()
    reset_prefix_version_for_tests()
    reset_store_for_tests()
    yield
    reset_staff_state_for_tests()
    reset_invites_for_tests()
    reset_prefix_version_for_tests()
    reset_store_for_tests()


@pytest.fixture()
def store() -> FakeAdminStore:
    """Install the fake admin store as the app.db singleton."""
    fake = FakeAdminStore()
    db_module._STORE = fake
    return fake


@pytest.fixture()
def plain_store() -> InMemoryStore:
    """A plain InMemoryStore — no admin list methods (503 paths)."""
    plain = InMemoryStore()
    db_module._STORE = plain
    return plain


@pytest.fixture()
def session_manager(monkeypatch: pytest.MonkeyPatch) -> Generator[SessionManager, None, None]:
    """A SessionManager on a fresh in-memory session store, wired into
    the staff service (``get_staff_session`` resolves through it) and
    admin_ops (``/admin/security`` lists through it). The default
    manager would use the live Supabase session store in this env
    (real .env) — slow, and migration 0007 is not applied live, so it
    502s. Tests control the store here. The manager reads the LIVE
    prefix version, exactly like production, so a rotation really
    kills sessions in tests."""
    manager = SessionManager(InMemoryStaffSessionStore(), current_prefix_version=get_prefix_version)
    monkeypatch.setattr("app.routers.admin_ops.get_session_manager", lambda: manager)
    # Child C's staff service revokes via its own manager hook — point
    # it at the same test manager so suspend/revoke really kill the
    # sessions the tests issue.
    set_staff_session_manager(manager)
    yield manager
    set_staff_session_manager(None)


def _seed_staff() -> dict[str, UUID]:
    """Owner + Admin + Support in Child C's registry. Returns ids."""
    owner_id, admin_id, support_id = uuid4(), uuid4(), uuid4()
    create_staff_account(owner_id, "owner@example.com", "owner", None)
    create_staff_account(admin_id, "admin@example.com", "admin", owner_id)
    create_staff_account(support_id, "support@example.com", "support", owner_id)
    return {"owner": owner_id, "admin": admin_id, "support": support_id}


def _client(
    manager: SessionManager | None = None,
    user_id: UUID | None = None,
    *,
    session: StaffSession | None = None,
    token: str | None = None,
) -> TestClient:
    """Build a TestClient with staff-session auth (Bearer session UUID).

    - ``manager`` + ``user_id``: issue a fresh session for the user.
    - ``session``: use an existing session (e.g. a stepped-up one).
    - ``token``: send a verbatim bearer token (bad/unknown -> 401).
    - Nothing: no Authorization header (unauthenticated -> 401).
    """
    app = create_app()
    headers: dict[str, str] = {}
    if session is not None:
        headers = {"Authorization": f"Bearer {session.id}"}
    elif token is not None:
        headers = {"Authorization": f"Bearer {token}"}
    elif manager is not None and user_id is not None:
        issued = manager.issue(user_id)
        headers = {"Authorization": f"Bearer {issued.id}"}
    return TestClient(app, headers=headers, base_url=f"http://{get_staff_host()}")


def _audit_actions(store: FakeAdminStore, action: str) -> list[AuditLog]:
    items, _ = store.list_audit_logs(action=action, limit=100)
    return items


# ---------------------------------------------------------------------------
# 401 / 403 matrix
# ---------------------------------------------------------------------------

ALL_GETS = [
    "/admin/me",
    "/admin/users",
    "/admin/scans",
    "/admin/scans/queue",
    "/admin/billing",
    "/admin/abuse",
    "/admin/support/tickets",
    "/admin/security",
    "/admin/system/audit",
    "/admin/settings",
    "/admin/founder",
]

ALL_POSTS = [
    ("/admin/users/invite", {"email": "x@example.com", "role": "support"}),
    (f"/admin/users/invites/{uuid4()}/revoke", None),
    (f"/admin/users/{uuid4()}/suspend", None),
    (f"/admin/users/{uuid4()}/delete", {"confirm": True}),
    (f"/admin/users/{uuid4()}/role", {"role": "admin"}),
    (f"/admin/users/{uuid4()}/revoke-sessions", None),
    (f"/admin/users/{uuid4()}/force-reset", None),
    (f"/admin/users/{uuid4()}/mfa-re-enroll", None),
    ("/admin/settings", {"staff_step_up_mfa": False}),
    ("/admin/settings/rotate-prefix", {"confirm": True}),
]


def test_matrix_no_token_401(store: FakeAdminStore) -> None:
    client = _client()
    for path in ALL_GETS:
        assert client.get(path).status_code == 401, path
    for path, body in ALL_POSTS:
        assert client.post(path, json=body).status_code == 401, path


def test_matrix_bad_token_401(store: FakeAdminStore, session_manager: SessionManager) -> None:
    """Malformed bearer, unknown session id, and a revoked session
    are all the same generic 401 INVALID_SESSION (no oracle)."""
    ids = _seed_staff()
    resp = _client(token="not-a-uuid").get("/admin/me")
    assert resp.status_code == 401
    assert resp.json()["code"] == "INVALID_SESSION"
    assert _client(token=str(uuid4())).get("/admin/me").status_code == 401
    session = session_manager.issue(ids["owner"])
    session_manager.revoke(session.id)
    resp = _client(session=session).get("/admin/me")
    assert resp.status_code == 401
    assert resp.json()["code"] == "INVALID_SESSION"


def test_customer_role_403_on_all_admin(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    """A valid session for a user with no staff row is 403 on every /admin route."""
    ids = _seed_staff()
    client = _client(session_manager, uuid4())
    assert ids  # seed runs so the 403 is about the caller, not the data
    for path in ALL_GETS:
        resp = client.get(path)
        assert resp.status_code == 403, path
    for path, body in ALL_POSTS:
        resp = client.post(path, json=body)
        assert resp.status_code == 403, path


def test_support_sees_support_and_abuse_only(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    client = _client(session_manager, ids["support"])
    assert client.get("/admin/support/tickets").status_code == 200
    assert client.get("/admin/abuse").status_code == 200
    assert client.get("/admin/me").status_code == 200
    for path in [
        "/admin/users",
        "/admin/scans",
        "/admin/scans/queue",
        "/admin/billing",
        "/admin/security",
        "/admin/system/audit",
        "/admin/settings",
        "/admin/founder",
    ]:
        assert client.get(path).status_code == 403, path


def test_admin_on_founder_403_and_owner_step_up_gate(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    admin_client = _client(session_manager, ids["admin"])
    assert admin_client.get("/admin/founder").status_code == 403
    # Owner without a stepped-up session is also refused (flag ON).
    owner_client = _client(session_manager, ids["owner"])
    resp = owner_client.get("/admin/founder")
    assert resp.status_code == 403
    assert resp.json()["code"] == "STEP_UP_REQUIRED"


# ---------------------------------------------------------------------------
# /admin/me + users
# ---------------------------------------------------------------------------


def test_me_returns_role_and_mfa(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    for key, email in [
        ("owner", "owner@example.com"),
        ("admin", "admin@example.com"),
        ("support", "support@example.com"),
    ]:
        resp = _client(session_manager, ids[key]).get("/admin/me")
        assert resp.status_code == 200
        body = resp.json()
        assert body["role"] == key
        assert body["email"] == email
        assert body["mfa_verified"] is False  # not enrolled yet


def test_users_list_pagination_and_roles(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    owner_client = _client(session_manager, ids["owner"])
    resp = owner_client.get("/admin/users", params={"limit": 2})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 2
    assert body["has_more"] is True
    assert body["next_cursor"]
    resp2 = owner_client.get("/admin/users", params={"limit": 2, "cursor": body["next_cursor"]})
    assert resp2.status_code == 200
    assert len(resp2.json()["data"]) == 1
    assert resp2.json()["has_more"] is False
    seen = {row["id"] for row in body["data"]} | {row["id"] for row in resp2.json()["data"]}
    assert seen == {str(v) for v in ids.values()}
    # Admin may list; Support may not.
    assert _client(session_manager, ids["admin"]).get("/admin/users").status_code == 200
    assert _client(session_manager, ids["support"]).get("/admin/users").status_code == 403
    # Malformed cursor is 422, not 500.
    assert owner_client.get("/admin/users", params={"cursor": "not-a-cursor"}).status_code == 422


def test_users_get_404s(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    resp = client.get(f"/admin/users/{ids['admin']}")
    assert resp.status_code == 200
    assert resp.json()["email"] == "admin@example.com"
    # Unknown id and customer id are both 404 (no existence oracle).
    assert client.get(f"/admin/users/{uuid4()}").status_code == 404
    assert client.get(f"/admin/users/{uuid4()}").status_code == 404
    # Support may not read users at all.
    assert (
        _client(session_manager, ids["support"]).get(f"/admin/users/{ids['admin']}").status_code
        == 403
    )


def test_invite_happy_path_and_single_use(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    resp = client.post("/admin/users/invite", json={"email": "new@example.com", "role": "support"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == "new@example.com"
    assert body["role"] == "support"
    assert len(body["invite_token"]) == 43  # 32 random bytes, urlsafe
    # Only the hash is stored; the raw token claims exactly once.
    stored = get_invite(UUID(body["id"]))
    assert stored is not None
    assert stored.token_hash == hashlib.sha256(body["invite_token"].encode()).hexdigest()
    assert claim_invite(body["invite_token"]) is not None
    assert claim_invite(body["invite_token"]) is None
    # Audit row written via the audit service.
    assert _audit_actions(store, "staff.invite_created")
    # Duplicate email and second Owner are 409; bad role is 422.
    assert (
        client.post(
            "/admin/users/invite", json={"email": "admin@example.com", "role": "support"}
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/admin/users/invite", json={"email": "other@example.com", "role": "owner"}
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/admin/users/invite", json={"email": "other@example.com", "role": "wizard"}
        ).status_code
        == 422
    )
    # Admin and Support may not invite.
    assert (
        _client(session_manager, ids["admin"])
        .post("/admin/users/invite", json={"email": "z@example.com", "role": "support"})
        .status_code
        == 403
    )


def test_invite_revoke_kills_pending_invite(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    """F3 fix (red-team): the Owner can revoke a pending invite, and
    the revoked token 404s at accept time. Revoking a consumed /
    expired invite — or an unknown id — answers 404 (already
    unusable, nothing to distinguish); non-Owners get 403."""
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    resp = client.post("/admin/users/invite", json={"email": "new@example.com", "role": "support"})
    assert resp.status_code == 201, resp.text
    invite_id = resp.json()["id"]
    token = resp.json()["invite_token"]
    revoked = client.post(f"/admin/users/invites/{invite_id}/revoke")
    assert revoked.status_code == 200, revoked.text
    assert revoked.json() == {"id": invite_id, "status": "revoked", "detail": None}
    assert _audit_actions(store, "staff.invite_revoked")
    # The revoked token is dead at accept time (claim -> None -> 404).
    assert claim_invite(token) is None
    # Revoking again is 404 (already consumed-by-revocation); an
    # unknown id is 404; Admin may not revoke.
    assert client.post(f"/admin/users/invites/{invite_id}/revoke").status_code == 404
    assert client.post(f"/admin/users/invites/{uuid4()}/revoke").status_code == 404
    assert (
        _client(session_manager, ids["admin"])
        .post(f"/admin/users/invites/{invite_id}/revoke")
        .status_code
        == 403
    )


def test_suspend_revokes_sessions_and_protects_owner(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    session_manager.issue(ids["admin"], ip=None, user_agent=None)
    assert session_manager.list_active_sessions(ids["admin"])
    client = _client(session_manager, ids["owner"])
    resp = client.post(f"/admin/users/{ids['admin']}/suspend")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "suspended"
    assert session_manager.list_active_sessions(ids["admin"]) == []
    assert _audit_actions(store, "staff.suspended")
    # A suspended account is refused at the staff door (403).
    assert _client(session_manager, ids["admin"]).get("/admin/me").status_code == 403
    # Owner cannot be suspended; unknown id is 404; Admin cannot suspend.
    # Self-suspension is refused explicitly by the router guard.
    resp = client.post(f"/admin/users/{ids['owner']}/suspend")
    assert resp.status_code == 409
    assert resp.json()["code"] == "SELF_ACTION_NOT_ALLOWED"
    assert client.post(f"/admin/users/{uuid4()}/suspend").status_code == 404
    assert (
        _client(session_manager, ids["support"])
        .post(f"/admin/users/{ids['support']}/suspend")
        .status_code
        == 403
    )


def test_delete_requires_confirm_and_keeps_audit(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    # No confirm -> 422 (two-step confirm, server-enforced).
    assert client.post(f"/admin/users/{ids['support']}/delete", json={}).status_code == 422
    assert (
        client.post(f"/admin/users/{ids['support']}/delete", json={"confirm": False}).status_code
        == 422
    )
    resp = client.post(f"/admin/users/{ids['support']}/delete", json={"confirm": True})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "deleted"
    assert client.get(f"/admin/users/{ids['support']}").status_code == 404
    assert _audit_actions(store, "staff.deleted")
    # Owner cannot be deleted; unknown id is 404; Admin cannot delete.
    # Self-deletion is refused explicitly by the router guard.
    resp = client.post(f"/admin/users/{ids['owner']}/delete", json={"confirm": True})
    assert resp.status_code == 409
    assert resp.json()["code"] == "SELF_ACTION_NOT_ALLOWED"
    assert client.post(f"/admin/users/{uuid4()}/delete", json={"confirm": True}).status_code == 404
    assert (
        _client(session_manager, ids["admin"])
        .post(f"/admin/users/{ids['support']}/delete", json={"confirm": True})
        .status_code
        == 403
    )


def test_role_change(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    resp = client.post(f"/admin/users/{ids['support']}/role", json={"role": "admin"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == "admin"
    assert _audit_actions(store, "staff.role_changed")
    # Owner cannot be re-roled; re-roling to owner is a second Owner (409).
    # Self-demotion is refused explicitly by the router guard.
    resp = client.post(f"/admin/users/{ids['owner']}/role", json={"role": "admin"})
    assert resp.status_code == 409
    assert resp.json()["code"] == "SELF_ACTION_NOT_ALLOWED"
    assert (
        client.post(f"/admin/users/{ids['support']}/role", json={"role": "owner"}).status_code
        == 409
    )
    assert client.post(f"/admin/users/{uuid4()}/role", json={"role": "admin"}).status_code == 404
    assert (
        client.post(f"/admin/users/{ids['support']}/role", json={"role": "wizard"}).status_code
        == 422
    )
    assert (
        _client(session_manager, ids["admin"])
        .post(f"/admin/users/{ids['support']}/role", json={"role": "support"})
        .status_code
        == 403
    )


def test_revoke_sessions(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    session_manager.issue(ids["support"], ip=None, user_agent=None)
    session_manager.issue(ids["support"], ip=None, user_agent=None)
    client = _client(session_manager, ids["owner"])
    resp = client.post(f"/admin/users/{ids['support']}/revoke-sessions")
    assert resp.status_code == 200, resp.text
    assert resp.json()["sessions_revoked"] == 2
    assert _audit_actions(store, "staff.sessions_revoked")
    assert client.post(f"/admin/users/{uuid4()}/revoke-sessions").status_code == 404
    assert (
        _client(session_manager, ids["admin"])
        .post(f"/admin/users/{ids['support']}/revoke-sessions")
        .status_code
        == 403
    )


def test_force_reset_requests_reset_and_audits(
    store: FakeAdminStore,
    monkeypatch: pytest.MonkeyPatch,
    session_manager: SessionManager,
) -> None:
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    # The provider swallows the unknown email by design (no
    # enumeration, no real email sent — support@example.com is not a
    # project user) and the endpoint 200s. A stub provider stands in
    # for the real GoTrue call: this module runs with Supabase keys
    # nulled (in-memory store), so the real provider would 503.
    requested: list[str] = []
    disabled: list[UUID] = []

    class _SwallowingProvider:
        def disable_password(self, user_id: UUID) -> None:
            disabled.append(user_id)

        def reset_password(self, email: str) -> None:
            requested.append(email)

    monkeypatch.setattr("app.auth.provider.get_auth_provider", lambda: _SwallowingProvider())
    resp = client.post(f"/admin/users/{ids['support']}/force-reset")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "password_reset_requested"
    assert requested == ["support@example.com"]
    assert disabled == [ids["support"]]
    assert _audit_actions(store, "staff.force_reset")
    assert client.post(f"/admin/users/{uuid4()}/force-reset").status_code == 404
    assert (
        _client(session_manager, ids["admin"])
        .post(f"/admin/users/{ids['support']}/force-reset")
        .status_code
        == 403
    )


def test_force_reset_provider_failure_propagates(
    store: FakeAdminStore,
    monkeypatch: pytest.MonkeyPatch,
    session_manager: SessionManager,
) -> None:
    """A dead/unconfigured provider must surface as 503 — the Owner
    must see that the reset email did NOT go out."""
    ids = _seed_staff()

    class _FailingProvider:
        def disable_password(self, user_id: UUID) -> None:
            # The disable succeeds; the RESET EMAIL is the failing
            # step — this test proves that failure propagates as 503.
            return None

        def reset_password(self, email: str) -> None:
            raise ApiError(503, "SUPABASE_NOT_CONFIGURED", "Supabase is not configured")

    monkeypatch.setattr("app.auth.provider.get_auth_provider", lambda: _FailingProvider())
    resp = _client(session_manager, ids["owner"]).post(f"/admin/users/{ids['support']}/force-reset")
    assert resp.status_code == 503
    assert resp.json()["code"] == "SUPABASE_NOT_CONFIGURED"


def test_mfa_re_enroll(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    from app.services.staff import get_staff_account

    account = get_staff_account(ids["support"])
    assert account is not None
    account.mfa_enrolled = True
    client = _client(session_manager, ids["owner"])
    resp = client.post(f"/admin/users/{ids['support']}/mfa-re-enroll")
    assert resp.status_code == 200, resp.text
    assert resp.json()["mfa_verified"] is False
    assert _audit_actions(store, "staff.mfa_re_enroll")
    assert client.post(f"/admin/users/{uuid4()}/mfa-re-enroll").status_code == 404
    assert (
        _client(session_manager, ids["admin"])
        .post(f"/admin/users/{ids['support']}/mfa-re-enroll")
        .status_code
        == 403
    )


# ---------------------------------------------------------------------------
# Scans + queue
# ---------------------------------------------------------------------------


def test_scans_list_all_tenants(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    target_a = store.create_target(ids["owner"], "a.example.com", "hash-a")
    target_b = store.create_target(ids["admin"], "b.example.com", "hash-b")
    store.create_scan(ids["owner"], target_a.id, {"depth": "standard", "max_urls": 500})
    store.create_scan(ids["admin"], target_b.id, {"depth": "quick", "max_urls": 100})
    client = _client(session_manager, ids["owner"])
    resp = client.get("/admin/scans")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["data"]) == 2  # admin sees ALL tenants' scans
    assert {row["user_id"] for row in body["data"]} == {str(ids["owner"]), str(ids["admin"])}
    assert _client(session_manager, ids["admin"]).get("/admin/scans").status_code == 200
    assert _client(session_manager, ids["support"]).get("/admin/scans").status_code == 403


def test_scans_list_503_without_store_support(
    plain_store: InMemoryStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    resp = _client(session_manager, ids["owner"]).get("/admin/scans")
    assert resp.status_code == 503
    assert resp.json()["code"] == "STAFF_DATA_UNAVAILABLE"


def test_queue_real_depths_from_redis(
    store: FakeAdminStore,
    monkeypatch: pytest.MonkeyPatch,
    session_manager: SessionManager,
) -> None:
    ids = _seed_staff()
    redis = fakeredis.FakeRedis(decode_responses=True)
    redis.rpush("recon", "t1", "t2", "t3")
    redis.rpush("vuln", "t4")
    redis.rpush("dlq:scan:aaa", '{"stage": "dns_enum"}', '{"stage": "port_scan"}')
    monkeypatch.setattr("app.routers.admin_ops.get_redis_client", lambda: redis)
    client = _client(session_manager, ids["owner"])
    resp = client.get("/admin/scans/queue")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["broker_reachable"] is True
    depths = {q["name"]: q["depth"] for q in body["queues"]}
    assert depths == {"recon": 3, "crawl": 0, "vuln": 1}
    assert body["dlq"] == {"scan_keys": 1, "entries": 2, "status": "ok"}
    assert _client(session_manager, ids["support"]).get("/admin/scans/queue").status_code == 403


def test_queue_redis_down_reports_unavailable(
    store: FakeAdminStore,
    monkeypatch: pytest.MonkeyPatch,
    session_manager: SessionManager,
) -> None:
    ids = _seed_staff()

    def _down() -> Any:
        raise ConnectionError("redis down")

    monkeypatch.setattr("app.routers.admin_ops.get_redis_client", _down)
    resp = _client(session_manager, ids["owner"]).get("/admin/scans/queue")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["broker_reachable"] is False
    assert all(q["depth"] is None and q["status"] == "unavailable" for q in body["queues"])
    assert body["dlq"]["status"] == "unavailable"


# ---------------------------------------------------------------------------
# Billing / abuse / tickets
# ---------------------------------------------------------------------------


def test_billing_summary(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    store.upsert_subscription(ids["owner"], plan="pro", status="active")
    store.upsert_subscription(ids["admin"], plan="free", status="active")
    store.upsert_subscription(ids["support"], plan="starter", status="past_due")
    client = _client(session_manager, ids["owner"])
    resp = client.get("/admin/billing")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_subscriptions"] == 3
    assert body["active_subscriptions"] == 2
    assert body["by_plan"] == {"pro": 1, "free": 1, "starter": 1}
    assert body["by_status"] == {"active": 2, "past_due": 1}
    assert _client(session_manager, ids["admin"]).get("/admin/billing").status_code == 200
    assert _client(session_manager, ids["support"]).get("/admin/billing").status_code == 403


def test_billing_503_without_store_support(
    plain_store: InMemoryStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    resp = _client(session_manager, ids["owner"]).get("/admin/billing")
    assert resp.status_code == 503
    assert resp.json()["code"] == "STAFF_DATA_UNAVAILABLE"


def test_abuse_and_tickets(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    now = datetime.now(timezone.utc)
    store._abuse.append(
        AbuseRow(id=uuid4(), user_id=ids["admin"], subject="spam scan", created_at=now)
    )
    store._tickets.append(
        TicketRow(
            id=uuid4(),
            user_id=ids["admin"],
            subject="false positive",
            status="open",
            priority="high",
            created_at=now,
            updated_at=now,
        )
    )
    owner_client = _client(session_manager, ids["owner"])
    resp = owner_client.get("/admin/abuse")
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["data"]) == 1
    assert resp.json()["data"][0]["subject"] == "spam scan"
    resp = owner_client.get("/admin/support/tickets")
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"][0]["subject"] == "false positive"
    assert resp.json()["data"][0]["priority"] == "high"
    # Support sees both screens.
    support_client = _client(session_manager, ids["support"])
    assert support_client.get("/admin/abuse").status_code == 200
    assert support_client.get("/admin/support/tickets").status_code == 200


def test_abuse_and_tickets_503_without_store_support(
    plain_store: InMemoryStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    assert client.get("/admin/abuse").status_code == 503
    assert client.get("/admin/support/tickets").status_code == 503


# ---------------------------------------------------------------------------
# Security / audit / settings / founder
# ---------------------------------------------------------------------------


def test_security_login_events_and_sessions(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    store.log_audit(ids["admin"], "auth.login", None, {})
    store.log_audit(ids["admin"], "auth.logout", None, {})
    store.log_audit(ids["owner"], "target.create", "example.com", {})
    manager = session_manager
    manager.issue(ids["admin"], ip="1.2.3.4", user_agent="test")
    client = _client(session_manager, ids["owner"])
    resp = client.get("/admin/security")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Only auth.* audit rows are login events.
    assert {e["action"] for e in body["login_events"]} == {"auth.login", "auth.logout"}
    # The admin's issued session AND the Owner's own calling session
    # are both live (security lists sessions across every account).
    assert len(body["active_sessions"]) == 2
    assert {s["user_id"] for s in body["active_sessions"]} == {
        str(ids["admin"]),
        str(ids["owner"]),
    }
    admin_session = next(s for s in body["active_sessions"] if s["user_id"] == str(ids["admin"]))
    assert admin_session["ip"] == "1.2.3.4"
    assert body["sessions_available"] is True
    assert body["api_keys"] == [] and body["api_keys_available"] is False
    assert _client(session_manager, ids["support"]).get("/admin/security").status_code == 403


def test_security_empty_without_audit_rows(
    plain_store: InMemoryStore, session_manager: SessionManager
) -> None:
    """A plain store now implements list_audit_logs, so security reads
    work with zero rows instead of 503."""
    ids = _seed_staff()
    resp = _client(session_manager, ids["owner"]).get("/admin/security")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["login_events"] == []
    # The caller's own session is live, so the list holds exactly it.
    assert len(body["active_sessions"]) == 1
    assert body["active_sessions"][0]["user_id"] == str(ids["owner"])


def test_audit_list_filters(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    store.log_audit(ids["admin"], "admin.users.suspend", None, {})
    store.log_audit(ids["owner"], "admin.users.invite", None, {})
    store.log_audit(ids["admin"], "target.create", "example.com", {})
    client = _client(session_manager, ids["owner"])
    resp = client.get("/admin/system/audit")
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["data"]) == 3
    resp = client.get("/admin/system/audit", params={"actor": str(ids["admin"])})
    assert {row["action"] for row in resp.json()["data"]} == {
        "admin.users.suspend",
        "target.create",
    }
    resp = client.get("/admin/system/audit", params={"action": "admin.users.invite"})
    assert len(resp.json()["data"]) == 1
    resp = client.get("/admin/system/audit", params={"search": "suspend"})
    assert len(resp.json()["data"]) == 1
    now = datetime.now(timezone.utc)
    resp = client.get(
        "/admin/system/audit",
        params={"since": (now - timedelta(hours=1)).isoformat()},
    )
    assert len(resp.json()["data"]) == 3
    resp = client.get(
        "/admin/system/audit",
        params={"until": (now - timedelta(hours=1)).isoformat()},
    )
    assert len(resp.json()["data"]) == 0
    assert _client(session_manager, ids["support"]).get("/admin/system/audit").status_code == 403


def test_audit_list_empty_with_plain_store(
    plain_store: InMemoryStore, session_manager: SessionManager
) -> None:
    """A plain store now implements list_audit_logs, so the audit
    viewer reads work with zero rows instead of 503."""
    ids = _seed_staff()
    resp = _client(session_manager, ids["owner"]).get("/admin/system/audit")
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"] == []


def test_settings_get_and_post(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    resp = client.get("/admin/settings")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["flags"]["staff_step_up_mfa"] is True
    assert body["quotas"]["max_scans_free_per_month"] == 3
    assert body["quotas"]["max_targets_free"] == 1
    assert body["quotas"]["staff_session_absolute_hours"] == 12
    assert body["quotas"]["staff_session_idle_minutes"] == 60
    assert body["staff_prefix_version"] == 1
    assert body["staff_prefix_version_available"] is True
    # POST has no persistence layer: Owner gets an honest 503, and
    # Admin/Support get 403 (authz runs before the 503).
    resp = client.post("/admin/settings", json={"staff_step_up_mfa": False})
    assert resp.status_code == 503
    assert resp.json()["code"] == "SETTINGS_STORE_UNAVAILABLE"
    assert (
        _client(session_manager, ids["admin"])
        .post("/admin/settings", json={"staff_step_up_mfa": False})
        .status_code
        == 403
    )
    assert _client(session_manager, ids["support"]).get("/admin/settings").status_code == 403


def test_rotate_prefix_bumps_version_and_audits(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    # A session issued before rotation must die with it (the manager
    # reads the live prefix version, exactly like production).
    victim = session_manager.issue(ids["admin"])
    victim_client = _client(session=victim)
    assert victim_client.get("/admin/me").status_code == 200
    client = _client(session_manager, ids["owner"])
    assert client.post("/admin/settings/rotate-prefix", json={}).status_code == 422
    resp = client.post("/admin/settings/rotate-prefix", json={"confirm": True})
    assert resp.status_code == 200, resp.text
    assert resp.json()["prefix_version"] == 2
    assert resp.json()["staff_sessions_invalidated"] is True
    # Rotation kills every pre-rotation session — the victim's and
    # the Owner's own — so both callers re-authenticate after it.
    assert victim_client.get("/admin/me").status_code == 401
    assert client.get("/admin/me").status_code == 401
    client = _client(session_manager, ids["owner"])
    assert client.get("/admin/settings").json()["staff_prefix_version"] == 2
    resp = client.post("/admin/settings/rotate-prefix", json={"confirm": True})
    assert resp.json()["prefix_version"] == 3
    assert _audit_actions(store, "admin.settings.rotate_prefix")
    # The second rotation killed this client too — re-authenticate.
    client = _client(session_manager, ids["owner"])
    assert client.get("/admin/settings").json()["staff_prefix_version"] == 3
    assert (
        _client(session_manager, ids["admin"])
        .post("/admin/settings/rotate-prefix", json={"confirm": True})
        .status_code
        == 403
    )


def test_founder_step_up_flow(store: FakeAdminStore, session_manager: SessionManager) -> None:
    ids = _seed_staff()
    store.upsert_subscription(ids["owner"], plan="pro", status="active")
    store.upsert_subscription(ids["admin"], plan="free", status="active")
    manager = session_manager
    # The Founder gate reads THIS session's step-up state: a fresh
    # session is refused, the same session after a fresh MFA check
    # (step-up mark) opens the screen.
    session = manager.issue(ids["owner"], ip=None, user_agent=None)
    owner_client = _client(session=session)
    # No stepped-up session yet -> 403 STEP_UP_REQUIRED.
    assert owner_client.get("/admin/founder").status_code == 403
    # After a fresh MFA check (step-up mark), the Founder screen opens.
    manager.mark_step_up_verified(session.id)
    resp = owner_client.get("/admin/founder")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_subscriptions"] == 2
    assert body["by_plan"] == {"pro": 1, "free": 1}
    assert body["total_staff"] == 3
    assert body["subscriptions_available"] is True
    # Admin and Support never see Founder, even stepped up.
    assert _client(session_manager, ids["admin"]).get("/admin/founder").status_code == 403
    assert _client(session_manager, ids["support"]).get("/admin/founder").status_code == 403


def test_founder_figures_degrade_without_store_support(
    plain_store: InMemoryStore, session_manager: SessionManager
) -> None:
    ids = _seed_staff()
    manager = session_manager
    session = manager.issue(ids["owner"], ip=None, user_agent=None)
    manager.mark_step_up_verified(session.id)
    resp = _client(session=session).get("/admin/founder")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_staff"] == 3
    assert body["subscriptions_available"] is False
    assert body["total_subscriptions"] is None
    assert body["scans_available"] is False
    assert body["total_scans"] is None


# ---------------------------------------------------------------------------
# Secret-prefix gate on the production mount (main.py)
# ---------------------------------------------------------------------------


def test_staff_prefix_gate_on_production_mount(
    store: FakeAdminStore,
    session_manager: SessionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The staff routers mount UNDER the secret prefix with the guard:
    outside the prefix on the staff host -> generic 404 (the prefix
    itself never leaks); inside the prefix -> the handler runs."""
    ids = _seed_staff()
    monkeypatch.setattr(settings, "staff_url_prefix", "s3cr3t-prefix")
    app = create_app()  # the mount reads the prefix at call time
    session = session_manager.issue(ids["owner"])
    headers = {"Authorization": f"Bearer {session.id}"}
    client = TestClient(app)
    outside = client.get("http://admin.websurfacehq.com/admin/me", headers=headers)
    assert outside.status_code == 404
    assert outside.json()["code"] == "NOT_FOUND"
    assert "s3cr3t-prefix" not in outside.text
    # A prefix lookalike is outside too.
    evil = client.get("http://admin.websurfacehq.com/s3cr3t-prefix-evil/admin/me", headers=headers)
    assert evil.status_code == 404
    assert evil.json()["code"] == "NOT_FOUND"
    # Inside the prefix the same session reaches the handler.
    inside = client.get("http://admin.websurfacehq.com/s3cr3t-prefix/admin/me", headers=headers)
    assert inside.status_code == 200, inside.text
    assert inside.json()["role"] == "owner"


# ---------------------------------------------------------------------------
# Store methods added with the admin API (protocol + both implementations)
# ---------------------------------------------------------------------------


def test_get_staff_role(store: FakeAdminStore) -> None:
    """get_staff_role resolves (role, status) server-side for Child C's
    staff auth; unknown users and non-staff users read as None."""
    ids = _seed_staff()
    assert store.get_staff_role(ids["owner"]) == ("owner", "active")
    assert store.get_staff_role(ids["admin"]) == ("admin", "active")
    assert store.get_staff_role(ids["support"]) == ("support", "active")
    assert store.get_staff_role(uuid4()) is None
    # A suspended account still resolves, with its status — the caller
    # (staff auth / get_current_staff) refuses suspended rows.
    from app.services.staff import get_staff_account, suspend_staff

    owner = get_staff_account(ids["owner"])
    assert owner is not None
    suspend_staff(owner, ids["admin"])
    assert store.get_staff_role(ids["admin"]) == ("admin", "suspended")


def test_list_audit_logs_real_implementation(store: FakeAdminStore) -> None:
    """The real InMemoryStore list_audit_logs (filters + cursor), not
    the fake override — the override was removed once the method
    landed in both implementations."""
    ids = _seed_staff()
    store.log_audit(ids["admin"], "admin.users.suspend", None, {"needle": "haystack"})
    store.log_audit(ids["owner"], "admin.users.invite", None, {})
    store.log_audit(ids["admin"], "target.create", "example.com", {})
    items, next_cursor = store.list_audit_logs(limit=2)
    assert len(items) == 2
    assert next_cursor is not None
    items2, next_cursor2 = store.list_audit_logs(cursor=next_cursor, limit=2)
    assert len(items2) == 1
    assert next_cursor2 is None
    assert {row.action for row in items + items2} == {
        "admin.users.suspend",
        "admin.users.invite",
        "target.create",
    }
    # Filters: actor, action, search (incl. metadata text on this path).
    rows, _ = store.list_audit_logs(actor_id=ids["admin"])
    assert {r.action for r in rows} == {"admin.users.suspend", "target.create"}
    rows, _ = store.list_audit_logs(action="admin.users.invite")
    assert len(rows) == 1
    rows, _ = store.list_audit_logs(search="haystack")
    assert len(rows) == 1 and rows[0].action == "admin.users.suspend"
    rows, _ = store.list_audit_logs(search="example.com")
    assert len(rows) == 1 and rows[0].action == "target.create"
    # Malformed cursor raises ValueError (routers map it to 422).
    with pytest.raises(ValueError):
        store.list_audit_logs(cursor="not-a-cursor")


# --- M1 / M3 / N4 / N7 regression tests (security-review fix round) ---------


def test_m1_audit_before_after_single_row(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    """M1: ONE audit row per action (the service's), with a correct
    before/after — the router's duplicate row (which read `before`
    from the already-mutated object, so before == after) is gone."""
    ids = _seed_staff()
    from app.services.staff import get_staff_account

    client = _client(session_manager, ids["owner"])
    # Suspend: before active, after suspended.
    resp = client.post(f"/admin/users/{ids['admin']}/suspend")
    assert resp.status_code == 200, resp.text
    rows = _audit_actions(store, "staff.suspended")
    assert len(rows) == 1
    assert rows[0].metadata["before"] == {"status": "active"}
    assert rows[0].metadata["after"]["status"] == "suspended"
    assert _audit_actions(store, "admin.users.suspend") == []
    # Role change: before support, after admin.
    resp = client.post(f"/admin/users/{ids['support']}/role", json={"role": "admin"})
    assert resp.status_code == 200, resp.text
    rows = _audit_actions(store, "staff.role_changed")
    assert len(rows) == 1
    assert rows[0].metadata["before"] == {"role": "support"}
    assert rows[0].metadata["after"]["role"] == "admin"
    assert _audit_actions(store, "admin.users.role") == []
    # MFA re-enroll: before enrolled with a factor, after unenrolled.
    account = get_staff_account(ids["support"])
    assert account is not None
    account.mfa_enrolled = True
    account.current_factor_id = "factor-1"
    resp = client.post(f"/admin/users/{ids['support']}/mfa-re-enroll")
    assert resp.status_code == 200, resp.text
    rows = _audit_actions(store, "staff.mfa_re_enroll")
    assert len(rows) == 1
    assert rows[0].metadata["before"] == {"mfa_enrolled": True, "had_factor": True}
    assert rows[0].metadata["after"]["mfa_enrolled"] is False
    assert _audit_actions(store, "admin.users.mfa_re_enroll") == []


def test_m3_customer_host_rejected(store: FakeAdminStore, session_manager: SessionManager) -> None:
    """M3: the staff API is served on the staff host only — a
    customer host presenting the staff path + a VALID staff session
    gets 404, not 200."""
    ids = _seed_staff()
    session = session_manager.issue(ids["owner"])
    headers = {"Authorization": f"Bearer {session.id}"}
    customer_client = TestClient(create_app(), headers=headers, base_url="http://websurfacehq.com")
    resp = customer_client.get("/admin/me")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"
    # The same session on the staff host still works.
    assert _client(session_manager, ids["owner"]).get("/admin/me").status_code == 200


def test_host_gate_allows_api_public_host_with_prefixed_path(
    store: FakeAdminStore,
    session_manager: SessionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Host-gate allowlist (20 Nov 2026): the Host header arriving
    at the API is ALWAYS the API origin — the web middleware proxies
    staff calls with ``Host: <API origin>`` (the staff web host
    arrives only as X-Forwarded-Host, which the API does not trust)
    and direct clients address the API by its own hostname too, so
    the gate must accept the API's own public host alongside the
    staff host. With a prefix set + ``API_PUBLIC_HOST`` set, the
    API-origin host + prefixed path + valid session -> 200; the
    bare path -> 404 (routing); the customer host + prefixed path
    -> 404 (gate). A staff-host-only gate would 404 every real
    production staff call, proxied and direct alike."""
    prefix = "s3cr3t-prefix-12345678"
    api_host = "api.websurfacehq.com"
    monkeypatch.setattr(settings, "staff_url_prefix", prefix)
    monkeypatch.setattr(settings, "api_public_host", api_host)
    ids = _seed_staff()
    session = session_manager.issue(ids["owner"])
    headers = {"Authorization": f"Bearer {session.id}"}
    api_client = TestClient(create_app(), headers=headers, base_url=f"http://{api_host}")
    ok = api_client.get(f"/{prefix}/admin/me")
    assert ok.status_code == 200, ok.text
    assert ok.json()["role"] == "owner"
    # Bare path (no prefix) on the API host -> 404: no route there.
    assert api_client.get("/admin/me").status_code == 404
    # Customer host + prefixed path + valid session -> 404 (gate).
    customer_client = TestClient(create_app(), headers=headers, base_url="http://websurfacehq.com")
    resp = customer_client.get(f"/{prefix}/admin/me")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"
    # The staff host still works (unchanged).
    assert _client(session_manager, ids["owner"]).get(f"/{prefix}/admin/me").status_code == 200


def test_host_gate_allows_host_from_api_public_url(
    store: FakeAdminStore,
    session_manager: SessionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gate also accepts the host parsed from ``API_PUBLIC_URL``
    when set, so either variable alone is enough — an operator who
    already sets the public URL does not also have to set the host."""
    monkeypatch.setattr(settings, "api_public_url", "https://api.websurfacehq.com")
    monkeypatch.setattr(settings, "api_public_host", None)
    ids = _seed_staff()
    session = session_manager.issue(ids["owner"])
    headers = {"Authorization": f"Bearer {session.id}"}
    api_client = TestClient(create_app(), headers=headers, base_url="http://api.websurfacehq.com")
    assert api_client.get("/admin/me").status_code == 200
    # ... and a lookalike host is still rejected (exact match only).
    evil_client = TestClient(
        create_app(), headers=headers, base_url="http://api.websurfacehq.com.evil.example"
    )
    assert evil_client.get("/admin/me").status_code == 404


def test_n4_security_login_events_include_staff_events(
    store: FakeAdminStore, session_manager: SessionManager
) -> None:
    """N4: /admin/security login_events used to filter action.startswith
    ("auth.") only, so staff events (staff.login / staff.mfa_verified)
    never appeared. They do now; unrelated actions still don't."""
    ids = _seed_staff()
    store.log_audit(ids["admin"], "staff.login", None, {})
    store.log_audit(ids["admin"], "staff.mfa_verified", None, {})
    store.log_audit(ids["admin"], "auth.login", None, {})
    store.log_audit(ids["admin"], "target.create", "example.com", {})
    resp = _client(session_manager, ids["owner"]).get("/admin/security")
    assert resp.status_code == 200, resp.text
    actions = {event["action"] for event in resp.json()["login_events"]}
    assert actions == {"staff.login", "staff.mfa_verified", "auth.login"}


def test_n7_invite_invalid_email_is_422(session_manager: SessionManager) -> None:
    """N7: InviteRequest.email is EmailStr — a malformed address is a
    422 at the boundary, not a stored invite."""
    ids = _seed_staff()
    client = _client(session_manager, ids["owner"])
    resp = client.post("/admin/users/invite", json={"email": "not-an-email", "role": "support"})
    assert resp.status_code == 422
