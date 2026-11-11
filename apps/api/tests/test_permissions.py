"""Unit tests for ``can(user, action, resource)`` (docs/permissions.md §3).

Matrix: own resource -> True, other tenant -> False (and audited, with the
resource id hashed — never raw), anonymous -> False, unverified-target
``scan.create`` -> False, nonexistent resource (``None`` for a
resource-level action) -> False. ``can()`` must never raise, even when the
resource itself misbehaves.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass

import pytest

from app.auth.jwt import User
from app.auth.permissions import can

OWNER_ID = uuid.uuid4()
OTHER_ID = uuid.uuid4()


@dataclass
class FakeTarget:
    """Stand-in for a ``targets`` row."""

    id: uuid.UUID
    user_id: uuid.UUID
    verification_status: str = "pending"


@dataclass
class FakeScan:
    """Stand-in for a ``scans`` row."""

    id: uuid.UUID
    user_id: uuid.UUID
    status: str = "queued"


@pytest.fixture()
def owner() -> User:
    return User(id=OWNER_ID, email="owner@example.com")


@pytest.fixture()
def other() -> User:
    return User(id=OTHER_ID, email="other@example.com")


def test_own_target_read_is_allowed(owner: User) -> None:
    target = FakeTarget(id=uuid.uuid4(), user_id=OWNER_ID, verification_status="verified")
    assert can(owner, "target.read", target) is True


def test_other_tenants_target_is_denied(owner: User) -> None:
    target = FakeTarget(id=uuid.uuid4(), user_id=OTHER_ID, verification_status="verified")
    assert can(owner, "target.read", target) is False


def test_anonymous_is_denied_everything() -> None:
    target = FakeTarget(id=uuid.uuid4(), user_id=OWNER_ID, verification_status="verified")
    assert can(None, "target.read", target) is False
    assert can(None, "target.create", None) is False
    assert can(None, "scan.create", target) is False


def test_collection_create_is_allowed_for_owner(owner: User) -> None:
    assert can(owner, "target.create", None) is True
    assert can(owner, "target.list", None) is True
    assert can(owner, "scan.list", None) is True


def test_resource_action_with_no_resource_is_denied(owner: User) -> None:
    # A nonexistent id loads nothing, so the handler passes None: deny.
    assert can(owner, "target.read", None) is False
    assert can(owner, "scan.read", None) is False
    assert can(owner, "scan.create", None) is False


def test_scan_create_requires_verified_target(owner: User) -> None:
    verified = FakeTarget(id=uuid.uuid4(), user_id=OWNER_ID, verification_status="verified")
    pending = FakeTarget(id=uuid.uuid4(), user_id=OWNER_ID, verification_status="pending")
    assert can(owner, "scan.create", verified) is True
    assert can(owner, "scan.create", pending) is False


def test_scan_create_on_other_tenants_target_is_denied_even_if_unverified(
    owner: User,
) -> None:
    # Tenant check first: the denial must not leak the target's state.
    target = FakeTarget(id=uuid.uuid4(), user_id=OTHER_ID, verification_status="pending")
    assert can(owner, "scan.create", target) is False


def test_finding_list_resource_scoped_on_own_scan_is_allowed(owner: User) -> None:
    # The findings router calls can(user, "finding.list", scan) — the
    # action must be allowed resource-scoped, not only collection-level.
    scan = FakeScan(id=uuid.uuid4(), user_id=OWNER_ID, status="done")
    assert can(owner, "finding.list", scan) is True
    other_scan = FakeScan(id=uuid.uuid4(), user_id=OTHER_ID, status="done")
    assert can(owner, "finding.list", other_scan) is False


def test_scan_cancel_is_allowed_on_own_scan_regardless_of_status(owner: User) -> None:
    # CORRECTED CONTRACT (see permissions.py): cancelling a finished scan
    # is a state conflict (409 SCAN_CONFLICT from the store/handler), not
    # an authorization denial — can() answers the tenancy + role question
    # only, so it allows cancel on any own scan. An earlier version of
    # this test asserted the opposite; that folded a 409 into a 404 and
    # broke the scans router's SCAN_CONFLICT path.
    done = FakeScan(id=uuid.uuid4(), user_id=OWNER_ID, status="done")
    running = FakeScan(id=uuid.uuid4(), user_id=OWNER_ID, status="running")
    assert can(owner, "scan.cancel", done) is True
    assert can(owner, "scan.cancel", running) is True
    other_scan = FakeScan(id=uuid.uuid4(), user_id=OTHER_ID, status="running")
    assert can(owner, "scan.cancel", other_scan) is False


def test_unknown_action_is_denied(owner: User) -> None:
    target = FakeTarget(id=uuid.uuid4(), user_id=OWNER_ID, verification_status="verified")
    assert can(owner, "target.explode", target) is False
    assert can(owner, "target.explode", None) is False


def test_non_owner_role_is_denied() -> None:
    viewer = User(id=OWNER_ID, email="viewer@example.com", role="viewer")
    target = FakeTarget(id=uuid.uuid4(), user_id=OWNER_ID, verification_status="verified")
    assert can(viewer, "target.read", target) is False
    assert can(viewer, "target.create", None) is False


def test_can_never_raises_on_broken_resource(owner: User) -> None:
    class BrokenResource:
        @property
        def user_id(self) -> uuid.UUID:
            raise RuntimeError("boom")

    assert can(owner, "target.read", BrokenResource()) is False  # type: ignore[arg-type]


def test_cross_tenant_denial_is_audited_with_hashed_resource_id(
    owner: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The store interface (Builder C): ``app.db.get_store().log_audit(
    user_id, action, target_domain, metadata)``. The audit must carry the
    resource id as a SHA-256 hash — never the raw id."""
    calls: list[dict[str, object]] = []

    class FakeStore:
        def log_audit(
            self,
            user_id: uuid.UUID,
            action: str,
            target_domain: str | None,
            metadata: dict[str, object],
        ) -> None:
            calls.append(
                {
                    "user_id": user_id,
                    "action": action,
                    "target_domain": target_domain,
                    "metadata": metadata,
                }
            )

    import app.db

    monkeypatch.setattr(app.db, "get_store", lambda: FakeStore())

    resource_id = uuid.uuid4()
    target = FakeTarget(id=resource_id, user_id=OTHER_ID, verification_status="verified")
    assert can(owner, "target.read", target) is False

    assert len(calls) == 1
    call = calls[0]
    assert call["user_id"] == OWNER_ID
    assert call["action"] == "target.read"
    metadata = call["metadata"]
    assert isinstance(metadata, dict)
    expected_hash = hashlib.sha256(str(resource_id).encode("utf-8")).hexdigest()
    assert metadata["resource_id_hash"] == expected_hash
    assert metadata["resource_type"] == "FakeTarget"
    # The raw id must appear nowhere in the audited payload.
    assert str(resource_id) not in str(call)


def test_cross_tenant_denial_still_denies_when_store_is_missing(
    owner: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the store is unavailable, the denial must still happen and
    ``can()`` must not raise."""
    import app.db

    def _unavailable() -> object:
        raise RuntimeError("store unavailable")

    monkeypatch.setattr(app.db, "get_store", _unavailable)
    target = FakeTarget(id=uuid.uuid4(), user_id=OTHER_ID, verification_status="verified")
    assert can(owner, "target.read", target) is False
