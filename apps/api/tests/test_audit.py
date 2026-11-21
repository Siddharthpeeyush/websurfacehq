"""Unit tests for the append-only audit writer (``app.services.audit``).

The writer maps ``write(actor, action, target, before, after, ip)`` onto
the frozen ``audit_logs`` row shape (migration 0001): actor -> user_id,
action -> action, a domain target -> target_domain, everything else
(before/after, IP, hashed UUID targets) -> metadata JSON. The database
trigger + REVOKEs (migration 0007) are proven by the migration
validator, not here — these tests prove the service-layer contract:
exactly one row per call, UUID targets hashed (never raw), no
update/delete surface, loud failure.
"""

from __future__ import annotations

import hashlib
import uuid

import pytest

from app.db.memory import InMemoryStore
from app.db.store import AuditLog
from app.services import audit


@pytest.fixture()
def store(monkeypatch: pytest.MonkeyPatch) -> InMemoryStore:
    """Fresh in-memory store wired in as the app's store."""
    fresh = InMemoryStore()
    import app.db

    monkeypatch.setattr(app.db, "get_store", lambda: fresh)
    return fresh


def _audit_rows(store: InMemoryStore) -> list[AuditLog]:
    """Test-only read path into the in-memory audit table. There is no
    audit-list method on the Store yet: the admin audit viewer needs a
    ``list_audit_logs`` store method, but adding it to the protocol
    without implementations in InMemoryStore/SupabaseStore breaks
    ``mypy .`` (both stores stop conforming), and those files belong
    to no child — so the method is specified in the Child A report for
    the coordinator to assign, not declared here. Until it lands,
    tests read the dict directly."""
    return list(store._audit.values())  # noqa: SLF001 - test-only read path


ACTOR_ID = uuid.uuid4()


def test_write_stores_actor_action_target_and_metadata(store: InMemoryStore) -> None:
    row = audit.write(
        ACTOR_ID,
        "admin.users.suspend",
        "example.com",
        before={"status": "active"},
        after={"status": "suspended"},
        ip="203.0.113.7",
    )
    assert isinstance(row, AuditLog)
    assert row.user_id == ACTOR_ID
    assert row.action == "admin.users.suspend"
    assert row.target_domain == "example.com"
    assert row.metadata["before"] == {"status": "active"}
    assert row.metadata["after"] == {"status": "suspended"}
    assert row.metadata["ip"] == "203.0.113.7"
    assert row.created_at is not None
    # The row is really in the store (not just returned).
    assert _audit_rows(store) == [row]


def test_write_hashes_uuid_target_and_never_stores_it_raw(store: InMemoryStore) -> None:
    target_id = uuid.uuid4()
    row = audit.write(ACTOR_ID, "admin.users.delete", target_id)
    assert row.target_domain is None
    expected = hashlib.sha256(str(target_id).encode("utf-8")).hexdigest()
    assert row.metadata["target_id_hash"] == expected
    # The raw id must appear nowhere in the stored row.
    assert str(target_id) not in str(row)
    assert str(target_id) not in str(row.metadata)


def test_write_hashes_uuid_shaped_string_target(store: InMemoryStore) -> None:
    target_id = uuid.uuid4()
    row = audit.write(ACTOR_ID, "admin.users.role", str(target_id))
    assert row.target_domain is None
    assert (
        row.metadata["target_id_hash"] == hashlib.sha256(str(target_id).encode("utf-8")).hexdigest()
    )
    assert str(target_id) not in str(row)


def test_write_with_no_target_or_snapshots_leaves_metadata_empty(
    store: InMemoryStore,
) -> None:
    row = audit.write(ACTOR_ID, "admin.settings.rotate_prefix")
    assert row.target_domain is None
    assert row.metadata == {}
    assert row.created_at is not None


def test_write_rejects_empty_action(store: InMemoryStore) -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        audit.write(ACTOR_ID, "   ")
    with pytest.raises(ValueError, match="non-empty string"):
        audit.write(ACTOR_ID, "")


def test_write_rejects_non_json_serializable_snapshots(store: InMemoryStore) -> None:
    with pytest.raises(ValueError, match="not JSON-serializable"):
        audit.write(ACTOR_ID, "admin.users.suspend", before={"when": object()})
    with pytest.raises(ValueError, match="not JSON-serializable"):
        audit.write(ACTOR_ID, "admin.users.suspend", after={"when": object()})
    # Nothing was written for the rejected calls.
    assert _audit_rows(store) == []


def test_write_is_append_only_two_writes_leave_two_unchanged_rows(
    store: InMemoryStore,
) -> None:
    first = audit.write(ACTOR_ID, "admin.users.suspend", before={"status": "active"})
    second = audit.write(ACTOR_ID, "admin.users.suspend", before={"status": "active"})
    assert first.id != second.id
    assert len(_audit_rows(store)) == 2
    # The first row is untouched by the second write.
    assert _audit_rows(store)[0].metadata == {"before": {"status": "active"}}
    assert _audit_rows(store)[0].created_at == first.created_at


def test_audit_module_exposes_no_update_or_delete_surface() -> None:
    """Append-only in code as well as in the DB: there is no function
    here that could mutate or erase an audit row."""
    for name in ("update", "delete", "update_audit", "delete_audit", "remove", "purge"):
        assert not hasattr(audit, name), f"audit module must not expose {name}()"
    assert hasattr(audit, "write")


def test_write_failure_is_loud_not_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    """A store failure propagates (the caller treats it as a 500) —
    an unaudited admin action must never fail silently."""

    class BrokenStore:
        def log_audit(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("store down")

    import app.db

    monkeypatch.setattr(app.db, "get_store", lambda: BrokenStore())
    with pytest.raises(RuntimeError, match="store down"):
        audit.write(ACTOR_ID, "admin.users.suspend")
