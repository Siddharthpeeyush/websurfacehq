"""Store protocol tests (InMemoryStore — the tested implementation).

Covers: target CRUD + duplicate + soft delete, scan CRUD + month/active
counts, findings + feedback, subscriptions, audit, scan jobs, cursor
pagination, and the two-tenant isolation proof (tenant B never sees
tenant A's rows).
"""

import hashlib
import uuid

import pytest

from app.db.memory import (
    TENANT_A_USER_ID,
    TENANT_B_USER_ID,
    InMemoryStore,
    seed_two_tenants,
)
from app.db.store import DuplicateTargetError, ScanConflictError


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def test_create_and_get_target() -> None:
    store = InMemoryStore()
    target = store.create_target(TENANT_A_USER_ID, "Example.COM", _hash("tok"))
    assert target.domain == "example.com"  # normalized
    assert target.verification_status == "pending"
    assert target.verification_token_hash == _hash("tok")
    assert store.get_target(TENANT_A_USER_ID, target.id) is not None
    # Cross-tenant get returns None, never the row.
    assert store.get_target(TENANT_B_USER_ID, target.id) is None
    assert store.get_target(TENANT_A_USER_ID, uuid.uuid4()) is None


def test_duplicate_target_same_user_409_shape() -> None:
    store = InMemoryStore()
    store.create_target(TENANT_A_USER_ID, "dup.example.com", _hash("t1"))
    with pytest.raises(DuplicateTargetError):
        store.create_target(TENANT_A_USER_ID, "dup.example.com", _hash("t2"))
    # Same domain for a DIFFERENT tenant is fine (unique is (user, domain)).
    other = store.create_target(TENANT_B_USER_ID, "dup.example.com", _hash("t3"))
    assert other.user_id == TENANT_B_USER_ID


def test_delete_target_soft_deletes_and_hides() -> None:
    store = InMemoryStore()
    target = store.create_target(TENANT_A_USER_ID, "gone.example.com", _hash("t"))
    assert store.delete_target(TENANT_A_USER_ID, target.id) is True
    assert store.get_target(TENANT_A_USER_ID, target.id) is None
    items, _ = store.list_targets(TENANT_A_USER_ID, None, 20)
    assert all(t.id != target.id for t in items)
    # Cross-tenant delete returns False and does not delete.
    target2 = store.create_target(TENANT_A_USER_ID, "kept.example.com", _hash("t"))
    assert store.delete_target(TENANT_B_USER_ID, target2.id) is False
    assert store.get_target(TENANT_A_USER_ID, target2.id) is not None
    # Re-creating a soft-deleted domain is allowed.
    store.create_target(TENANT_A_USER_ID, "gone.example.com", _hash("t2"))


def test_list_targets_cursor_pagination() -> None:
    store = InMemoryStore()
    for i in range(5):
        store.create_target(TENANT_A_USER_ID, f"p{i}.example.com", _hash(f"t{i}"))
    page1, cursor1 = store.list_targets(TENANT_A_USER_ID, None, 2)
    assert len(page1) == 2 and cursor1 is not None
    page2, cursor2 = store.list_targets(TENANT_A_USER_ID, cursor1, 2)
    assert len(page2) == 2 and cursor2 is not None
    page3, cursor3 = store.list_targets(TENANT_A_USER_ID, cursor2, 2)
    assert len(page3) == 1 and cursor3 is None
    seen = {t.id for t in page1 + page2 + page3}
    assert len(seen) == 5  # no repeats, no skips
    # Other tenant sees an empty list.
    items, _ = store.list_targets(TENANT_B_USER_ID, None, 20)
    assert items == []
    with pytest.raises(ValueError):
        store.list_targets(TENANT_A_USER_ID, "not-a-cursor", 20)


def test_update_target_verification() -> None:
    store = InMemoryStore()
    target = store.create_target(TENANT_A_USER_ID, "v.example.com", _hash("t"))
    updated = store.update_target_verification(
        TENANT_A_USER_ID, target.id, status="verified", method="dns"
    )
    assert updated is not None and updated.verification_status == "verified"
    assert updated.verification_method == "dns"
    assert store.update_target_verification(TENANT_B_USER_ID, target.id, status="verified") is None


def test_scan_lifecycle_and_counts() -> None:
    store = InMemoryStore()
    target = store.create_target(TENANT_A_USER_ID, "s.example.com", _hash("t"))
    scan = store.create_scan(TENANT_A_USER_ID, target.id, {"depth": "quick", "max_urls": 100})
    assert scan.status == "queued" and scan.progress == 0
    assert store.count_scans_this_month(TENANT_A_USER_ID) == 1
    assert store.count_active_scans(TENANT_A_USER_ID) == 1
    assert store.count_scans_this_month(TENANT_B_USER_ID) == 0
    assert store.get_scan(TENANT_B_USER_ID, scan.id) is None
    updated = store.update_scan(TENANT_A_USER_ID, scan.id, status="done", progress=100)
    assert updated is not None and updated.status == "done"
    assert store.count_active_scans(TENANT_A_USER_ID) == 0
    # Cancelling a done scan raises the conflict error.
    with pytest.raises(ScanConflictError):
        store.cancel_scan(TENANT_A_USER_ID, scan.id)
    scan2 = store.create_scan(TENANT_A_USER_ID, target.id, {"depth": "deep", "max_urls": 500})
    cancelled = store.cancel_scan(TENANT_A_USER_ID, scan2.id)
    assert cancelled is not None and cancelled.status == "cancelled"
    assert store.cancel_scan(TENANT_B_USER_ID, scan2.id) is None


def test_findings_and_feedback() -> None:
    store = InMemoryStore()
    target = store.create_target(TENANT_A_USER_ID, "f.example.com", _hash("t"))
    scan = store.create_scan(TENANT_A_USER_ID, target.id, {"depth": "quick"})
    f1 = store.create_finding(
        TENANT_A_USER_ID,
        scan.id,
        target.id,
        "tpl-1",
        "Issue one",
        "high",
        ai_verdict="likely_true",
        ai_confidence=80,
        ai_reason="evidence matches",
    )
    f2 = store.create_finding(
        TENANT_A_USER_ID,
        scan.id,
        target.id,
        "tpl-2",
        "Issue two",
        "low",
    )
    assert store.get_finding(TENANT_B_USER_ID, f1.id) is None
    items, _ = store.list_findings(TENANT_A_USER_ID, scan.id, None, 20)
    assert len(items) == 2
    highs, _ = store.list_findings(TENANT_A_USER_ID, scan.id, None, 20, severity="high")
    assert [f.id for f in highs] == [f1.id]
    # Another tenant's scan id yields an empty page, never findings.
    items_b, _ = store.list_findings(TENANT_B_USER_ID, scan.id, None, 20)
    assert items_b == []
    # Feedback changes status only; ai_* fields are untouched.
    updated = store.update_finding_feedback(TENANT_A_USER_ID, f1.id, "false_positive")
    assert updated is not None and updated.status == "false_positive"
    assert updated.ai_verdict == "likely_true"
    assert updated.ai_confidence == 80
    assert updated.ai_reason == "evidence matches"
    assert store.update_finding_feedback(TENANT_B_USER_ID, f1.id, "confirmed") is None
    assert store.get_finding(TENANT_A_USER_ID, f2.id) is not None


def test_subscriptions_upsert() -> None:
    store = InMemoryStore()
    assert store.get_subscription(TENANT_A_USER_ID) is None
    sub = store.upsert_subscription(TENANT_A_USER_ID, plan="free")
    assert sub.plan == "free" and sub.status == "active"
    sub2 = store.upsert_subscription(TENANT_A_USER_ID, plan="pro")
    assert sub2.id == sub.id and sub2.plan == "pro"
    assert store.get_subscription(TENANT_B_USER_ID) is None


def test_audit_log_and_scan_jobs() -> None:
    store = InMemoryStore()
    entry = store.log_audit(TENANT_A_USER_ID, "scan.create", "a.example.com", {"scan_id": "x"})
    assert entry.action == "scan.create"
    target = store.create_target(TENANT_A_USER_ID, "j.example.com", _hash("t"))
    scan = store.create_scan(TENANT_A_USER_ID, target.id, {"depth": "quick"})
    key = f"{scan.id}:recon:abc123"
    job = store.create_scan_job(TENANT_A_USER_ID, scan.id, "recon", key)
    assert job.status == "queued" and job.attempt == 0
    assert store.get_scan_job_by_key(TENANT_A_USER_ID, key) is not None
    assert store.get_scan_job_by_key(TENANT_B_USER_ID, key) is None
    assert store.get_scan_job_by_key(TENANT_A_USER_ID, "nope") is None
    updated = store.update_scan_job(TENANT_A_USER_ID, job.id, status="done", attempt=1)
    assert updated is not None and updated.status == "done" and updated.attempt == 1
    assert store.update_scan_job(TENANT_B_USER_ID, job.id, status="done") is None


def test_seed_two_tenants() -> None:
    store = InMemoryStore()
    ids = seed_two_tenants(store)
    assert ids["tenant_a_user_id"] == TENANT_A_USER_ID
    assert ids["tenant_b_user_id"] == TENANT_B_USER_ID
    target_a = store.get_target(TENANT_A_USER_ID, ids["target_a_id"])
    assert target_a is not None and target_a.verification_status == "verified"
    assert target_a.domain == "example-a.com"
    # Tenant B cannot see A's target/scan/finding; A cannot see B's target.
    assert store.get_target(TENANT_B_USER_ID, ids["target_a_id"]) is None
    assert store.get_scan(TENANT_B_USER_ID, ids["scan_a_id"]) is None
    assert store.get_finding(TENANT_B_USER_ID, ids["finding_a_id"]) is None
    assert store.get_target(TENANT_A_USER_ID, ids["target_b_id"]) is None
    assert store.ping() is True


def test_get_target_by_domain_and_count_targets() -> None:
    # M3 review fix: the store helpers the 1-domain cap runs on.
    store = InMemoryStore()
    assert store.get_target_by_domain(TENANT_A_USER_ID, "x.example.com") is None
    assert store.count_targets(TENANT_A_USER_ID) == 0
    store.create_target(TENANT_A_USER_ID, "x.example.com", _hash("t1"))
    store.create_target(TENANT_A_USER_ID, "y.example.com", _hash("t2"))
    found = store.get_target_by_domain(TENANT_A_USER_ID, "x.example.com")
    assert found is not None and found.domain == "x.example.com"
    assert store.get_target_by_domain(TENANT_B_USER_ID, "x.example.com") is None
    assert store.count_targets(TENANT_A_USER_ID) == 2
    assert store.count_targets(TENANT_B_USER_ID) == 0


def test_get_owner_audit_only() -> None:
    # M8 review fix: get_owner returns only the owner id (audit-only);
    # it never reveals the row itself.
    store = InMemoryStore()
    target = store.create_target(TENANT_A_USER_ID, "o.example.com", _hash("t"))
    scan = store.create_scan(TENANT_A_USER_ID, target.id, {})
    finding = store.create_finding(
        TENANT_A_USER_ID, scan.id, target.id, "template-1", "Test finding", "high"
    )
    assert store.get_owner("target", target.id) == TENANT_A_USER_ID
    assert store.get_owner("scan", scan.id) == TENANT_A_USER_ID
    assert store.get_owner("finding", finding.id) == TENANT_A_USER_ID
    assert store.get_owner("target", target.id) != TENANT_B_USER_ID
    assert store.get_owner("target", uuid.uuid4()) is None
    assert store.get_owner("scan", uuid.uuid4()) is None


def test_list_scans_excludes_soft_deleted() -> None:
    # Round-2 review: list_scans used to return soft-deleted scans
    # (list_targets already filtered them). There is no delete_scan in
    # the Store protocol — scans are soft-deleted only via the SQL
    # soft_delete_scan RPC helper — so the test sets deleted_at directly
    # on the stored row, which is exactly what the helper does.
    from datetime import datetime, timezone

    store = InMemoryStore()
    target = store.create_target(TENANT_A_USER_ID, "s.example.com", _hash("t"))
    live = store.create_scan(TENANT_A_USER_ID, target.id, {})
    gone = store.create_scan(TENANT_A_USER_ID, target.id, {})
    store._scans[gone.id].deleted_at = datetime.now(timezone.utc)
    listed, _ = store.list_scans(TENANT_A_USER_ID, None, 10)
    assert [s.id for s in listed] == [live.id]
    # get_scan still returns the row itself (same as get_target's
    # behaviour is NOT mirrored here — list is the fixed surface).
    assert store.get_scan(TENANT_A_USER_ID, gone.id) is not None


# --- Staff accounts / invites / admin settings (C2 + C3 fixes) -----------


def test_staff_account_crud_and_factor_ids() -> None:
    from datetime import datetime, timezone

    from app.db.store import DuplicateOwnerAccountError, DuplicateStaffAccountError

    store = InMemoryStore()
    now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
    owner_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    owner = store.create_staff_account(owner_id, "Owner@Example.com", "owner", None, now)
    assert owner.email == "owner@example.com"  # normalized
    assert owner.status == "active"
    assert owner.created_at == now
    with pytest.raises(DuplicateOwnerAccountError):
        store.create_staff_account(uuid.uuid4(), "second@example.com", "owner", owner_id)
    with pytest.raises(DuplicateStaffAccountError):
        store.create_staff_account(uuid.uuid4(), "OWNER@example.com", "admin", owner_id)
    admin = store.create_staff_account(admin_id, "admin@example.com", "admin", owner_id)
    assert store.get_staff_account(admin_id) is admin
    assert store.get_staff_account_by_email("ADMIN@EXAMPLE.COM") is admin
    assert {row.user_id for row in store.list_staff_accounts()} == {owner_id, admin_id}
    updated = store.update_staff_account(admin_id, role="support", status="suspended")
    assert updated is not None and updated.role == "support" and updated.status == "suspended"
    with_factor = store.set_staff_factor_ids(
        admin_id, current_factor_id="factor-1", pending_factor_id="factor-2"
    )
    assert with_factor is not None
    assert with_factor.current_factor_id == "factor-1"
    assert with_factor.pending_factor_id == "factor-2"
    cleared = store.set_staff_factor_ids(admin_id, current_factor_id=None, pending_factor_id=None)
    assert cleared is not None
    assert cleared.current_factor_id is None and cleared.pending_factor_id is None
    assert store.delete_staff_account(admin_id) is True
    assert store.get_staff_account(admin_id) is None
    assert store.get_staff_account_by_email("admin@example.com") is None
    assert store.delete_staff_account(admin_id) is False


def test_staff_invite_claim_is_single_use() -> None:
    from datetime import datetime, timedelta, timezone

    store = InMemoryStore()
    now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
    inviter = uuid.uuid4()
    invite = store.create_staff_invite(
        "NewHire@Example.com",
        "support",
        inviter,
        _hash("invite-token"),
        now + timedelta(hours=72),
        now,
    )
    assert invite.email == "newhire@example.com"
    claimed = store.claim_staff_invite(_hash("invite-token"), now)
    assert claimed is not None and claimed.id == invite.id
    assert claimed.used_at == now
    assert store.claim_staff_invite(_hash("invite-token"), now) is None
    assert store.get_staff_invite(invite.id) is not None
    # Expired invites never claim.
    store.create_staff_invite("late@example.com", "admin", inviter, _hash("old-token"), now, now)
    assert store.claim_staff_invite(_hash("old-token"), now) is None


def test_admin_settings_prefix_version_round_trip() -> None:
    store = InMemoryStore()
    assert store.get_prefix_version() == 1  # seeded by the migration
    assert store.get_admin_setting("prefix_version") == "1"
    assert store.bump_prefix_version() == 2
    assert store.bump_prefix_version() == 3
    assert store.get_prefix_version() == 3
    assert store.set_prefix_version(1) == 1
    assert store.set_admin_setting("probe-key", "probe-value") == "probe-value"
    assert store.get_admin_setting("probe-key") == "probe-value"
