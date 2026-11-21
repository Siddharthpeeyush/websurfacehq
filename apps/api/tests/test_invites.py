"""Tests for the staff invite service (``app.services.invites``).

- Token: 32 random bytes, URL-safe; only the SHA-256 hash is stored
  (the raw token appears nowhere in the stored record).
- Claim: valid -> claimed (``used_at`` stamped); reuse -> None;
  expired -> None; invalid -> None — all three indistinguishable.
- Expiry: created + 72h.
- Role validation + email normalization.
- The exactly-one-Owner rule, enforced where the accounts live
  (``app.services.staff``): a second Owner invite is refused, and a
  second Owner account cannot be created at accept time either.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.db import reset_store_for_tests
from app.services.invites import (
    INVITE_TTL_HOURS,
    claim_invite,
    create_invite,
    generate_invite_token,
    get_invite,
    hash_invite_token,
    reset_invites_for_tests,
)
from app.services.staff import (
    DuplicateOwnerError,
    DuplicateStaffError,
    create_staff_account,
    create_staff_invite,
    reset_staff_state_for_tests,
)

INVITER = uuid.uuid4()
EMAIL = "newhire@websurfacehq.com"


@pytest.fixture(autouse=True)
def _test_store_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invites + staff accounts live in the STORE now (C2 fix), so
    these service tests must run against the in-memory store — the
    real .env configures live Supabase, and migration 0007 is not
    applied live, so the Supabase path 404s on staff_invites. Null
    the keys (same F-M1 pattern as tests.test_staff_auth) so the
    store singleton re-selects in-memory."""
    monkeypatch.setattr(settings, "supabase_url", None)
    monkeypatch.setattr(settings, "supabase_anon_key", None)
    monkeypatch.setattr(settings, "supabase_service_role_key", None)


@pytest.fixture(autouse=True)
def _reset_state() -> Generator[None, None, None]:
    reset_store_for_tests()
    reset_invites_for_tests()
    reset_staff_state_for_tests()
    yield
    reset_store_for_tests()
    reset_invites_for_tests()
    reset_staff_state_for_tests()


def test_invite_token_is_32_random_bytes_and_hash_only_stored() -> None:
    token = generate_invite_token()
    assert len(token) == 43  # 32 bytes, URL-safe base64, no padding
    assert token == token.strip()
    invite, raw = create_invite(EMAIL, "admin", INVITER)
    assert len(raw) == 43
    assert invite.token_hash == hash_invite_token(raw)
    assert invite.token_hash != raw
    # The raw token appears nowhere in the stored record.
    assert raw not in str(invite)
    assert raw not in invite.token_hash


def test_invite_expiry_is_72_hours() -> None:
    assert INVITE_TTL_HOURS == 72
    now = datetime.now(timezone.utc)
    invite, _token = create_invite(EMAIL, "support", INVITER, now=now)
    assert invite.expires_at == now + timedelta(hours=72)
    assert invite.used_at is None
    assert invite.created_at == now


def test_claim_valid_invite_stamps_used_at() -> None:
    invite, token = create_invite(EMAIL, "admin", INVITER)
    claimed = claim_invite(token)
    assert claimed is not None
    assert claimed.id == invite.id
    assert claimed.used_at is not None
    stored = get_invite(invite.id)
    assert stored is not None and stored.used_at is not None


def test_claim_reuse_expired_and_invalid_are_indistinguishable() -> None:
    # Reuse: claim once, claim again -> None.
    _invite, token = create_invite("reuse@websurfacehq.com", "admin", INVITER)
    assert claim_invite(token) is not None
    reuse = claim_invite(token)
    # Expired: created 73h ago -> None (even on the first claim).
    _old, old_token = create_invite(
        "old@websurfacehq.com",
        "admin",
        INVITER,
        now=datetime.now(timezone.utc) - timedelta(hours=73),
    )
    expired = claim_invite(old_token)
    # Invalid: never issued -> None.
    invalid = claim_invite("never-issued-token")
    assert reuse is None and expired is None and invalid is None


def test_claim_at_exact_expiry_is_rejected() -> None:
    now = datetime.now(timezone.utc)
    _invite, token = create_invite(EMAIL, "support", INVITER, now=now)
    assert claim_invite(token, now=now + timedelta(hours=72)) is None
    assert claim_invite(token, now=now + timedelta(hours=71, minutes=59)) is not None


def test_create_invite_rejects_unknown_role_and_normalizes_email() -> None:
    with pytest.raises(ValueError):
        create_invite(EMAIL, "superuser", INVITER)
    invite, _token = create_invite("  Admin@WebsurfaceHQ.COM ", "admin", INVITER)
    assert invite.email == "admin@websurfacehq.com"
    assert invite.role == "admin"


def test_exactly_one_owner_invite() -> None:
    from app.services.staff import get_staff_account

    owner_id = uuid.uuid4()
    create_staff_account(owner_id, "owner@websurfacehq.com", "owner", None)
    owner = get_staff_account(owner_id)
    assert owner is not None
    # The existing Owner cannot invite a second Owner ...
    with pytest.raises(DuplicateOwnerError):
        create_staff_invite(owner, "second-owner@websurfacehq.com", "owner")
    # ... and a second Owner row cannot be created directly either.
    with pytest.raises(DuplicateOwnerError):
        create_staff_account(uuid.uuid4(), "second-owner@websurfacehq.com", "owner", None)


def test_invite_for_existing_staff_email_is_refused() -> None:
    from app.services.staff import get_staff_account

    owner_id = uuid.uuid4()
    create_staff_account(owner_id, "owner@websurfacehq.com", "owner", None)
    create_staff_account(uuid.uuid4(), "admin@websurfacehq.com", "admin", owner_id)
    owner = get_staff_account(owner_id)
    assert owner is not None
    with pytest.raises(DuplicateStaffError):
        create_staff_invite(owner, "admin@websurfacehq.com", "support")


def test_two_invites_for_same_email_are_independent() -> None:
    _first, first_token = create_invite(EMAIL, "admin", INVITER)
    second, second_token = create_invite(EMAIL, "support", INVITER)
    assert first_token != second_token
    assert claim_invite(first_token) is not None
    # Claiming the first does not consume the second.
    claimed_second = claim_invite(second_token)
    assert claimed_second is not None
    assert claimed_second.id == second.id
    assert claimed_second.role == "support"


def test_reinvite_invalidates_prior_pending_invite() -> None:
    """F3 fix (red-team): re-inviting an email INVALIDATES its prior
    pending invite — previously ``create_staff_invite`` minted a
    second live token (two 201s, distinct tokens, even different
    roles). The low-level ``create_invite`` stays independent (see
    the test above); the invalidation lives in the Owner path
    (``create_staff_invite``), so only the newest setup link for an
    email is ever live."""
    owner = create_staff_account(uuid.uuid4(), "owner@websurfacehq.com", "owner", None)
    _first, first_token = create_staff_invite(owner, EMAIL, "support")
    second, second_token = create_staff_invite(owner, EMAIL, "admin")
    assert first_token != second_token
    assert second.role == "admin"
    # The old token is dead; the new one is live.
    assert claim_invite(first_token) is None
    claimed = claim_invite(second_token)
    assert claimed is not None
    assert claimed.id == second.id
