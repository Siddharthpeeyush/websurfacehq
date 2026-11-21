"""Staff invite links: single-use, 72-hour expiry (Owner-issued).

Locked design (DESIGN-LOCK.md, "Staff accounts", 14 Nov 2026 + plan §1):
the Owner alone creates staff accounts; credential handoff is by a
one-time expiring invite link (single-use, 72h expiry). The staff
member sets their OWN password + MFA through the link — the Owner
never sees or sets staff passwords.

Token handling reuses the existing verification-token pattern
(``app.services.verification`` — 32 random bytes, SHA-256 hash stored
only, raw token returned once and never logged):

- :func:`generate_invite_token` — 32 random bytes, URL-safe (43 chars).
- Only the SHA-256 hex (:func:`hash_invite_token`) is ever stored, in
  ``StaffInvite.token_hash`` (migration 0007's ``staff_invites``
  table, Child A).
- :func:`claim_invite` is the single-use enforcement: the store's
  atomic claim (``UPDATE ... WHERE used_at IS NULL AND expires_at >
  now RETURNING`` on the Supabase path; one lock on the in-memory
  path). A lost race returns ``None`` (the loser sees the invite as
  already used).

Anti-enumeration: expired, used, and invalid tokens are
INDISTINGUISHABLE — :func:`claim_invite` returns ``None`` for all three,
and the router answers all three with the same 404
(``NOT_FOUND`` / "Invalid or expired invite link").

SOURCE OF TRUTH (C2 fix, 20 Nov 2026): invites live in the STORE
(migration 0007's ``staff_invites`` table on the Supabase path) —
the process-local registry that used to live here is GONE. A restart
loses no invite, and replicas share the same claim state.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from app.db.store import StaffInviteRow
from app.services.verification import hash_token

if TYPE_CHECKING:
    from app.db.store import Store

# Invite lifetime (plan §2): created + 72h.
INVITE_TTL_HOURS = 72

StaffRole = Literal["owner", "admin", "support"]

STAFF_ROLES: frozenset[str] = frozenset({"owner", "admin", "support"})

# Token entropy mirrors the verification-token decision (32 random bytes).
_INVITE_TOKEN_BYTES = 32


# The service layer's invite shape IS the store row (same pattern as
# app.services.staff.StaffAccount). Kept as an alias so existing
# imports keep working.
StaffInvite = StaffInviteRow


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _store() -> Store:
    """The active store (the source of truth for invites)."""
    from app.db import get_store

    return get_store()


def generate_invite_token() -> str:
    """A fresh URL-safe invite token (32 random bytes, 43 chars).

    Returned ONCE, to the Owner who forwards the setup link. Never
    logged, never stored.
    """
    return secrets.token_urlsafe(_INVITE_TOKEN_BYTES)


# The token alphabet ``secrets.token_urlsafe`` draws from (RFC 4648
# §5, no padding): 43 chars for 32 random bytes.
_INVITE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def is_well_formed_invite_token(token: str) -> bool:
    """True when ``token`` has the shape a generated invite token has.

    Well-formedness only (N-NEW5, 20 Nov 2026): the invite-accept
    rate limit's per-token bucket applies ONLY to well-formed
    tokens, so a 429 can never fire for a garbage string — the
    429 fires only after the token was already validated as
    well-formed, and expired / used / invalid tokens still share
    the one 404. This says nothing about whether the token was
    ever issued (that is ``claim_invite``'s job).
    """
    return bool(_INVITE_TOKEN_RE.match(token))


def hash_invite_token(token: str) -> str:
    """SHA-256 hex of an invite token — the only form ever stored."""
    return hash_token(token)


def _validate_role(role: str) -> StaffRole:
    if role not in STAFF_ROLES:
        raise ValueError(f"Unknown staff role: {role!r}")
    return role  # type: ignore[return-value]


def create_invite(
    email: str,
    role: str,
    invited_by: UUID,
    *,
    now: datetime | None = None,
) -> tuple[StaffInvite, str]:
    """Create an invite and return ``(invite, raw_token)``.

    The raw token is returned once — the caller (the Owner's admin
    route) forwards it in the setup link and never stores it. Raises
    ValueError on an unknown role. The exactly-one-Owner rule is
    enforced by the caller (``app.services.staff.create_staff_invite``,
    which sees the staff accounts) and by the DB trigger (Child A) —
    not here, because this module does not own the accounts.
    """
    created = now or _now()
    staff_role = _validate_role(role)
    token = generate_invite_token()
    invite = _store().create_staff_invite(
        email.strip().lower(),
        staff_role,
        invited_by,
        hash_invite_token(token),
        created + timedelta(hours=INVITE_TTL_HOURS),
        created,
    )
    return invite, token


def claim_invite(token: str, *, now: datetime | None = None) -> StaffInvite | None:
    """Atomically claim an invite, or ``None`` when it cannot be used.

    Returns the invite and stamps ``used_at`` (single-use) when the
    token matches a stored hash, the invite is unused, and it has not
    expired. Returns ``None`` — identically — for an invalid token, an
    already-used invite, and an expired invite: callers must not
    distinguish them in any response.
    """
    current = now or _now()
    return _store().claim_staff_invite(hash_invite_token(token), current)


def get_invite(invite_id: UUID) -> StaffInvite | None:
    """Look an invite up by id (admin inspection; never by raw token)."""
    return _store().get_staff_invite(invite_id)


def revoke_pending_invites(email: str, *, now: datetime | None = None) -> int:
    """Invalidate every pending invite for an email (F3 fix).

    Called on re-invite so only the newest setup link for an email
    is ever live — the old token 404s at accept time. Returns the
    count revoked (0 when there was nothing pending)."""
    return _store().revoke_pending_staff_invites(email.strip().lower(), now or _now())


def revoke_invite(invite_id: UUID, *, now: datetime | None = None) -> StaffInvite | None:
    """Revoke ONE pending invite by id (Owner invite-revoke).

    Returns the revoked row, or None when there is no such invite
    or it is already consumed/expired (already unusable — the
    caller answers 404 either way, documented in the endpoint).
    """
    return _store().revoke_staff_invite(invite_id, now or _now())


def reset_invites_for_tests() -> None:
    """Drop all invites (tests only).

    Invites live in the store, so "drop all invites" drops the
    in-memory store singleton itself (the F-M1 pattern: fixtures
    re-select a fresh store afterwards). Supabase-backed state is
    never touched by a test reset.
    """
    try:
        from app.db import reset_store_for_tests

        reset_store_for_tests()
    except Exception:  # noqa: BLE001 - reset must never fail a fixture
        pass
