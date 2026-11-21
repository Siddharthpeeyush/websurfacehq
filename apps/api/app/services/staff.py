"""Staff account management (Owner-only admin operations).

Used by the Owner-only admin routes (Child D's ``/admin/users/*``):
create (via invite), suspend, delete, re-role, revoke-sessions,
force-reset, MFA re-enrollment. Every mutation is audit-logged via
Child A's audit service (``app.services.audit.write``).

SOURCE OF TRUTH (C2 fix, 20 Nov 2026): staff accounts live in the
STORE (migration 0007's ``staff_roles`` table on the Supabase path,
``InMemoryStore`` in tests/dev) — the process-local registry that
used to live here is GONE. Every read and write in this module goes
through ``Store`` methods (``create/get/update/delete_staff_account``,
``set_staff_factor_ids``, ``list_staff_accounts``); a restart loses
nothing the store persisted. ``StaffAccount`` IS the store's
``StaffAccountRow`` — on the in-memory path the store returns the
stored row object itself, so a caller holding a reference always
sees the current persisted state.

Owner-only enforcement goes through the CENTRAL ``can()``
(``app.auth.permissions`` — Child A): each function maps to its
``admin.users.*`` action and passes the actor's server-resolved
platform role. ``can()`` never trusts the client; the actor is the
server-resolved ``StaffAccount``.

Rules (plan §1, DESIGN-LOCK.md "Staff accounts"):

- Exactly one Owner: creating / re-roling to ``owner`` when an Owner
  already exists raises :class:`DuplicateOwnerError`; the Owner
  account itself cannot be suspended, deleted, or re-roled
  (:class:`OwnerProtectedError`).
- Suspend / delete revoke ALL sessions instantly (via Child B's
  ``SessionManager``); audit history is kept (audit rows live in
  ``audit_logs``, a separate table — deleting a staff row never
  touches them).
- Re-role revokes all sessions, so the new role takes effect at the
  next sign-in (sessions never carry a stale role).
- Force-reset invalidates the old password IMMEDIATELY via the
  GoTrue Admin API (``AuthProvider.disable_password`` — the password
  is replaced with a fresh random unguessable one, F2 fix 20 Nov
  2026), AND sends the reset email AND revokes sessions. The reset
  link is the only way back in: it sets a new password without
  needing the old one. The random-password route (not a ban) is
  deliberate — a ban would block sign-in via the recovery link
  itself until unbanned. If the reset email fails AFTER the disable,
  the 502 propagates and the account stays locked out until the
  Owner retries force-reset (the retry re-sends the email; the
  password stays invalidated).
- MFA re-enrollment clears the enrolled MFA state AND revokes
  sessions. It is EFFECTIVE (not just a flag): the account's stored
  ``current_factor_id`` is cleared, and the login flow only ever
  challenges the stored factor — so the old GoTrue factor, while it
  still exists in GoTrue, can no longer complete a staff sign-in.
  The orphaned GoTrue factor itself is only removable via GoTrue's
  Admin API (Child B follow-up); the login flow never touches it.
- The underlying Supabase Auth user is NOT deleted by
  :func:`delete_staff` — the provider protocol has no delete-user
  method. The staff row is gone, so the staff door answers the generic
  401 for that identity; deleting the Auth user itself is a Child F /
  live follow-up (Admin API). This gap is recorded, not hidden.

AUDIT CONTRACT (M1 fix, 20 Nov 2026): each mutation writes exactly
ONE audit row — the service's row, with ``before`` captured BEFORE
the mutation (the admin router writes NO duplicate row for these
actions). The audit write happens AFTER the mutation (the store has
no transactions, so true atomicity is impossible — see the residual
below); if the audit write fails, the mutation is NOT rolled back
and NOT hidden: this module logs a loud ERROR and raises
``ApiError(500, "AUDIT_WRITE_FAILED")`` whose message tells the
admin the action SUCCEEDED but was NOT audited, so a human follows
up. The router lets that ApiError through unchanged.

RESIDUAL (documented, out of scope for this pass): audit and
mutation are not atomic — a crash between the two, or a store that
accepts the mutation and then fails the audit insert, leaves a real
action with no audit row (now loudly reported instead of silent).
Full atomicity needs store transactions (a future Store protocol
change); until then the loud 500 + the audit-log review in the live
proof are the mitigation. See ADR-0010.
"""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

from app.auth.jwt import User
from app.auth.permissions import can
from app.auth.sessions import SessionManager, default_session_store
from app.core.errors import ApiError
from app.core.logging import logger
from app.core.staff_prefix import get_prefix_version
from app.db.store import (
    DuplicateOwnerAccountError,
    DuplicateStaffAccountError,
    StaffAccountRow,
)
from app.services import audit as audit_service
from app.services.invites import STAFF_ROLES, StaffInvite, create_invite, revoke_pending_invites

if TYPE_CHECKING:
    from app.db.store import Store

# The service layer's account shape IS the store row (see module
# docstring). Kept as an alias so existing imports keep working.
StaffAccount = StaffAccountRow

# --- Session manager wiring (Child B) -----------------------------------------
# The manager is resolved here (services layer) so both this module's
# revocation paths and Child C's router share one override hook.
# Production: SessionManager on the default store (Supabase when
# configured, else the process-wide in-memory store) with the LIVE
# prefix-version counter (``app.core.staff_prefix`` — DB-backed since
# the C3 fix), so rotation invalidates sessions.

_session_manager_override: SessionManager | None = None


def get_staff_session_manager() -> SessionManager:
    """The SessionManager for staff sessions (test override wins)."""
    if _session_manager_override is not None:
        return _session_manager_override
    return SessionManager(default_session_store(), current_prefix_version=get_prefix_version)


def set_staff_session_manager(manager: SessionManager | None) -> None:
    """Override the session manager (tests only). ``None`` clears it."""
    global _session_manager_override
    _session_manager_override = manager


class StaffNotOwnerError(ValueError):
    """Raised when a non-Owner attempts an Owner-only staff operation."""


class DuplicateOwnerError(ValueError):
    """Raised when a second Owner would be created (exactly one Owner)."""


class OwnerProtectedError(ValueError):
    """Raised when the Owner account itself would be suspended/deleted/re-roled."""


class StaffNotFoundError(ValueError):
    """Raised when the target staff account does not exist."""


class DuplicateStaffError(ValueError):
    """Raised when the email already has a staff account."""


_LOCK = threading.RLock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _store() -> Store:
    """The active store (the source of truth for staff accounts)."""
    from app.db import get_store

    return get_store()


def _audit_or_fail(
    actor: UUID, action: str, *, target: UUID | None = None, before: Any = None, after: Any = None
) -> None:
    """Write the mutation's ONE audit row (M1 contract).

    The mutation has already happened when this runs. An audit
    failure is LOUD (ERROR log with actor + action) and raises a
    500 that tells the admin the action SUCCEEDED but was NOT
    audited — never a silent gap, never a disguised success.
    """
    try:
        audit_service.write(actor, action, target=target, before=before, after=after)
    except Exception as exc:  # noqa: BLE001 - the loud contract is the point
        logger.error(
            "staff audit write failed; action performed but NOT audited",
            extra={"actor_id": str(actor), "action": action, "error_type": type(exc).__name__},
        )
        raise ApiError(
            500,
            "AUDIT_WRITE_FAILED",
            "The action succeeded but the audit record could not be "
            "written. Follow up: check the audit log and re-record "
            f"this action ({action}).",
        ) from exc


def _require_owner(actor: StaffAccount, action: str) -> None:
    """Owner-only gate via the CENTRAL ``can()`` (Child A).

    The platform role is the actor's server-resolved staff role;
    ``can()`` decides the ``admin.users.*`` action on that alone.
    """
    user = User(id=actor.user_id, email=actor.email)
    if not can(user, action, None, platform_role=actor.role):
        raise StaffNotOwnerError("Only the Owner can manage staff accounts")


def _get_owner_account() -> StaffAccount | None:
    for account in _store().list_staff_accounts():
        if account.role == "owner":
            return account
    return None


# --- Accounts ----------------------------------------------------------------


def public_staff_profile(account: StaffAccount) -> dict[str, Any]:
    """Outward shape of a staff account — NEVER includes MFA material."""
    return {
        "user_id": str(account.user_id),
        "email": account.email,
        "role": account.role,
        "status": account.status,
        "mfa_enrolled": account.mfa_enrolled,
        "created_at": account.created_at.isoformat() if account.created_at else None,
        "updated_at": account.updated_at.isoformat() if account.updated_at else None,
    }


def create_staff_account(
    user_id: UUID,
    email: str,
    role: str,
    invited_by: UUID | None,
    *,
    now: datetime | None = None,
) -> StaffAccount:
    """Create the staff row for a newly accepted invite (or the first Owner).

    Persists through the store (the DB is the source of truth).
    Raises DuplicateOwnerError (second Owner), DuplicateStaffError (the
    email already has a staff row), ValueError (unknown role).
    """
    if role not in STAFF_ROLES:
        raise ValueError(f"Unknown staff role: {role!r}")
    try:
        return _store().create_staff_account(user_id, email, role, invited_by, now)
    except DuplicateOwnerAccountError as exc:
        raise DuplicateOwnerError("An Owner account already exists") from exc
    except DuplicateStaffAccountError as exc:
        raise DuplicateStaffError(str(exc)) from exc


def get_staff_account(user_id: UUID) -> StaffAccount | None:
    """A staff account by Auth user id, or None (incl. deleted accounts)."""
    return _store().get_staff_account(user_id)


def get_staff_account_by_email(email: str) -> StaffAccount | None:
    """A staff account by email (lowercased), or None."""
    return _store().get_staff_account_by_email(email)


def resolve_staff_role(user_id: UUID, store: Store | None = None) -> tuple[str, str] | None:
    """Resolve (role, status) for a staff user — store-first.

    ``Store.get_staff_role`` is the source of truth; when the store
    does not know the account, the full row (same store, different
    method) answers. Returns None when neither knows the user.

    Never raises: a store failure falls back to the row lookup, which
    is empty in production, so the fallback is fail-closed there.
    No direct DB queries anywhere — only the sanctioned store
    methods are used; the router never touches the DB.
    """
    resolved_store = store
    if resolved_store is None:
        try:
            resolved_store = _store()
        except Exception:  # noqa: BLE001 - resolver must never break login
            resolved_store = None
    if resolved_store is not None:
        try:
            method = getattr(resolved_store, "get_staff_role", None)
            if callable(method):
                result = method(user_id)
                if result is not None:
                    return (str(result[0]), str(result[1]))
        except Exception:  # noqa: BLE001 - fall back to the row lookup
            pass
    account = get_staff_account(user_id)
    if account is None:
        return None
    return (account.role, account.status)


def ensure_staff_account(user_id: UUID, email: str | None = None) -> StaffAccount | None:
    """The staff row for a user, synthesizing from the store's role when needed.

    When the store's ``get_staff_role`` knows the user but no full row
    exists (e.g. a row created by the dashboard bootstrap SQL before
    the API ever saw it, or a store that only implements the role
    method), a row is created from the store's role/status so the MFA
    factor ids have somewhere to live. Synthesis needs an email — pass
    it when the caller has one (the login flow does, from the JWT);
    without one, a row-less user reads as "not staff". Returns None
    when neither the store row nor the store role knows the user.
    Never raises for a synthesis failure (e.g. a second-Owner
    conflict) — the caller treats None as "not staff".
    """
    account = get_staff_account(user_id)
    if account is not None:
        return account
    resolved = resolve_staff_role(user_id)
    if resolved is None or email is None:
        return None
    role, status = resolved
    try:
        account = create_staff_account(user_id, email, role, invited_by=None)
    except ValueError:
        return None
    if status != "active":
        updated = _store().update_staff_account(user_id, status=status)
        if updated is not None:
            account = updated
    return account


def list_staff_accounts() -> list[StaffAccount]:
    """All staff accounts (Owner-only callers; no secrets in the shape)."""
    return _store().list_staff_accounts()


def set_staff_pending_factor(user_id: UUID, factor_id: str) -> StaffAccount | None:
    """Persist the factor being enrolled (``/mfa/enroll``).

    Sets ``pending_factor_id`` and keeps the current factor — the
    pending factor activates only after ``/mfa/confirm`` verifies a
    code against it (see :func:`activate_staff_factor`)."""
    row = _store().get_staff_account(user_id)
    if row is None:
        return None
    return _store().set_staff_factor_ids(
        user_id, current_factor_id=row.current_factor_id, pending_factor_id=factor_id
    )


def activate_staff_factor(user_id: UUID, factor_id: str) -> StaffAccount | None:
    """Persist a verified factor as the account's current factor
    (``/mfa/confirm``): current = the verified factor, pending
    cleared, enrolled flag set. The old current factor (if any) is
    retired by this write."""
    updated = _store().set_staff_factor_ids(
        user_id, current_factor_id=factor_id, pending_factor_id=None
    )
    if updated is None:
        return None
    _store().update_staff_account(user_id, mfa_enrolled=True)
    return updated


def revoke_all_staff_sessions(user_id: UUID) -> int:
    """Revoke every live session for a user (Child B's SessionManager)."""
    return get_staff_session_manager().revoke_all_for_user(user_id)


# --- Owner-only operations -----------------------------------------------------


def create_staff_invite(
    actor: StaffAccount,
    email: str,
    role: str,
    *,
    now: datetime | None = None,
) -> tuple[StaffInvite, str]:
    """Owner creates a staff invite; returns ``(invite, raw_token)``.

    The raw token goes to the Owner (who forwards the setup link) and
    is never stored. Re-inviting an email INVALIDATES its prior
    pending invites first (F3 fix) — only the newest setup link is
    ever live, so a stale link forwarded by mistake cannot still be
    used. Raises StaffNotOwnerError, DuplicateOwnerError,
    DuplicateStaffError, ValueError (unknown role).
    """
    _require_owner(actor, "admin.users.invite")
    if role not in STAFF_ROLES:
        raise ValueError(f"Unknown staff role: {role!r}")
    normalized = email.strip().lower()
    with _LOCK:
        if role == "owner" and _get_owner_account() is not None:
            raise DuplicateOwnerError("An Owner account already exists")
        if get_staff_account_by_email(normalized) is not None:
            raise DuplicateStaffError(f"Staff account already exists for {normalized}")
    prior_revoked = revoke_pending_invites(normalized, now=now)
    invite, token = create_invite(normalized, role, actor.user_id, now=now)
    _audit_or_fail(
        actor.user_id,
        "staff.invite_created",
        after={
            "role": role,
            "email_hash": hashlib.sha256(normalized.encode()).hexdigest(),
            "prior_invites_revoked": prior_revoked,
        },
    )
    return invite, token


def revoke_staff_invite(actor: StaffAccount, invite_id: UUID) -> StaffInvite:
    """Owner revokes a pending invite; returns the revoked invite.

    The old token 404s at accept time from now on. Revoking a
    consumed/expired invite — or an unknown id — raises
    StaffNotFoundError (the router answers 404: it is already
    unusable, so there is nothing to distinguish). Raises
    StaffNotOwnerError for non-Owners.
    """
    _require_owner(actor, "admin.users.invite")
    from app.services.invites import revoke_invite

    invite = revoke_invite(invite_id)
    if invite is None:
        raise StaffNotFoundError(f"No pending invite for {invite_id}")
    _audit_or_fail(
        actor.user_id,
        "staff.invite_revoked",
        target=invite_id,
        after={
            "email_hash": hashlib.sha256(invite.email.encode()).hexdigest(),
            "role": invite.role,
        },
    )
    return invite


def _get_or_raise(user_id: UUID) -> StaffAccount:
    account = get_staff_account(user_id)
    if account is None:
        raise StaffNotFoundError(f"No staff account for {user_id}")
    return account


def suspend_staff(actor: StaffAccount, user_id: UUID) -> StaffAccount:
    """Suspend a staff account; all sessions revoked instantly."""
    _require_owner(actor, "admin.users.suspend")
    account = _get_or_raise(user_id)
    if account.role == "owner":
        raise OwnerProtectedError("The Owner account cannot be suspended")
    before = {"status": account.status}
    updated = _store().update_staff_account(user_id, status="suspended")
    if updated is None:
        raise StaffNotFoundError(f"No staff account for {user_id}")
    revoked = revoke_all_staff_sessions(user_id)
    _audit_or_fail(
        actor.user_id,
        "staff.suspended",
        target=user_id,
        before=before,
        after={"status": "suspended", "sessions_revoked": revoked},
    )
    return updated


def delete_staff(actor: StaffAccount, user_id: UUID) -> None:
    """Delete a staff account; sessions revoked instantly, audit kept.

    The staff row is removed; audit rows (``audit_logs``) are untouched.
    The underlying Supabase Auth user is NOT deleted (see module
    docstring) — the staff door answers the generic 401 for that
    identity from now on.
    """
    _require_owner(actor, "admin.users.delete")
    account = _get_or_raise(user_id)
    if account.role == "owner":
        raise OwnerProtectedError("The Owner account cannot be deleted")
    before = {
        "email_hash": hashlib.sha256(account.email.encode()).hexdigest(),
        "role": account.role,
    }
    revoke_all_staff_sessions(user_id)
    _store().delete_staff_account(user_id)
    _audit_or_fail(actor.user_id, "staff.deleted", target=user_id, before=before)


def re_role_staff(actor: StaffAccount, user_id: UUID, new_role: str) -> StaffAccount:
    """Change a staff member's role; all sessions revoked instantly."""
    _require_owner(actor, "admin.users.role")
    if new_role not in STAFF_ROLES:
        raise ValueError(f"Unknown staff role: {new_role!r}")
    account = _get_or_raise(user_id)
    if account.role == "owner":
        raise OwnerProtectedError("The Owner account cannot be re-roled")
    if new_role == "owner":
        raise DuplicateOwnerError("An Owner account already exists")
    old_role = account.role
    before = {"role": old_role}
    try:
        updated = _store().update_staff_account(user_id, role=new_role)
    except DuplicateOwnerAccountError as exc:
        raise DuplicateOwnerError("An Owner account already exists") from exc
    if updated is None:
        raise StaffNotFoundError(f"No staff account for {user_id}")
    revoked = revoke_all_staff_sessions(user_id)
    _audit_or_fail(
        actor.user_id,
        "staff.role_changed",
        target=user_id,
        before=before,
        after={"role": new_role, "sessions_revoked": revoked},
    )
    return updated


def revoke_staff_sessions(actor: StaffAccount, user_id: UUID) -> int:
    """Owner revokes all of a staff member's sessions. Returns the count."""
    _require_owner(actor, "admin.users.revoke_sessions")
    _get_or_raise(user_id)
    revoked = revoke_all_staff_sessions(user_id)
    _audit_or_fail(
        actor.user_id,
        "staff.sessions_revoked",
        target=user_id,
        after={"sessions_revoked": revoked},
    )
    return revoked


def force_password_reset(actor: StaffAccount, user_id: UUID) -> None:
    """Owner forces a password reset: old password invalidated +
    reset email + sessions revoked.

    Order matters. The old password is invalidated FIRST
    (``disable_password`` — Admin API, random unguessable password),
    so there is no window in which the reset email is out and the
    old password still works. The reset email goes second: the
    recovery link sets a new password without needing the old one,
    so it still works after the disable. Sessions are revoked last.

    Provider failures (503 unconfigured / 502 upstream) propagate —
    the Owner must see that the reset email did NOT go out. If the
    reset email fails after the disable, the account stays locked
    out until the Owner retries force-reset (the retry re-sends the
    email; the password stays invalidated). Unknown-email
    swallowing lives in the provider, not here.
    """
    _require_owner(actor, "admin.users.force_reset")
    account = _get_or_raise(user_id)
    from app.auth.provider import get_auth_provider

    get_auth_provider().disable_password(account.user_id)
    get_auth_provider().reset_password(account.email)
    revoked = revoke_all_staff_sessions(user_id)
    _audit_or_fail(
        actor.user_id,
        "staff.force_reset",
        target=user_id,
        after={"sessions_revoked": revoked, "password_invalidated": True},
    )


def mfa_re_enroll_staff(actor: StaffAccount, user_id: UUID) -> StaffAccount:
    """Owner clears a staff member's MFA; sessions revoked instantly.

    Clears the stored factor ids, so the login flow treats the account
    as unenrolled and the old GoTrue factor can no longer complete a
    staff sign-in (see module docstring). The account re-enrolls on
    its next login (``enroll_required`` flow).
    """
    _require_owner(actor, "admin.users.mfa_re_enroll")
    account = _get_or_raise(user_id)
    before = {
        "mfa_enrolled": account.mfa_enrolled,
        "had_factor": account.current_factor_id is not None,
    }
    updated = _store().set_staff_factor_ids(user_id, current_factor_id=None, pending_factor_id=None)
    if updated is None:
        raise StaffNotFoundError(f"No staff account for {user_id}")
    _store().update_staff_account(user_id, mfa_enrolled=False)
    revoked = revoke_all_staff_sessions(user_id)
    _audit_or_fail(
        actor.user_id,
        "staff.mfa_re_enroll",
        target=user_id,
        before=before,
        after={"mfa_enrolled": False, "sessions_revoked": revoked},
    )
    return updated


def reset_staff_state_for_tests() -> None:
    """Drop all staff accounts + clear the session-manager override (tests only).

    The store is the source of truth, so "drop all staff accounts"
    drops the in-memory store singleton itself (the F-M1 pattern:
    fixtures re-select a fresh store afterwards). Supabase-backed
    state is never touched by a test reset.
    """
    set_staff_session_manager(None)
    try:
        from app.db import reset_store_for_tests

        reset_store_for_tests()
    except Exception:  # noqa: BLE001 - reset must never fail a fixture
        pass
