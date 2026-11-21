"""Staff sessions (admin foundation, plan §1/§2).

Rules (DESIGN-LOCK.md "Staff sessions", locked 15 Nov 2026):

- Absolute lifetime 12h; idle 60 min -> sign in again.
- TOTP at EVERY staff sign-in; no trusted-device bypass (the MFA
  check itself lives in ``app/auth/mfa.py`` + Child C's login flow —
  a session is only ever ISSUED after MFA has verified).
- Session cookies are scoped to the staff subdomain + secret prefix
  (Child C/E); this module enforces the server side: sessions carry
  a ``prefix_version`` and any session whose version is older than
  the current one is dead — prefix rotation invalidates all staff
  sessions without touching each row.
- Suspend/delete revokes sessions instantly (Child C calls
  :meth:`SessionManager.revoke_all_for_user`).

Storage: the ``staff_sessions`` table from plan §2 (migration 0007,
Child A): ``id, user_id, issued_at, last_seen_at, revoked_at, ip,
user_agent, prefix_version``. Two implementations of the
:class:`StaffSessionStore` protocol exist here:

- :class:`InMemoryStaffSessionStore` — tests and dev.
- :class:`SupabaseStaffSessionStore` — Postgres via supabase-py with
  the service-role key (server-side only).

INTERFACE GAP (flagged for Child A / coordinator, 20 Nov 2026):
plan §2's ``staff_sessions`` schema has NO column for the step-up
state, but plan §3 requires ``POST /staff/auth/step-up/verify`` to
mark the session step-up-verified. This module therefore carries
``step_up_verified_at`` on :class:`StaffSession` and the store
protocol, and the Supabase store reads/writes a
``step_up_verified_at`` column — migration 0007 MUST add that column
(one nullable ``timestamptz``) or the step-up path 502s at runtime.
The Supabase store is written defensively around it: the column is
only sent when a step-up time is set, so issue / validate / revoke
all work before the column lands; only ``mark_step_up_verified``
needs it. The in-memory store supports it fully today.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol
from uuid import UUID

from app.core.config import Settings, settings
from app.core.errors import ApiError
from app.core.http import create_supabase_client
from app.core.logging import logger

# One generic 401 for every session-validation failure — expired,
# idle-timed-out, revoked, stale prefix, unknown id: indistinguishable
# by design, so a probe can never learn WHY a session died (and a
# stolen-but-revoked token looks exactly like a never-existent one).
_INVALID_SESSION = ("INVALID_SESSION", "Session is invalid or expired")


def _unauthorized() -> ApiError:
    return ApiError(401, _INVALID_SESSION[0], _INVALID_SESSION[1])


def _store_unavailable() -> ApiError:
    return ApiError(502, "BAD_GATEWAY", "Session store unavailable")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: Any) -> datetime | None:
    """Parse a Supabase timestamptz value (ISO string or datetime)."""
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    return None


# ---------------------------------------------------------------------------
# Row shape
# ---------------------------------------------------------------------------


@dataclass
class StaffSession:
    """One staff session (plan §2 ``staff_sessions`` + step-up state).

    ``step_up_verified_at`` is None until the session passes a fresh MFA check for the
    Founder gate (see the module docstring — migration 0007 must add the column).

    ``absolute_hours`` / ``idle_minutes`` record the lifetimes the
    session was issued under (informational — the plan §2 schema has
    no columns for them, so a row re-read from Postgres carries the
    defaults). Enforcement ALWAYS uses the ``SessionManager``'s
    current configured lifetimes, never these fields, so a re-read
    row can never silently gain a longer life than policy allows.
    """

    id: UUID
    user_id: UUID
    issued_at: datetime
    last_seen_at: datetime
    prefix_version: int
    revoked_at: datetime | None = None
    ip: str | None = None
    user_agent: str | None = None
    step_up_verified_at: datetime | None = None
    absolute_hours: int = 12
    idle_minutes: int = 60


# ---------------------------------------------------------------------------
# Store protocol
# ---------------------------------------------------------------------------


class StaffSessionStore(Protocol):
    """Persistence for staff sessions. Implementations must be safe to
    call from any thread (the in-memory one locks; the Supabase one
    is a stateless HTTP client)."""

    def create_session(
        self,
        user_id: UUID,
        *,
        now: datetime,
        ip: str | None,
        user_agent: str | None,
        prefix_version: int,
        absolute_hours: int,
        idle_minutes: int,
    ) -> StaffSession: ...

    def get_session(self, session_id: UUID) -> StaffSession | None: ...

    def touch_session(self, session_id: UUID, now: datetime) -> StaffSession | None:
        """Set ``last_seen_at = now``. None when the session is gone."""
        ...

    def revoke_session(self, session_id: UUID, now: datetime) -> bool:
        """Set ``revoked_at = now``. False when already revoked/gone."""
        ...

    def revoke_all_for_user(self, user_id: UUID, now: datetime) -> int:
        """Revoke every live session of a user. Returns the count."""
        ...

    def list_sessions_for_user(self, user_id: UUID) -> list[StaffSession]:
        """All non-revoked sessions of a user, most-recent first."""
        ...

    def mark_step_up_verified(self, session_id: UUID, now: datetime) -> StaffSession | None:
        """Set ``step_up_verified_at = now``. None when the session is gone."""
        ...


# ---------------------------------------------------------------------------
# In-memory store (tests + dev)
# ---------------------------------------------------------------------------


class InMemoryStaffSessionStore:
    """Thread-safe in-memory staff-session store."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[UUID, StaffSession] = {}

    def create_session(
        self,
        user_id: UUID,
        *,
        now: datetime,
        ip: str | None,
        user_agent: str | None,
        prefix_version: int,
        absolute_hours: int,
        idle_minutes: int,
    ) -> StaffSession:
        with self._lock:
            session = StaffSession(
                id=uuid.uuid4(),
                user_id=user_id,
                issued_at=now,
                last_seen_at=now,
                prefix_version=prefix_version,
                ip=ip,
                user_agent=user_agent,
                absolute_hours=absolute_hours,
                idle_minutes=idle_minutes,
            )
            self._sessions[session.id] = session
            return session

    def get_session(self, session_id: UUID) -> StaffSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def touch_session(self, session_id: UUID, now: datetime) -> StaffSession | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked_at is not None:
                return None
            updated = _replace(session, last_seen_at=now)
            self._sessions[session_id] = updated
            return updated

    def revoke_session(self, session_id: UUID, now: datetime) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked_at is not None:
                return False
            self._sessions[session_id] = _replace(session, revoked_at=now)
            return True

    def revoke_all_for_user(self, user_id: UUID, now: datetime) -> int:
        with self._lock:
            count = 0
            for session_id, session in list(self._sessions.items()):
                if session.user_id == user_id and session.revoked_at is None:
                    self._sessions[session_id] = _replace(session, revoked_at=now)
                    count += 1
            return count

    def list_sessions_for_user(self, user_id: UUID) -> list[StaffSession]:
        with self._lock:
            rows = [
                session
                for session in self._sessions.values()
                if session.user_id == user_id and session.revoked_at is None
            ]
            return sorted(rows, key=lambda s: s.last_seen_at, reverse=True)

    def mark_step_up_verified(self, session_id: UUID, now: datetime) -> StaffSession | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked_at is not None:
                return None
            updated = _replace(session, step_up_verified_at=now)
            self._sessions[session_id] = updated
            return updated


def _replace(session: StaffSession, **changes: Any) -> StaffSession:
    """Copy a frozen-in-spirit dataclass row with field overrides."""
    data: dict[str, Any] = {
        "id": session.id,
        "user_id": session.user_id,
        "issued_at": session.issued_at,
        "last_seen_at": session.last_seen_at,
        "prefix_version": session.prefix_version,
        "revoked_at": session.revoked_at,
        "ip": session.ip,
        "user_agent": session.user_agent,
        "step_up_verified_at": session.step_up_verified_at,
        "absolute_hours": session.absolute_hours,
        "idle_minutes": session.idle_minutes,
    }
    data.update(changes)
    return StaffSession(**data)


# ---------------------------------------------------------------------------
# Supabase store (production — service-role key, server-side only)
# ---------------------------------------------------------------------------


def _row_to_session(row: dict[str, Any]) -> StaffSession | None:
    """Parse a ``staff_sessions`` row. None when malformed (logged)."""
    try:
        session_id = uuid.UUID(str(row["id"]))
        user_id = uuid.UUID(str(row["user_id"]))
    except (KeyError, ValueError, AttributeError, TypeError):
        logger.warning("staff_sessions row has an invalid id/user_id")
        return None
    issued_at = _parse_dt(row.get("issued_at"))
    last_seen_at = _parse_dt(row.get("last_seen_at"))
    prefix_version = row.get("prefix_version")
    if issued_at is None or last_seen_at is None or not isinstance(prefix_version, int):
        logger.warning("staff_sessions row is missing issued_at/last_seen_at/prefix_version")
        return None
    return StaffSession(
        id=session_id,
        user_id=user_id,
        issued_at=issued_at,
        last_seen_at=last_seen_at,
        prefix_version=prefix_version,
        revoked_at=_parse_dt(row.get("revoked_at")),
        ip=row.get("ip") if isinstance(row.get("ip"), str) else None,
        user_agent=row.get("user_agent") if isinstance(row.get("user_agent"), str) else None,
        step_up_verified_at=_parse_dt(row.get("step_up_verified_at")),
    )


class SupabaseStaffSessionStore:
    """Staff sessions in Postgres (``staff_sessions``, migration 0007).

    Uses the service-role client (server-side only) via the proxy-safe
    client factory. The step-up column is only written when set (see
    the module docstring): before migration 0007 adds
    ``step_up_verified_at``, issue/validate/revoke work; only the
    step-up mark fails, loudly (502), instead of silently passing.
    """

    _TABLE = "staff_sessions"

    def __init__(self, app_settings: Settings | None = None) -> None:
        self._settings = app_settings or settings
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            if not self._settings.supabase_configured:
                raise _store_unavailable()
            url = self._settings.supabase_url or ""
            key = self._settings.supabase_service_role_key
            self._client = create_supabase_client(
                url, key.get_secret_value() if key is not None else ""
            )
        return self._client

    def _table(self) -> Any:
        return self._get_client().table(self._TABLE)

    @staticmethod
    def _rows(response: Any) -> list[dict[str, Any]]:
        data = getattr(response, "data", None)
        return data if isinstance(data, list) else []

    def create_session(
        self,
        user_id: UUID,
        *,
        now: datetime,
        ip: str | None,
        user_agent: str | None,
        prefix_version: int,
        absolute_hours: int,
        idle_minutes: int,
    ) -> StaffSession:
        session_id = uuid.uuid4()
        payload: dict[str, Any] = {
            "id": str(session_id),
            "user_id": str(user_id),
            "issued_at": now.isoformat(),
            "last_seen_at": now.isoformat(),
            "revoked_at": None,
            "ip": ip,
            "user_agent": user_agent,
            "prefix_version": prefix_version,
        }
        try:
            response = self._table().insert(payload).execute()
        except Exception as exc:  # noqa: BLE001 - transport/upstream -> 502
            logger.warning("staff_sessions insert failed", extra={"error_type": type(exc).__name__})
            raise _store_unavailable() from exc
        rows = self._rows(response)
        parsed = _row_to_session(rows[0]) if rows else None
        if parsed is None:
            raise _store_unavailable()
        # The absolute/idle lifetimes live in config, not on the row
        # (plan §2 schema has no columns for them); stamp the values
        # this session was issued under onto the returned shape.
        return _replace(parsed, absolute_hours=absolute_hours, idle_minutes=idle_minutes)

    def get_session(self, session_id: UUID) -> StaffSession | None:
        try:
            response = self._table().select("*").eq("id", str(session_id)).execute()
        except Exception as exc:  # noqa: BLE001 - transport/upstream -> not found
            logger.warning("staff_sessions select failed", extra={"error_type": type(exc).__name__})
            return None
        rows = self._rows(response)
        return _row_to_session(rows[0]) if rows else None

    def touch_session(self, session_id: UUID, now: datetime) -> StaffSession | None:
        try:
            response = (
                self._table()
                .update({"last_seen_at": now.isoformat()})
                .eq("id", str(session_id))
                .is_("revoked_at", "null")
                .execute()
            )
        except Exception as exc:  # noqa: BLE001 - transport/upstream -> not found
            logger.warning("staff_sessions touch failed", extra={"error_type": type(exc).__name__})
            return None
        rows = self._rows(response)
        return _row_to_session(rows[0]) if rows else None

    def revoke_session(self, session_id: UUID, now: datetime) -> bool:
        try:
            response = (
                self._table()
                .update({"revoked_at": now.isoformat()})
                .eq("id", str(session_id))
                .is_("revoked_at", "null")
                .execute()
            )
        except Exception as exc:  # noqa: BLE001 - transport/upstream -> False
            logger.warning("staff_sessions revoke failed", extra={"error_type": type(exc).__name__})
            return False
        return len(self._rows(response)) > 0

    def revoke_all_for_user(self, user_id: UUID, now: datetime) -> int:
        try:
            response = (
                self._table()
                .update({"revoked_at": now.isoformat()})
                .eq("user_id", str(user_id))
                .is_("revoked_at", "null")
                .execute()
            )
        except Exception as exc:  # noqa: BLE001 - transport/upstream -> 0
            logger.warning(
                "staff_sessions revoke-all failed",
                extra={"error_type": type(exc).__name__},
            )
            return 0
        return len(self._rows(response))

    def list_sessions_for_user(self, user_id: UUID) -> list[StaffSession]:
        try:
            response = (
                self._table()
                .select("*")
                .eq("user_id", str(user_id))
                .is_("revoked_at", "null")
                .order("last_seen_at", desc=True)
                .execute()
            )
        except Exception as exc:  # noqa: BLE001 - transport/upstream -> empty
            logger.warning("staff_sessions list failed", extra={"error_type": type(exc).__name__})
            return []
        parsed = [_row_to_session(row) for row in self._rows(response)]
        return [session for session in parsed if session is not None]

    def mark_step_up_verified(self, session_id: UUID, now: datetime) -> StaffSession | None:
        try:
            response = (
                self._table()
                .update({"step_up_verified_at": now.isoformat()})
                .eq("id", str(session_id))
                .is_("revoked_at", "null")
                .execute()
            )
        except Exception as exc:  # noqa: BLE001 - e.g. column missing -> 502
            logger.warning(
                "staff_sessions step-up mark failed",
                extra={"error_type": type(exc).__name__},
            )
            raise _store_unavailable() from exc
        rows = self._rows(response)
        return _row_to_session(rows[0]) if rows else None


# ---------------------------------------------------------------------------
# Session manager (the layer Child C's router calls)
# ---------------------------------------------------------------------------


class SessionManager:
    """Issue / validate / revoke staff sessions per the locked rules.

    - ``issue`` only after MFA has verified (the caller proves that;
      this class never mints a session from a password alone).
    - ``validate`` enforces, in order: exists, not revoked, prefix
      version current, absolute lifetime, idle window — then slides
      the idle window (``last_seen_at = now``). Every failure is the
      same generic 401; the specific reason is logged server-side
      only (no session id in the log line).
    - ``clock`` and ``current_prefix_version`` are injectable so tests
      can move time and rotate the prefix deterministically.
    """

    def __init__(
        self,
        store: StaffSessionStore,
        *,
        app_settings: Settings | None = None,
        absolute_hours: int | None = None,
        idle_minutes: int | None = None,
        current_prefix_version: int | Callable[[], int] = 1,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        resolved = app_settings or settings
        self._store = store
        self._absolute_hours = (
            absolute_hours if absolute_hours is not None else resolved.staff_session_absolute_hours
        )
        self._idle_minutes = (
            idle_minutes if idle_minutes is not None else resolved.staff_session_idle_minutes
        )
        self._current_prefix_version = current_prefix_version
        self._clock = clock or _now
        self._step_up_mfa = resolved.staff_step_up_mfa

    def _now(self) -> datetime:
        return self._clock()

    def _current_version(self) -> int:
        version = self._current_prefix_version
        return version() if callable(version) else version

    def _absolute_expires_at(self, session: StaffSession) -> datetime:
        """Absolute expiry under the CURRENT configured lifetime."""
        return session.issued_at + timedelta(hours=self._absolute_hours)

    def _idle_expires_at(self, session: StaffSession) -> datetime:
        """Idle expiry under the CURRENT configured idle window."""
        return session.last_seen_at + timedelta(minutes=self._idle_minutes)

    def issue(
        self,
        user_id: UUID,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
        prefix_version: int | None = None,
    ) -> StaffSession:
        """Mint a session. Call ONLY after MFA has verified for this
        sign-in — a session is the proof that password + TOTP both
        passed, and there is no trusted-device bypass."""
        current = self._current_version()
        version = prefix_version if prefix_version is not None else current
        return self._store.create_session(
            user_id,
            now=self._now(),
            ip=ip,
            user_agent=user_agent,
            prefix_version=version,
            absolute_hours=self._absolute_hours,
            idle_minutes=self._idle_minutes,
        )

    def validate(self, session_id: UUID, *, now: datetime | None = None) -> StaffSession:
        """Validate a session id (opaque token) and slide its idle
        window. Returns the live session; raises the generic 401 on
        any failure (unknown, revoked, stale prefix, absolute-expired,
        idle-expired)."""
        at = now or self._now()
        session = self._store.get_session(session_id)
        if session is None:
            logger.warning("staff session validation failed", extra={"reason": "unknown"})
            raise _unauthorized()
        reason: str | None = None
        if session.revoked_at is not None:
            reason = "revoked"
        elif session.prefix_version != self._current_version():
            # C3 fix: `!=`, not `<`. A session stamped with a NEWER
            # version than current (clock/replica skew, or a version
            # that was rolled back) is just as dead as an older one —
            # only the CURRENT version validates. (With `<`, a
            # restart that reset the counter to 1 resurrected every
            # rotated-out session.)
            reason = "stale_prefix_version"
        elif at >= self._absolute_expires_at(session):
            reason = "absolute_expired"
        elif at >= self._idle_expires_at(session):
            reason = "idle_expired"
        if reason is not None:
            logger.warning("staff session validation failed", extra={"reason": reason})
            raise _unauthorized()
        touched = self._store.touch_session(session_id, at)
        if touched is None:
            logger.warning("staff session validation failed", extra={"reason": "touch_failed"})
            raise _unauthorized()
        return touched

    def revoke(self, session_id: UUID, *, now: datetime | None = None) -> bool:
        """Revoke one session (logout). True when a live session died;
        False when it was already gone/revoked (logout is idempotent)."""
        return self._store.revoke_session(session_id, now or self._now())

    def revoke_all_for_user(self, user_id: UUID, *, now: datetime | None = None) -> int:
        """Revoke every live session of a user — suspend/delete and
        force-sign-out. Returns the number revoked."""
        return self._store.revoke_all_for_user(user_id, now or self._now())

    def list_active_sessions(
        self, user_id: UUID, *, now: datetime | None = None
    ) -> list[StaffSession]:
        """The user's live sessions (non-revoked, within absolute +
        idle lifetimes) — the /admin/security "active sessions" view.

        N9: stale-prefix sessions are filtered out here too — a
        rotated-out session is not "active" even before its next
        validate call kills it."""
        at = now or self._now()
        current_version = self._current_version()
        return [
            session
            for session in self._store.list_sessions_for_user(user_id)
            if session.prefix_version == current_version
            and at < self._absolute_expires_at(session)
            and at < self._idle_expires_at(session)
        ]

    def mark_step_up_verified(
        self, session_id: UUID, *, now: datetime | None = None
    ) -> StaffSession:
        """Mark a session step-up-verified after a fresh MFA check
        (Founder gate). Validates the session first — a dead session
        cannot be stepped up. The caller performs the MFA verify
        (``MfaService.verify_step_up``) BEFORE calling this."""
        at = now or self._now()
        self.validate(session_id, now=at)
        marked = self._store.mark_step_up_verified(session_id, at)
        if marked is None:
            logger.warning("staff session step-up mark failed", extra={"reason": "gone"})
            raise _unauthorized()
        return marked

    def is_step_up_verified(self, session: StaffSession) -> bool:
        """True when the session has passed a fresh MFA check."""
        return session.step_up_verified_at is not None

    def step_up_required(self, session: StaffSession) -> bool:
        """True when the Founder gate needs a fresh MFA check for this
        session: the ``STAFF_STEP_UP_MFA`` flag is on (default ON) and
        the session has not been stepped up yet."""
        return bool(self._step_up_mfa) and not self.is_step_up_verified(session)


# ---------------------------------------------------------------------------
# Default wiring (Child C's router uses this unless it injects its own)
# ---------------------------------------------------------------------------

_in_memory_store: InMemoryStaffSessionStore | None = None


def default_session_store(app_settings: Settings | None = None) -> StaffSessionStore:
    """The production session store when Supabase is configured, else
    the process-wide in-memory store (dev/tests)."""
    resolved = app_settings or settings
    if resolved.supabase_configured:
        return SupabaseStaffSessionStore(resolved)
    global _in_memory_store
    if _in_memory_store is None:
        _in_memory_store = InMemoryStaffSessionStore()
    return _in_memory_store


def get_session_manager(
    store: StaffSessionStore | None = None,
    *,
    app_settings: Settings | None = None,
) -> SessionManager:
    """A SessionManager on the default store (override the store in tests)."""
    return SessionManager(store or default_session_store(app_settings), app_settings=app_settings)
