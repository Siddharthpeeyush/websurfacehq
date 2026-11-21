"""Append-only audit writer for staff/admin actions.

Every admin action writes one row via :func:`write` — (actor, action,
target, before/after, IP, timestamp) — into ``audit_logs``. This module
is the ONLY writer of admin audit rows, and it exposes NO update or
delete function: audit history is append-only by design (migration
0007 enforces it in the database with a trigger + REVOKEs, and this
module enforces it in code by never offering a mutation path).

Row shape (the frozen 0001 schema — no new columns): ``user_id`` is
the actor, ``action`` is the dotted action name (``admin.users.suspend``),
``target_domain`` carries a domain target when the target IS a domain,
and everything else rides in ``metadata`` (JSON): ``before`` / ``after``
snapshots, the caller's IP, and a SHA-256 hash of a UUID target (never
the raw id — same rule as ``app.auth.permissions``).

Caller contract — read before calling ``write()``:
* Never pass secrets, tokens, or passwords in ``target`` / ``before`` /
  ``after``. UUIDs nested inside ``before`` / ``after`` are the caller's
  responsibility to hash or omit; only a top-level UUID ``target`` is
  hashed here.
* ``before`` / ``after`` must be JSON-serializable (the Supabase store
  inserts them as JSON); a non-serializable snapshot raises
  ``ValueError`` here, fast, instead of failing inside the store.
* Failure is LOUD: if the store write raises, ``write()`` propagates
  it — an unaudited admin action must never fail silently. Callers
  (Child D's admin router) write the audit row AFTER the mutation
  succeeds and treat an audit failure as a 500; the mutation and its
  audit row are not atomic (the store protocol has no transaction),
  so a failed audit after a successful mutation leaves a real action
  with no audit row — visible in the error log, reconcilable, and far
  better than a silently missing row. Do NOT wrap ``write()`` in a
  try/except that swallows the error.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any
from uuid import UUID

from app.db.store import AuditLog

__all__ = ["write"]


def _is_uuid_like(value: str) -> bool:
    """True when ``value`` parses as a UUID (a bare id, not a domain)."""
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _check_json_serializable(name: str, value: Any) -> None:
    """Fail fast on a snapshot the store could never insert as JSON."""
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"audit {name} is not JSON-serializable: {exc}") from exc


def write(
    actor: UUID,
    action: str,
    target: str | UUID | None = None,
    before: Any | None = None,
    after: Any | None = None,
    ip: str | None = None,
) -> AuditLog:
    """Write one append-only audit row. Returns the stored row.

    Args:
        actor: The acting staff user's id (``staff_roles.user_id``).
        action: Dotted action name, e.g. ``"admin.users.suspend"``.
        target: What the action acted on. A domain string is stored
            as ``target_domain``; a UUID (or a UUID-shaped string) is
            stored only as its SHA-256 hash in ``metadata``
            (``target_id_hash``) — the raw id never lands in the log.
            ``None`` when the action has no target.
        before / after: JSON-serializable snapshots of the affected
            state (already redacted by the caller — see the module
            docstring). Omitted from ``metadata`` when ``None``.
        ip: The caller's IP, stored in ``metadata`` (the frozen
            schema has no ip column). Omitted when ``None``.

    Raises:
        ValueError: empty ``action``, or a non-JSON-serializable
            ``before`` / ``after``.
        Exception: any store failure propagates (loud, by design).
    """
    if not action or not action.strip():
        raise ValueError("audit action must be a non-empty string")
    metadata: dict[str, Any] = {}
    target_domain: str | None = None
    if target is not None:
        target_text = str(target)
        if isinstance(target, UUID) or _is_uuid_like(target_text):
            metadata["target_id_hash"] = hashlib.sha256(target_text.encode("utf-8")).hexdigest()
        else:
            target_domain = target_text
    if before is not None:
        _check_json_serializable("before", before)
        metadata["before"] = before
    if after is not None:
        _check_json_serializable("after", after)
        metadata["after"] = after
    if ip is not None:
        metadata["ip"] = ip

    # Lazy import (same pattern as app.auth.permissions): the store is
    # built in parallel to this module; importing it here keeps this
    # module importable before the store lands.
    from app.db import get_store

    return get_store().log_audit(
        user_id=actor,
        action=action,
        target_domain=target_domain,
        metadata=metadata,
    )
