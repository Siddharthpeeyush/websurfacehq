"""Secret staff-address prefix enforcement (two-door scheme).

Locked design (DESIGN-LOCK.md, "Secret staff address", 15 Nov 2026):
the whole staff site lives under a secret random path prefix on the
staff subdomain — ``admin.websurfacehq.com/<secret>/...``. Everything
outside the prefix on that subdomain answers a generic 404. The prefix
is a 128-bit random value, generated once at setup, stored in server
config only — never in the repo, never in docs, never in logs, and never
echoed in any error response (the 404 below names no prefix).

Enforcement rules implemented here:

- When ``STAFF_URL_PREFIX`` is empty, enforcement is OFF (local dev
  only — production refuses to start without it; that fail-fast check
  lives in Child B's ``config.py`` and is in place).
- When the request Host is the staff host (``STAFF_HOST``, default
  ``admin.websurfacehq.com``) AND a prefix is configured, the path must
  be exactly ``/<prefix>`` or start with ``/<prefix>/``; anything else
  is a generic 404 (``NOT_FOUND`` / "Resource not found" — the same
  body the API returns for any missing resource, so a probe cannot
  tell "wrong prefix" from "no such page").
- HOST GATE (M3 fix, 20 Nov 2026; allowlist fix, 20 Nov 2026):
  the API itself rejects staff paths unless the Host is one of the
  allowed hosts — the staff web host (``STAFF_HOST``), the API's
  OWN public host (``API_PUBLIC_HOST`` and/or the host parsed from
  ``API_PUBLIC_URL``), or localhost in dev only. The API host MUST
  be allowed: the Host header arriving at the API is ALWAYS the
  API origin — the web middleware proxies staff calls with
  ``Host: <API origin>`` (the staff web host arrives only as
  X-Forwarded-Host, which the API deliberately does not trust,
  and direct clients address the API by its own hostname too —
  the original staff-host-only gate 404d EVERY staff API call in
  production, proxied and direct alike. The primary doors remain
  the web middleware (browser) + the secret prefix + the staff
  session; the API host gate is a secondary check that still
  rejects unexpected hosts (e.g. the customer host).
- When the Host is anything else (the customer site), the prefix
  dependency passes — the customer host never serves staff routes
  (Child E's middleware owns that side); the prefix only gates the
  staff door. The host gate (``require_staff_host``) is the check
  that refuses the customer host on staff mounts.

Wiring note for Child D (``app/main.py``): the staff routers must be
mounted UNDER the prefix, e.g.
``app.include_router(staff_auth.router, prefix=f"/{prefix}")`` so the
login path is ``/<prefix>/staff/auth/login`` (the router already
carries ``prefix="/staff/auth"``; the mount adds the secret segment in
front). If the router is mounted with no prefix in the path, every
staff request 404s in production while working in dev (prefix empty) —
the prefix unit tests pin the path rule so that mistake is caught.

Prefix rotation (Owner-only, Child D's ``POST /admin/settings/
rotate-prefix``) bumps the version; staff sessions created under an
older version are dead (Child B's ``SessionManager.validate``
enforces the version check). The version counter is PERSISTED in
migration 0007's ``admin_settings`` table (key ``prefix_version``,
C3 fix, 20 Nov 2026) — a process-local counter reset to 1 on every
restart, resurrecting rotated-out sessions, and replicas diverged.
This module reads/writes the counter through the store
(``Store.get/bump_prefix_version``); the module-global below is
only a fallback when the store is unavailable (fail-safe: a stale
read can only keep the OLD version, never invent a new one — a
rotation that fails to persist is loud in the logs and the
rotate-prefix endpoint reports it).
"""

from __future__ import annotations

import os
import re
import threading
from urllib.parse import urlparse

from fastapi import Request

from app.core.errors import ApiError
from app.core.logging import logger

# NOTE: this module does NOT import app.core.config at module level:
# config.py's prod validator imports staff_url_prefix_is_strong from
# here while the Settings class is still being constructed, so a
# top-level config import would cycle (config -> staff_prefix ->
# config, with `settings` not yet defined). Settings are imported
# lazily inside the functions that need them.

_STAFF_HOST_ENV = "STAFF_HOST"
_DEFAULT_STAFF_HOST = "admin.websurfacehq.com"

_lock = threading.Lock()
_prefix_version = 1


def get_staff_host() -> str:
    """The staff subdomain (env ``STAFF_HOST``; default ``admin.websurfacehq.com``)."""
    return os.environ.get(_STAFF_HOST_ENV, _DEFAULT_STAFF_HOST).strip().lower()


def get_staff_url_prefix() -> str:
    """The secret path prefix (``settings.staff_url_prefix``), or ``""`` when unset.

    The value comes from Child B's config (env ``STAFF_URL_PREFIX``) —
    never logged, never returned, never echoed in an error.
    Surrounding slashes are stripped so ``/abc123/`` and ``abc123``
    behave identically. Production refuses to start without it
    (``config.py`` fail-fast); empty means enforcement OFF, local dev
    only.
    """
    from app.core.config import settings

    return settings.staff_url_prefix.strip().strip("/")


def _store_prefix_version() -> int | None:
    """The persisted prefix version from the store, or None when the
    store is unavailable (the caller falls back to the module global
    and logs loudly — a stale read is fail-safe, never fail-open to a
    NEW version)."""
    try:
        from app.db import get_store

        return get_store().get_prefix_version()
    except Exception:  # noqa: BLE001 - fallback is the documented behaviour
        logger.warning("prefix version store read failed; using process-local value")
        return None


def get_prefix_version() -> int:
    """Current prefix version (1 until the first rotation).

    Read from the persisted ``admin_settings`` counter on every call
    — a restart or a second replica sees the same version the
    rotation wrote (C3 fix)."""
    stored = _store_prefix_version()
    if stored is not None:
        return stored
    with _lock:
        return _prefix_version


def bump_prefix_version() -> int:
    """Bump the persisted prefix version (called by prefix rotation).

    Returns the new version. All staff sessions stamped with an older
    version become invalid immediately. The store write is the
    source of truth; the process-local counter is updated to match
    so a store outage still moves the local counter forward.
    """
    global _prefix_version
    try:
        from app.db import get_store

        new_version = get_store().bump_prefix_version()
    except Exception:  # noqa: BLE001 - rotation must not 500 on a store blip
        logger.error("prefix version store bump failed; bumping process-local counter")
        with _lock:
            _prefix_version += 1
            return _prefix_version
    with _lock:
        _prefix_version = new_version
    return new_version


def set_prefix_version(version: int) -> int:
    """Persist a prefix version (tests / reset only). Returns it."""
    global _prefix_version
    try:
        from app.db import get_store

        stored = get_store().set_prefix_version(version)
    except Exception:  # noqa: BLE001 - tests reset the local counter too
        stored = max(version, 1)
    with _lock:
        _prefix_version = stored
    return stored


def is_staff_host(host: str | None) -> bool:
    """True when ``host`` (port stripped, case-insensitive) is the staff host."""
    if not host:
        return False
    return host.strip().lower().split(":")[0] == get_staff_host()


def get_api_public_hosts() -> set[str]:
    """The API's own public host(s) (lowercased, no port).

    Union of ``API_PUBLIC_HOST`` (explicit) and the host parsed
    from ``API_PUBLIC_URL`` when set — either variable alone is
    enough, so an operator who already sets the public URL does
    not also have to set the host. Both are operator-controlled
    server config, never client input. Empty in local dev (no
    public host); localhost is allowed there by the dev rule.
    """
    from app.core.config import settings

    hosts: set[str] = set()
    if settings.api_public_host:
        hosts.add(settings.api_public_host.strip().lower())
    if settings.api_public_url:
        parsed = urlparse(settings.api_public_url)
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    return hosts


def is_api_public_host(host: str | None) -> bool:
    """True when ``host`` is the API's own public host."""
    if not host:
        return False
    return host.strip().lower().split(":")[0] in get_api_public_hosts()


def _is_dev_localhost(host: str | None) -> bool:
    """True for loopback hosts — allowed on staff mounts in local
    dev only (development environment), never in staging/production."""
    from app.core.config import settings

    if not host or settings.environment.value != "development":
        return False
    bare = host.strip().lower().split(":")[0]
    return bare in ("localhost", "127.0.0.1", "::1", "[::1]")


def check_staff_prefix(host: str | None, path: str) -> None:
    """Enforce the prefix rule for one request (pure function, unit-testable).

    Raises:
        ApiError: 404 ``NOT_FOUND`` with the generic "Resource not found"
            message when the request is for the staff host, a prefix is
            configured, and the path is outside it. The message never
            names the prefix or the staff host.
    """
    prefix = get_staff_url_prefix()
    if not prefix:
        return  # Local dev only: enforcement off.
    if not is_staff_host(host):
        return  # Customer host: staff routes are never served here.
    if path == f"/{prefix}" or path.startswith(f"/{prefix}/"):
        return
    raise ApiError(404, "NOT_FOUND", "Resource not found")


async def require_staff_prefix(request: Request) -> None:
    """FastAPI dependency: enforce the prefix rule for staff-door requests.

    Mount on the staff routers (Child D wires it in ``main.py``). When the
    prefix is empty (local dev) this is a no-op.
    """
    host = request.headers.get("host")
    check_staff_prefix(host, request.url.path)


def check_staff_host(host: str | None) -> None:
    """Enforce the API-side host gate for staff mounts (M3 fix;
    allowlist fix 20 Nov 2026).

    The Host must be one of the allowed hosts: exactly the staff
    host (``STAFF_HOST`` env, default ``admin.websurfacehq.com``),
    the API's own public host (``API_PUBLIC_HOST`` / the host of
    ``API_PUBLIC_URL``), or localhost in dev only. The API host is
    on the list because the Host header arriving at the API is
    ALWAYS the API origin — the web proxy forwards with ``Host:
    <API origin>`` and direct clients address the API by its own
    hostname; the staff web host never appears as Host at the API
    (it arrives only as X-Forwarded-Host, which is client-spoofable
    and deliberately unread). Anything else — including the customer
    host presenting the correct secret prefix — is the generic 404,
    so a probe cannot tell "wrong host" from "no such page". The
    check is exact: no suffix/prefix matching, so
    ``evil-admin.websurfacehq.com`` and
    ``admin.websurfacehq.com.evil.example`` both fail.
    """
    if is_staff_host(host) or is_api_public_host(host) or _is_dev_localhost(host):
        return
    raise ApiError(404, "NOT_FOUND", "Resource not found")


async def require_staff_host(request: Request) -> None:
    """FastAPI dependency: enforce the host gate for staff-door requests.

    Mounted alongside ``require_staff_prefix`` on the staff routers
    (``main.py``). When the prefix is empty (local dev) the prefix
    guard is off, but the host gate still applies — a customer host
    must never reach the staff API, even in dev.
    """
    check_staff_host(request.headers.get("host"))


def reset_prefix_version_for_tests() -> None:
    """Reset the prefix version to 1 (tests only) — persisted AND local."""
    set_prefix_version(1)


# --- Prefix entropy (N9) -------------------------------------------------
# Minimum entropy for STAFF_URL_PREFIX, enforced by config.py's prod
# fail-fast (not here — this module only defines the rule so the
# config validator and the tests share one constant).
MIN_STAFF_URL_PREFIX_LENGTH = 16
_STAFF_URL_PREFIX_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def staff_url_prefix_is_strong(prefix: str) -> bool:
    """True when a prefix value meets the prod minimum: at least
    16 chars, URL-path-safe charset only (no slashes, dots, or
    spaces — a prefix containing ``/`` would break the mount, and a
    short one is guessable). 16 chars of [A-Za-z0-9_-] is ~95 bits;
    the setup generator issues 128-bit (22 chars) — this is the
    floor, not the target."""
    return len(prefix) >= MIN_STAFF_URL_PREFIX_LENGTH and bool(_STAFF_URL_PREFIX_RE.match(prefix))


__all__: list[str] = [
    "MIN_STAFF_URL_PREFIX_LENGTH",
    "bump_prefix_version",
    "check_staff_host",
    "check_staff_prefix",
    "get_api_public_hosts",
    "get_prefix_version",
    "get_staff_host",
    "get_staff_url_prefix",
    "is_api_public_host",
    "is_staff_host",
    "require_staff_host",
    "require_staff_prefix",
    "reset_prefix_version_for_tests",
    "set_prefix_version",
    "staff_url_prefix_is_strong",
]
