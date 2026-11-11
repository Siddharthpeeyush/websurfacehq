"""Proxy-safe HTTP clients for the Supabase SDK (live-proof fix F1).

Root cause (evidence ``/tmp/live-proof/evidence.md`` §0a): this VM's stock
``no_proxy``/``NO_PROXY`` contains bracketed IPv6 entries (``[::1]``,
``[fd8b:...]``). ``httpx`` turns ``[::1]`` into the proxy mount
``all://*[::1]``, whose port ``:1]`` fails URL parsing, so a plain
``httpx.Client()`` raises ``InvalidURL`` — and ``supabase-py`` builds one
inside ``create_client`` (GoTrue auth client), killing every Supabase call.

Two layers, both applied:

(a) Every supabase-py client is built with a prebuilt
    ``httpx.Client(trust_env=False)`` via ``SyncClientOptions.httpx_client``
    (supabase-py 2.18.0: ``create_client(url, key, options)`` where
    ``options: SyncClientOptions`` carries ``httpx_client``; the same client
    is handed to the auth, PostgREST, storage and functions sub-clients).
    ``trust_env=False`` makes httpx ignore the environment entirely, so no
    malformed proxy entry can ever break client construction again.

    Deliberate deviation from a bare ``httpx.Client(trust_env=False)``:
    on this VM ``trust_env=False`` ALSO drops the egress proxy and the
    ``SSL_CERT_FILE`` CA bundle (httpx only honours ``SSL_CERT_FILE`` when
    ``trust_env`` is true — see ``httpx/_config.py``), and direct egress is
    blocked here, so a bare client constructs fine but can never reach
    Supabase live (verified 11 Nov 2026: direct ``ConnectError``; explicit
    proxy without the CA ``CERTIFICATE_VERIFY_FAILED``). This helper
    therefore re-applies the operator's explicit proxy (``https_proxy``,
    falling back to ``http_proxy`` / ``all_proxy`` when no ``https_proxy``
    is set — F-L6) and CA bundle (``SSL_CERT_FILE``) when — and only when — they are
    configured, and never disables certificate verification. On Render (no
    proxy/CA env) this is exactly a bare ``trust_env=False`` direct client.
    Assumption (unproven): production Render is unaffected by this VM-only
    proxy issue.

(b) ``sanitize_no_proxy_env()`` strips bracketed entries from
    ``NO_PROXY``/``no_proxy`` at launch (``app/main.py``) and again inside
    ``create_supabase_client`` (entry points that never import ``main``,
    e.g. workers). Other entries and ``http(s)_proxy`` are untouched.

No async variant: the API uses sync supabase-py only (no ``AsyncClient`` /
``create_async_client`` anywhere under ``app/``).
"""

from __future__ import annotations

import inspect
import logging
import os
import ssl
from typing import TYPE_CHECKING

import httpx
from supabase.lib.client_options import SyncClientOptions

logger = logging.getLogger("websurfacehq.http")

if TYPE_CHECKING:
    from supabase import Client

__all__ = [
    "create_supabase_client",
    "proxy_safe_httpx_client",
    "proxy_safe_supabase_options",
    "sanitize_no_proxy_env",
]

# Shared-client timeout: supabase-py used to build one httpx client per
# sub-client (PostgREST 120s, storage 20s, GoTrue httpx default 5s); a
# single prebuilt client cannot preserve all three, so the loosest prior
# bound wins — a tighter timeout would newly fail slow PostgREST queries.
# PostgREST passes no per-request timeout, so this value is the effective
# timeout for store traffic.
_SHARED_CLIENT_TIMEOUT_SECONDS = 120.0


def sanitize_no_proxy_env() -> dict[str, list[str]]:
    """Strip bracketed IPv6 entries from ``NO_PROXY``/``no_proxy``.

    Entries starting with ``[`` (``[::1]``, ``[fd8b:...]``, ``[::1]:8080``)
    are what break httpx's proxy-mount parsing; bare entries (``::1``,
    ``localhost``, hostnames) parse fine and are kept, as are
    ``http_proxy``/``https_proxy`` (never touched here). Idempotent: a
    second call removes nothing. Returns ``{var: [removed entries]}``.
    """
    removed: dict[str, list[str]] = {}
    for name in ("NO_PROXY", "no_proxy"):
        raw = os.environ.get(name)
        if not raw:
            continue
        entries = [entry.strip() for entry in raw.split(",")]
        dropped = [entry for entry in entries if entry.startswith("[")]
        if not dropped:
            continue
        kept = [entry for entry in entries if entry and not entry.startswith("[")]
        removed[name] = dropped
        os.environ[name] = ",".join(kept)
    return removed


def _proxy_from_env() -> str | None:
    """The operator's explicit egress proxy, if one is configured.

    Only read — never logged: proxy URLs can carry credentials. Returns
    ``None`` when no proxy is configured (direct connection, e.g. Render).

    Precedence mirrors httpx's own env handling: ``https_proxy`` first
    (F-L6 — previously the only source, so an ``http_proxy``-only setup
    silently went direct and failed on this VM), then ``http_proxy``,
    then ``all_proxy``. The returned URL is validated once here: a
    malformed value raises a clear ``ValueError`` at client construction
    instead of surfacing later as an obscure httpx ``InvalidURL`` (or
    silently going direct). Both failure modes are fail-closed and loud.
    """
    for name in (
        "https_proxy",
        "HTTPS_PROXY",
        "http_proxy",
        "HTTP_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ):
        value = os.environ.get(name)
        if not value:
            continue
        try:
            parsed = httpx.URL(value)
        except httpx.InvalidURL as exc:
            raise ValueError(f"invalid proxy URL in {name}: {exc}") from exc
        if parsed.scheme not in ("http", "https") or not parsed.host:
            raise ValueError(f"invalid proxy URL in {name}: expected an http:// or https:// URL")
        return value
    return None


def _ssl_context_from_env() -> ssl.SSLContext | None:
    """An SSL context trusting the operator's CA bundle (``SSL_CERT_FILE``).

    This is the bundle the intercepting egress proxy's certificate chains
    to on this VM; without it a ``trust_env=False`` client cannot verify
    the proxy. ``None`` means "httpx default" (certifi). Built as a
    context (not a bare path) because httpx deprecates ``verify=<str>``.
    """
    value = os.environ.get("SSL_CERT_FILE")
    if value and os.path.isfile(value):
        return ssl.create_default_context(cafile=value)
    return None


def proxy_safe_httpx_client(timeout: float = _SHARED_CLIENT_TIMEOUT_SECONDS) -> httpx.Client:
    """Build an httpx client that never chokes on the process proxy env.

    ``trust_env=False`` ignores the (possibly malformed) proxy env for
    parsing; the operator's explicit proxy and CA bundle are re-applied
    from the environment (see module docstring) so live traffic still
    routes correctly where a proxy is required. Certificate verification
    is never disabled.
    """
    return httpx.Client(
        trust_env=False,
        proxy=_proxy_from_env(),
        verify=_ssl_context_from_env() or True,
        timeout=timeout,
    )


def proxy_safe_supabase_options() -> SyncClientOptions:
    """``SyncClientOptions`` carrying the proxy-safe httpx client."""
    return SyncClientOptions(httpx_client=proxy_safe_httpx_client())


def create_supabase_client(url: str, key: str) -> Client:
    """Create a supabase-py client whose transport ignores the proxy env.

    Passes a prebuilt ``httpx.Client(trust_env=False)`` via
    ``SyncClientOptions.httpx_client`` (verified against supabase-py
    2.18.0: ``create_client(url, key, options: SyncClientOptions | None)``;
    the sub-clients all receive ``options.httpx_client``). Also sanitizes
    ``NO_PROXY``/``no_proxy`` first, for any other httpx client built in
    this process.

    The ``create_client`` binding is resolved lazily (inside the function)
    and the ``options`` keyword is passed only when the resolved callable
    accepts it: the existing tests patch ``supabase.create_client`` /
    ``app.auth.provider.create_client`` with two-argument fakes
    (``lambda url, key: ...``), and those fakes must keep working — the
    real ``create_client`` always accepts ``options``, so production always
    takes the proxy-safe path.
    """
    sanitize_no_proxy_env()
    from supabase import create_client

    try:
        parameters = inspect.signature(create_client).parameters
    except (TypeError, ValueError):
        # Cannot introspect the binding: fall back to the plain call, but
        # LOUDLY (F-L5). A silent fallback here would rebuild exactly the
        # F1 failure mode (no proxy-safe client) with no trace. Not
        # raised: the existing tests patch create_client with 2-arg
        # fakes, and raising would break them.
        logger.warning(
            "create_supabase_client: could not inspect create_client signature; "
            "falling back to create_client(url, key) without the proxy-safe client"
        )
        return create_client(url, key)
    accepts_options = "options" in parameters or any(
        param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters.values()
    )
    if accepts_options:
        return create_client(url, key, options=proxy_safe_supabase_options())
    logger.warning(
        "create_supabase_client: create_client does not accept options; "
        "falling back to create_client(url, key) without the proxy-safe client"
    )
    return create_client(url, key)
