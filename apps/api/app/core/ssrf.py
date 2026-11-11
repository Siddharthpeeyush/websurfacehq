"""SSRF guard — every outbound fetch the API or worker makes goes through
here first (docs/threat-model.md §3.4, blueprint §0.2).

Blocked, before any connection is attempted:

- IPv4 private / loopback / link-local ranges: ``10/8``, ``172.16/12``,
  ``192.168/16``, ``127/8``, ``169.254/16`` (incl. cloud metadata
  ``169.254.169.254``), ``0/8``.
- Hostnames: ``localhost`` (and ``*.localhost``), ``*.local``,
  ``*.internal``, ``metadata.google.internal``.
- IPv6 private / special ranges: ``fc00::/7`` (unique-local), ``fe80::/10``
  (link-local), ``::1`` (loopback), ``::`` (unspecified) — the blueprint
  lists IPv4 only; the IPv6 gap is closed here per threat-model §3.4.
- DNS rebinding: the hostname is resolved TWICE and both resolutions are
  checked; a second resolution that introduces a private IP is rejected.

TOCTOU honesty note: ``safe_get`` resolves + checks immediately before
connecting, but between the check and the TCP connect the DNS answer can
still change (a rebinding attack in that window is not fully excluded).
Fully rebinding-proof fetching needs a transport pinned to the checked IP
(address the socket to the resolved IP and send the hostname in Host/SNI),
which lands with the worker's httpx stage in Week 2. This module does not
pretend otherwise — it closes the cheap, common SSRF paths, not the
race-window one.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

BLOCKED_HOST_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".localhost",
    ".internal",
    ".metadata.google.internal",
)
BLOCKED_HOSTS: frozenset[str] = frozenset({"localhost", "metadata.google.internal"})


class UnsafeUrlError(ValueError):
    """Raised when a URL fails the SSRF checks. The message names the
    reason (private IP, blocked suffix, unresolvable host) but never
    echoes credentials or a full URL with userinfo."""


def _unwrap_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse an IP literal, unwrapping IPv4-mapped IPv6 (``::ffff:127.0.0.1``
    is 127.0.0.1 and must be blocked as such)."""
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def check_resolved_ips(ips: list[str]) -> None:
    """Reject if ANY resolved IP is not a globally routable public address.

    ``is_global`` is False for private, loopback, link-local, reserved,
    multicast and unspecified addresses — exactly the set that must never
    be fetched. Raises :class:`UnsafeUrlError` naming the offending IP.
    """
    for raw in ips:
        try:
            ip = _unwrap_ip(raw)
        except ValueError as exc:
            raise UnsafeUrlError(f"Unparseable resolved IP: {raw!r}") from exc
        if not ip.is_global:
            raise UnsafeUrlError(f"Resolved IP {raw} is not a public address ({ip})")


def resolve_all(host: str) -> list[str]:
    """Resolve ``host`` to every A/AAAA address (deduplicated, order kept).

    Uses the system resolver (``/etc/hosts`` included, so ``localhost``
    resolves even without DNS). Raises UnsafeUrlError when the host does
    not resolve at all — fail closed.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Cannot resolve host: {host}") from exc
    seen: list[str] = []
    for info in infos:
        sockaddr = info[4]
        ip = str(sockaddr[0])
        if ip not in seen:
            seen.append(ip)
    if not seen:
        raise UnsafeUrlError(f"Cannot resolve host: {host}")
    return seen


def _check_hostname(host: str) -> None:
    """Blocklist on the hostname itself, before any DNS lookup."""
    host = host.lower().rstrip(".")
    if host in BLOCKED_HOSTS:
        raise UnsafeUrlError(f"Blocked hostname: {host}")
    if any(host.endswith(suffix) for suffix in BLOCKED_HOST_SUFFIXES):
        raise UnsafeUrlError(f"Blocked hostname suffix: {host}")
    try:
        ip = _unwrap_ip(host)
    except ValueError:
        return  # Not an IP literal — DNS checks below apply instead.
    if not ip.is_global:
        raise UnsafeUrlError(f"Blocked IP literal: {host}")


def assert_url_safe(url: str) -> None:
    """Raise UnsafeUrlError unless ``url`` is safe to fetch.

    Checks, in order: http(s) scheme only, no userinfo, hostname blocklist,
    IP-literal check, first DNS resolution checked, second DNS resolution
    checked (rebinding: the second set must not introduce a private IP).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeUrlError(f"Blocked URL scheme: {parsed.scheme or '(none)'}")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeUrlError("URLs with userinfo are not allowed")
    host = parsed.hostname
    if not host:
        raise UnsafeUrlError("URL has no hostname")
    _check_hostname(host)
    # Resolution 1: every address must be public.
    first = resolve_all(host)
    check_resolved_ips(first)
    # Resolution 2 (DNS-rebinding check): the answer must not flip to a
    # private IP between lookups. Legitimate round-robin answers that stay
    # public are allowed; only a private introduction is rejected.
    second = resolve_all(host)
    check_resolved_ips(second)


def safe_get(url: str, timeout: float = 10.0, max_bytes: int = 65536) -> httpx.Response:
    """An httpx GET that runs :func:`assert_url_safe` immediately before
    connecting. Redirects are NOT followed — a redirect target is a new
    URL that has not been checked, so a 3xx is returned to the caller
    instead of being followed.

    The body is streamed with a hard cap (M5 review fix): a target serving
    a multi-GB ``/.well-known/scan-verify.txt`` must not OOM the worker —
    the token is 43 characters, so anything over ``max_bytes`` (default
    64 KiB) is rejected before it is read in full. A lying Content-Length
    is caught by the same cap while streaming.

    ``trust_env=False``: the fetch goes DIRECT to the target, never via a
    proxy from the environment. A proxy would route the request through
    the proxy's network (defeating the SSRF checks) and, in this VM, the
    proxy env itself breaks httpx's URL parsing. Week 2's httpx stages
    must use the same setting.

    TOCTOU: see the module docstring — the check-then-connect window is
    not fully rebinding-proof; a pinned-IP transport lands in Week 2.
    """
    assert_url_safe(url)
    with httpx.stream(
        "GET", url, timeout=timeout, follow_redirects=False, trust_env=False
    ) as response:
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                # Unparseable Content-Length: the stream cap below applies.
                declared = None
            # The raise is OUTSIDE the try: UnsafeUrlError subclasses
            # ValueError, so raising inside the try would be swallowed by
            # the except above (round-2 review finding — the pre-check was
            # dead code until this fix).
            if declared is not None and declared > max_bytes:
                raise UnsafeUrlError(f"Response body exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise UnsafeUrlError(f"Response body exceeds {max_bytes} bytes")
            chunks.append(chunk)
        body = b"".join(chunks)
    return httpx.Response(
        response.status_code, content=body, headers=response.headers, request=response.request
    )
