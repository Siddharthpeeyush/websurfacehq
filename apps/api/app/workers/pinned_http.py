"""Pinned-IP HTTP GET for the worker's JS fetches (Week 2).

Closes the TOCTOU / DNS-rebinding window the ``ssrf.py`` docstring is
honest about: :func:`pinned_get` resolves the hostname ONCE, checks every
resolved address with :func:`app.core.ssrf.check_resolved_ips`, then
connects the socket to that checked IP — while still sending the
hostname in the ``Host`` header and as the TLS SNI / certificate name.
A DNS answer that flips between the check and the connect can no
longer redirect the request to a private host, because the connection
never re-resolves the name.

Implementation note: httpx cannot do this — its transports derive the
connect address AND the TLS server name from the URL host, with no
per-request override. So the transport here is stdlib ``socket`` +
``ssl`` with a small hand-rolled HTTP/1.1 reader (status line, headers,
``Content-Length`` / chunked bodies, hard byte cap). Only GET, no
redirects followed (a 3xx is returned to the caller, like
``safe_get``), no proxy — a proxy would re-resolve the hostname itself
and defeat the pinning, so pinned fetches always go direct. On this
VM direct egress is blocked (egress proxy only), so a live pinned fetch
fails here with a connection error; on Render (direct egress) it works.
That environment gap is reported, not hidden.

Scope: only the ``js_secret_scan`` task fetches JS this way. The Go
scanner-agent's own fetches (httpx/katana inside the agent) are NOT
pinned by this module — that is workstream A's side of the contract.
"""

from __future__ import annotations

import socket
import ssl
from typing import BinaryIO

import httpx

from app.core.ssrf import (
    UnsafeUrlError,
    assert_url_safe,
    check_resolved_ips,
    resolve_all,
)

_USER_AGENT = "WebSurfaceHQ-Recon/1.0"


def _read_headers(sock_file: BinaryIO) -> tuple[int, dict[str, str]]:
    """Read the status line + headers from a buffered socket file."""
    status_line = sock_file.readline(65536)
    if not status_line:
        raise httpx.RemoteProtocolError("Empty response from server")
    try:
        status = int(status_line.decode("iso-8859-1").split()[1])
    except (IndexError, ValueError) as exc:
        raise httpx.RemoteProtocolError("Unparseable HTTP status line") from exc
    headers: dict[str, str] = {}
    while True:
        line = sock_file.readline(65536)
        if not line or line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("iso-8859-1")
        if ":" not in decoded:
            raise httpx.RemoteProtocolError("Unparseable HTTP header line")
        name, _, value = decoded.partition(":")
        headers[name.strip().lower()] = value.strip()
    return status, headers


def _read_body(sock_file: BinaryIO, headers: dict[str, str], max_bytes: int) -> bytes:
    """Read the response body honouring Content-Length / chunked, capped.

    Raises :class:`UnsafeUrlError` when the body exceeds ``max_bytes``
    (a lying Content-Length is caught by the same streaming cap).
    """
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    chunks: list[bytes] = []
    total = 0

    def _take(data: bytes) -> None:
        nonlocal total
        total += len(data)
        if total > max_bytes:
            raise UnsafeUrlError(f"Response body exceeds {max_bytes} bytes")
        chunks.append(data)

    if "chunked" in transfer_encoding:
        while True:
            size_line = sock_file.readline(65536).strip()
            try:
                size = int(size_line.split(b";", 1)[0], 16)
            except ValueError as exc:
                raise httpx.RemoteProtocolError("Unparseable chunked size") from exc
            if size == 0:
                # Trailers until the blank line.
                while True:
                    trailer = sock_file.readline(65536)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                break
            remaining = size
            while remaining > 0:
                data = sock_file.read(min(remaining, 65536))
                if not data:
                    raise httpx.RemoteProtocolError("Truncated chunked response")
                _take(data)
                remaining -= len(data)
            sock_file.readline(65536)  # trailing CRLF after the chunk
        return b"".join(chunks)

    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError:
            declared = -1
        if declared > max_bytes:
            raise UnsafeUrlError(f"Response body exceeds {max_bytes} bytes")
        if declared >= 0:
            remaining = declared
            while remaining > 0:
                data = sock_file.read(min(remaining, 65536))
                if not data:
                    raise httpx.RemoteProtocolError("Truncated response body")
                _take(data)
                remaining -= len(data)
            return b"".join(chunks)
    # No length, no chunked: read until the server closes the connection
    # (we sent ``Connection: close``).
    while True:
        data = sock_file.read(65536)
        if not data:
            break
        _take(data)
    return b"".join(chunks)


def pinned_get(url: str, timeout: float = 10.0, max_bytes: int = 65536) -> httpx.Response:
    """GET ``url`` over a connection pinned to a checked IP.

    Steps: :func:`assert_url_safe` (hostname blocklist + double DNS
    resolution, both checked) → resolve once more and check every
    address → connect the socket to the FIRST checked address →
    TLS (when https) with SNI + certificate verification against the
    hostname → send the request with ``Host: <hostname>``.

    Returns an :class:`httpx.Response` (same shape as ``safe_get``) so
    callers can treat the two interchangeably. Redirects are NOT
    followed. Raises :class:`UnsafeUrlError` on any SSRF failure or an
    over-cap body, :class:`httpx.ConnectError` / :class:`httpx.TimeoutException`
    on transport failure.
    """
    from urllib.parse import urlparse

    assert_url_safe(url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    ips = resolve_all(host)
    check_resolved_ips(ips)
    ip = ips[0]

    request = httpx.Request("GET", url)
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        raise httpx.ConnectError(
            f"could not connect to {host} ({ip}): {exc}", request=request
        ) from exc
    try:
        raw.settimeout(timeout)
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            try:
                raw = context.wrap_socket(raw, server_hostname=host)
            except ssl.SSLError as exc:
                raise httpx.ConnectError(
                    f"TLS handshake failed for {host}: {exc}", request=request
                ) from exc
        sock_file = raw.makefile("rb")
        try:
            request_line = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {_USER_AGENT}\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            raw.sendall(request_line.encode("iso-8859-1"))
            status, headers = _read_headers(sock_file)
            body = _read_body(sock_file, headers, max_bytes)
        finally:
            sock_file.close()
    except httpx.HTTPError:
        raise
    except UnsafeUrlError:
        raise
    except (OSError, ssl.SSLError) as exc:
        raise httpx.ConnectError(f"fetch of {host} failed: {exc}", request=request) from exc
    except TimeoutError as exc:
        raise httpx.TimeoutException(f"fetch of {host} timed out", request=request) from exc
    finally:
        raw.close()
    return httpx.Response(status, content=body, headers=headers, request=request)
