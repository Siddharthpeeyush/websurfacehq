"""Tests for the pinned-IP transport (Week 2).

The transport is exercised against a local HTTP server on 127.0.0.1,
with the SSRF guard's resolution patched to return the loopback
address (the real guard blocks loopback by design — that block is
tested unpatched below). The server records the Host header it saw,
proving the request was addressed to the checked IP while still
carrying the hostname.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest

from app.core.ssrf import UnsafeUrlError
from app.workers.pinned_http import pinned_get

BIG_BODY = b"x" * 70000  # over the 64 KiB cap


class _Handler(BaseHTTPRequestHandler):
    seen_hosts: list[str] = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # silence test output
        pass

    def do_GET(self) -> None:
        type(self).seen_hosts.append(self.headers.get("Host", ""))
        if self.path == "/app.js":
            body = b"const x = 1;\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/chunked.js":
            body = b"chunk-one-chunk-two"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(body), body))
            self.wfile.write(b"0\r\n\r\n")
        elif self.path == "/big.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(BIG_BODY)))
            self.end_headers()
            self.wfile.write(BIG_BODY)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture()
def _local_server() -> Any:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture()
def _pinned_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the transport's resolution at the local test server.

    The SSRF guard itself is bypassed here on purpose: the test's
    point is the transport mechanics (connect to the checked IP, send
    the hostname), not the guard — the guard is covered unpatched
    below and by test_ssrf.py.
    """
    monkeypatch.setattr("app.workers.pinned_http.assert_url_safe", lambda url: None)
    monkeypatch.setattr("app.workers.pinned_http.resolve_all", lambda host: ["127.0.0.1"])
    # The transport's own check would (correctly) reject loopback — the
    # test's point is the transport mechanics, so the check is bypassed
    # here too; the guard is covered unpatched below and by test_ssrf.py.
    monkeypatch.setattr("app.workers.pinned_http.check_resolved_ips", lambda ips: None)


def test_pinned_get_sends_hostname_as_host_header(
    _local_server: int, _pinned_to_loopback: None
) -> None:
    _Handler.seen_hosts.clear()
    response = pinned_get(f"http://example.test:{_local_server}/app.js")
    assert response.status_code == 200
    assert response.content == b"const x = 1;\n"
    # Connected to 127.0.0.1, but the request carried the hostname.
    assert _Handler.seen_hosts == ["example.test"]


def test_pinned_get_reads_chunked_bodies(_local_server: int, _pinned_to_loopback: None) -> None:
    response = pinned_get(f"http://example.test:{_local_server}/chunked.js")
    assert response.status_code == 200
    assert response.content == b"chunk-one-chunk-two"


def test_pinned_get_rejects_over_cap_body(_local_server: int, _pinned_to_loopback: None) -> None:
    with pytest.raises(UnsafeUrlError, match="exceeds 65536 bytes"):
        pinned_get(f"http://example.test:{_local_server}/big.js")


def test_pinned_get_returns_404_without_following_redirects(
    _local_server: int, _pinned_to_loopback: None
) -> None:
    response = pinned_get(f"http://example.test:{_local_server}/missing.js")
    assert response.status_code == 404


def test_pinned_get_blocks_loopback_host_unpatched() -> None:
    # The real guard runs: a loopback URL never reaches the transport.
    with pytest.raises(UnsafeUrlError):
        pinned_get("http://127.0.0.1:9/app.js")


def test_pinned_get_blocks_unresolvable_host() -> None:
    with pytest.raises(UnsafeUrlError):
        pinned_get("http://nonexistent.invalid/app.js")


def test_pinned_get_connect_error_is_httpx_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A refused connection surfaces as an httpx error, not a raw socket
    # error — callers catch httpx.HTTPError. The socket is faked so the
    # test does not depend on live egress behaviour.
    monkeypatch.setattr("app.workers.pinned_http.assert_url_safe", lambda url: None)
    monkeypatch.setattr("app.workers.pinned_http.resolve_all", lambda host: ["93.184.216.34"])

    def _refused(*args: object, **kwargs: object) -> object:
        raise OSError("Connection refused")

    monkeypatch.setattr("socket.create_connection", _refused)
    with pytest.raises(httpx.ConnectError):
        pinned_get("http://example.com:9/app.js", timeout=2.0)
