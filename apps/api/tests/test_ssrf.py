"""SSRF guard tests (docs/testing.md §4): every blocklist case, IPv6
ranges, the DNS-rebinding flip, and safe_get going through the guard.
The real network is NEVER touched — ``resolve_all`` is mocked, except
the non-standard-IP-literal tests (local getaddrinfo only, no network)
and the oversize-body test (a local loopback HTTP server).
"""

from typing import Any

import httpx
import pytest

from app.core import ssrf
from app.core.ssrf import UnsafeUrlError, assert_url_safe, check_resolved_ips


def _public(monkeypatch: pytest.MonkeyPatch, ips: list[str] | None = None) -> None:
    monkeypatch.setattr(ssrf, "resolve_all", lambda host: list(ips or ["93.184.216.34"]))


def test_blocks_ipv4_private_ranges(monkeypatch: pytest.MonkeyPatch) -> None:
    # Literal IPs never reach DNS; the literal check must fire.
    for url in [
        "http://10.0.0.5/",
        "http://10.255.255.255/admin",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.1/",
        "http://127.0.0.1/",
        "http://127.1.2.3:8080/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
    ]:
        with pytest.raises(UnsafeUrlError):
            assert_url_safe(url)


def test_blocks_localhost_and_private_suffixes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _public(monkeypatch)
    for url in [
        "http://localhost/",
        "http://localhost:3000/admin",
        "http://foo.local/",
        "http://foo.local:8080/",
        "http://db.internal/",
        "http://something.internal/",
        "http://metadata.google.internal/",
        "http://x.metadata.google.internal/",
    ]:
        with pytest.raises(UnsafeUrlError):
            assert_url_safe(url)


def test_blocks_ipv6_private_ranges(monkeypatch: pytest.MonkeyPatch) -> None:
    for url in [
        "http://[fc00::1]/",
        "http://[fd12:3456::1]/",
        "http://[fe80::1]/",
        "http://[fe80::1ff:fe23:4567:890a]/",
        "http://[::1]/",
        "http://[::]/",
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped loopback
        "http://[::ffff:10.0.0.1]/",  # IPv4-mapped private
    ]:
        with pytest.raises(UnsafeUrlError):
            assert_url_safe(url)


def test_blocks_non_http_schemes_and_userinfo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _public(monkeypatch)
    for url in [
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "http://user:pass@example.com/",
        "https://user@example.com/",
        "not-a-url",
        "http://",
    ]:
        with pytest.raises(UnsafeUrlError):
            assert_url_safe(url)


def test_allows_public_url(monkeypatch: pytest.MonkeyPatch) -> None:
    _public(monkeypatch, ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
    assert_url_safe("https://example.com/")
    assert_url_safe("http://example.com:8080/path?q=1")


def test_resolved_private_ip_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    # A public-looking hostname that resolves to a private IP is blocked.
    monkeypatch.setattr(ssrf, "resolve_all", lambda host: ["10.1.2.3"])
    with pytest.raises(UnsafeUrlError):
        assert_url_safe("https://innocent.example.com/")


def test_check_resolved_ips_direct() -> None:
    check_resolved_ips(["8.8.8.8", "1.1.1.1"])  # no raise
    for bad in [
        ["10.0.0.1"],
        ["172.16.0.1"],
        ["192.168.0.1"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["8.8.8.8", "192.168.1.1"],  # one bad poisons the whole set
        ["fc00::1"],
        ["fe80::1"],
        ["::1"],
        ["::ffff:127.0.0.1"],
        ["not-an-ip"],
    ]:
        with pytest.raises(UnsafeUrlError):
            check_resolved_ips(bad)


def test_dns_rebinding_flip_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    # First resolution public, second flips to private -> blocked.
    calls = {"n": 0}

    def _flip(host: str) -> list[str]:
        calls["n"] += 1
        return ["93.184.216.34"] if calls["n"] == 1 else ["169.254.169.254"]

    monkeypatch.setattr(ssrf, "resolve_all", _flip)
    with pytest.raises(UnsafeUrlError):
        assert_url_safe("https://rebind.example.com/")
    assert calls["n"] == 2


def test_dns_rebinding_stable_public_round_robin_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Two different PUBLIC answers (round-robin) are fine — only a
    # private introduction is rejected.
    answers = iter([["93.184.216.34"], ["151.101.1.140"]])
    monkeypatch.setattr(ssrf, "resolve_all", lambda host: next(answers))
    assert_url_safe("https://example.com/")


def test_unresolvable_host_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(host: str) -> list[str]:
        raise UnsafeUrlError("Cannot resolve host: nope.invalid")

    monkeypatch.setattr(ssrf, "resolve_all", _fail)
    with pytest.raises(UnsafeUrlError):
        assert_url_safe("https://nope.invalid/")


def test_safe_get_checks_before_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class _FakeStream:
        """Minimal stand-in for httpx's streaming response (context manager)."""

        def __init__(self, url: str) -> None:
            self.url = url
            self.status_code = 200
            self.headers: dict[str, str] = {}
            self.request = httpx.Request("GET", url)

        def __enter__(self) -> "_FakeStream":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def iter_bytes(self) -> Any:
            yield b"ok"

    def _fake_stream(method: str, url: str, **kwargs: Any) -> _FakeStream:
        calls.append(url)
        assert method == "GET"
        assert kwargs.get("follow_redirects") is False  # redirects are never followed
        return _FakeStream(url)

    monkeypatch.setattr(httpx, "stream", _fake_stream)
    _public(monkeypatch)
    resp = ssrf.safe_get("https://example.com/.well-known/scan-verify.txt")
    assert resp.status_code == 200
    assert resp.text == "ok"
    assert calls == ["https://example.com/.well-known/scan-verify.txt"]
    # Unsafe URL: httpx.stream is never called.
    calls.clear()
    with pytest.raises(UnsafeUrlError):
        ssrf.safe_get("http://169.254.169.254/latest/meta-data/")
    assert calls == []


def test_blocks_nonstandard_ip_literals() -> None:
    """L13 review fix: decimal / hex / octal IP literals must be blocked
    even though ``ipaddress`` does not parse them as literals — the
    resolver (getaddrinfo) turns them into 127.0.0.1, and the resolved-IP
    check must catch that. These tests use the REAL resolver (no mock):
    the literals resolve locally, no network is touched."""
    for literal in ("2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1"):
        with pytest.raises(UnsafeUrlError):
            ssrf.assert_url_safe(f"http://{literal}/")


def test_safe_get_rejects_oversize_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """M5 review fix: a body over the 64 KiB cap is rejected without being
    read in full. The SSRF guard is patched out here (localhost is
    blocked by design) so the test exercises the streaming cap against a
    real local server — the cap logic itself is unmocked."""
    import http.server
    import threading

    big_body = b"x" * (128 * 1024)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib name
            # No Content-Length: the streaming cap (not the header check)
            # must catch this.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(big_body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr(ssrf, "assert_url_safe", lambda url: None)
        with pytest.raises(UnsafeUrlError, match="exceeds"):
            ssrf.safe_get(f"http://127.0.0.1:{server.server_port}/", max_bytes=65536)
        # A small body passes through the same path.
        resp = ssrf.safe_get(f"http://127.0.0.1:{server.server_port}/", max_bytes=1024 * 1024)
        assert resp.status_code == 200
        assert len(resp.content) == len(big_body)
    finally:
        server.shutdown()
        server.server_close()


def test_safe_get_rejects_lying_content_length(monkeypatch: pytest.MonkeyPatch) -> None:
    """Round-2 review: the Content-Length pre-check used to be dead code —
    UnsafeUrlError subclasses ValueError, so raising it inside the try
    was swallowed by its own except. A server claiming 1 MB but sending
    10 bytes must be rejected by the pre-check (UnsafeUrlError), not by
    a protocol error from the stream loop."""
    import http.server
    import threading

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib name
            self.send_response(200)
            self.send_header("Content-Length", "1000000")
            self.end_headers()
            self.wfile.write(b"tiny-body!")

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr(ssrf, "assert_url_safe", lambda url: None)
        with pytest.raises(UnsafeUrlError, match="exceeds"):
            ssrf.safe_get(f"http://127.0.0.1:{server.server_port}/", max_bytes=65536)
    finally:
        server.shutdown()
        server.server_close()
