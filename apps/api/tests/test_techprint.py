"""Tech fingerprint / TLS summary / probe aggregation tests (Week 2 recon).

All inputs are synthetic httpx-shaped dicts — no network, no live hosts.
"""

from typing import Any

from app.services.techprint import fingerprint, summarize_http_probe, tls_summary


def _cloudflare_nextjs_result() -> dict[str, Any]:
    return {
        "url": "https://example.com/",
        "host": "example.com",
        "ip": "93.184.216.34",
        "status_code": 200,
        "title": "Example Site",
        "tech": ["Next.js", "React", "Vercel"],
        "headers": {
            "Server": "cloudflare",
            "CF-Ray": "abc123",
            "CF-Cache-Status": "HIT",
            "X-Powered-By": "Next.js",
            "Content-Type": "text/html; charset=utf-8",
            "Set-Cookie": "next-auth.session-token=abc; Path=/; HttpOnly",
        },
        "tls": {
            "version": "TLSv1.3",
            "issuer": "Let's Encrypt",
            "not_after": "2027-01-01T00:00:00Z",
            "expired": False,
            "self_signed": False,
        },
        "webserver": "cloudflare",
        "content_type": "text/html; charset=utf-8",
        "body_snippet": '<html><head><meta name="generator" content="Next.js">'
        '<script src="/_next/static/chunks/app.js"></script></head></html>',
    }


def test_fingerprint_cloudflare_nextjs_case() -> None:
    result = fingerprint(_cloudflare_nextjs_result())
    assert result["technologies"] == [
        "Cloudflare",
        "Next.js",
        "NextAuth",
        "React",
        "Vercel",
    ]
    assert result["webserver"] == "cloudflare"
    assert result["tls"]["version"] == "TLS 1.3"
    assert result["tls"]["grade_hint"] == "ok"
    assert result["tls"]["expired"] is False
    assert result["tls"]["self_signed"] is False
    assert result["headers"] == {
        "server": "cloudflare",
        "x_powered_by": "Next.js",
        "content_type": "text/html; charset=utf-8",
    }
    assert result["title"] == "Example Site"
    assert result["status_code"] == 200


def test_fingerprint_realistic_httpx_dict() -> None:
    result = fingerprint(
        {
            "url": "https://example.com/",
            "host": "example.com",
            "status_code": 200,
            "title": "Example",
            "tech": ["WordPress", "PHP"],
            "headers": {
                "Server": "nginx/1.25.4",
                "X-Powered-By": "PHP/8.1.0",
                "Content-Type": "text/html",
                "Set-Cookie": "wordpress_logged_in_abc=1; Path=/",
            },
            "tls": {"version": "tls12"},
            "body_snippet": '<link href="/wp-content/themes/twenty/style.css">',
        }
    )
    assert result["technologies"] == ["Nginx", "PHP", "WordPress"]
    assert result["webserver"] == "nginx/1.25.4"
    assert result["tls"]["version"] == "TLS 1.2"
    assert result["tls"]["grade_hint"] == "ok"
    assert result["headers"]["server"] == "nginx/1.25.4"
    assert result["headers"]["x_powered_by"] == "PHP/8.1.0"
    assert result["headers"]["content_type"] == "text/html"


def test_fingerprint_empty_input() -> None:
    result = fingerprint({})
    assert result == {
        "technologies": [],
        "webserver": None,
        "tls": {
            "version": None,
            "issuer": None,
            "not_after": None,
            "expired": None,
            "self_signed": None,
            "grade_hint": "unknown",
        },
        "headers": {"server": None, "x_powered_by": None, "content_type": None},
        "title": None,
        "status_code": None,
    }


def test_fingerprint_never_invents_technologies() -> None:
    # A title and a status code evidence nothing about the stack.
    result = fingerprint({"title": "Hello", "status_code": 200})
    assert result["technologies"] == []
    assert result["webserver"] is None


def test_fingerprint_header_case_insensitive() -> None:
    result = fingerprint(
        {"headers": {"SERVER": "Apache/2.4.58 (Ubuntu)", "x-powered-by": "Express"}}
    )
    assert "Apache" in result["technologies"]
    assert "Express" in result["technologies"]
    assert result["headers"]["server"] == "Apache/2.4.58 (Ubuntu)"
    assert result["headers"]["x_powered_by"] == "Express"


def test_fingerprint_cookie_and_body_hints() -> None:
    result = fingerprint(
        {
            "headers": {"Set-Cookie": "PHPSESSID=abc; Path=/"},
            "body_snippet": '<meta name="generator" content="WordPress 6.4">',
        }
    )
    assert result["technologies"] == ["PHP", "WordPress"]


def test_fingerprint_status_code_string_coerced() -> None:
    assert fingerprint({"status_code": "404"})["status_code"] == 404
    assert fingerprint({"status_code": "not-a-code"})["status_code"] is None
    assert fingerprint({"status_code": None})["status_code"] is None


def test_tls_summary_none() -> None:
    assert tls_summary(None) == {
        "version": None,
        "issuer": None,
        "not_after": None,
        "expired": None,
        "self_signed": None,
        "grade_hint": "unknown",
    }


def test_tls_summary_expired() -> None:
    summary = tls_summary({"version": "TLS 1.2", "not_after": "2020-01-01T00:00:00Z"})
    assert summary["version"] == "TLS 1.2"
    assert summary["expired"] is True
    assert summary["grade_hint"] == "expired"


def test_tls_summary_self_signed() -> None:
    summary = tls_summary(
        {
            "version": "1.3",
            "issuer": "example.com",
            "subject": "example.com",
            "not_after": "2030-01-01T00:00:00Z",
        }
    )
    assert summary["version"] == "TLS 1.3"
    assert summary["self_signed"] is True
    assert summary["expired"] is False
    assert summary["grade_hint"] == "ok"


def test_tls_summary_weak_version() -> None:
    assert tls_summary({"version": "TLSv1.0"})["grade_hint"] == "weak"
    assert tls_summary({"version": "TLS 1.1"})["grade_hint"] == "weak"
    assert tls_summary({"version": "TLS 1.2"})["grade_hint"] == "ok"
    assert tls_summary({})["grade_hint"] == "unknown"


def test_summarize_http_probe_counts() -> None:
    results: list[dict[str, Any]] = [
        {
            "status_code": 200,
            "tech": ["Nginx"],
            "webserver": "nginx",
            "tls": {"version": "TLS 1.3"},
        },
        {
            "status_code": 404,
            "tech": ["Apache"],
            "headers": {"Server": "Apache/2.4"},
            "tls": {"version": "TLS 1.2"},
        },
        {"url": "https://down.example.com/"},  # no response at all
    ]
    summary = summarize_http_probe(results)
    assert summary["counts"] == {
        "hosts": 3,
        "live": 2,
        "by_status_class": {
            "2xx": 1,
            "3xx": 0,
            "4xx": 1,
            "5xx": 0,
            "no_response": 1,
        },
    }
    assert summary["technologies"] == ["Apache", "Nginx"]
    assert summary["tls_versions"] == ["TLS 1.2", "TLS 1.3"]
    assert summary["webservers"] == ["Apache/2.4", "nginx"]


def test_summarize_http_probe_empty() -> None:
    summary = summarize_http_probe([])
    assert summary["counts"]["hosts"] == 0
    assert summary["counts"]["live"] == 0
    assert summary["counts"]["by_status_class"]["no_response"] == 0
    assert summary["technologies"] == []
    assert summary["tls_versions"] == []
    assert summary["webservers"] == []
