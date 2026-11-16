"""JS secret scanner tests (Week 2 recon).

Redaction rule for this file: fixtures are SYNTHETIC fake secrets only,
built programmatically (hash-derived fragments / split literals) so that no
real-looking secret literal sits in source — the CI secrets job scans this
file. Every test that uses a fixture secret asserts the full secret string
appears NOWHERE in the scanner output.
"""

import base64
import hashlib
import json

from app.services.js_secrets import (
    MAX_CONTENT_BYTES,
    redact_value,
    scan_js,
    shannon_entropy,
)

URL = "https://example.com/static/app.js"


# ---------------------------------------------------------------------------
# Synthetic fixture builders (deterministic, hash-derived — never real keys)
# ---------------------------------------------------------------------------


def _b64(label: str, length: int = 40) -> str:
    """High-entropy base64 string derived from a label (not a real secret)."""
    digest = base64.b64encode(hashlib.sha256(label.encode()).digest()).decode()
    return digest[:length]


def _hex(label: str, length: int = 36) -> str:
    """Hex string derived from a label (not a real secret)."""
    return hashlib.sha256(label.encode()).hexdigest()[:length]


def _aws_access_key() -> str:
    # AKIA + 16 chars, split so the full token never appears as one literal.
    return "AKIA" + "IOSF" + "ODNN" + "7XKC" + "D2EF"


def _aws_example_key() -> str:
    # The AWS-documented example key, same split treatment.
    return "AKIA" + "IOSF" + "ODNN" + "7EXAMPLE"


def _jwt() -> str:
    """A jwt.io-shaped token built from public header/payload JSON."""

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(
        json.dumps({"sub": "test-user", "iat": 1516239022}, separators=(",", ":")).encode()
    )
    signature = _b64url(hashlib.sha256(b"jwt-fixture-signature").digest())
    return f"{header}.{payload}.{signature}"


def _assert_redacted(findings: list[dict[str, object]], secrets: list[str]) -> None:
    """No fixture secret appears in full in any returned dict, and no
    redacted snippet holds more than 8 contiguous chars of any secret."""
    joined = " ".join(str(value) for f in findings for value in f.values())
    for secret in secrets:
        assert secret not in joined
        for finding in findings:
            snippet = str(finding["redacted_snippet"])
            assert secret not in snippet
            # No 9-char window of the secret may appear in the snippet:
            # redaction keeps at most first-4 + last-4 (8 chars, split).
            for start in range(len(secret) - 8):
                assert secret[start : start + 9] not in snippet


def _keys(findings: list[dict[str, object]]) -> set[str]:
    return {str(f["pattern_name"]) for f in findings}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_shannon_entropy_basics() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("password123") < 4.5
    assert shannon_entropy(_b64("api-key-fixture")) > 4.5


def test_redact_value() -> None:
    assert redact_value("short") == "[redacted]"
    assert redact_value("12345678") == "[redacted]"
    assert redact_value("abcdefghij") == "abcd...ghij"
    assert redact_value(_b64("api-key-fixture")).count("...") == 1


# ---------------------------------------------------------------------------
# Every pattern fires on a synthetic fixture
# ---------------------------------------------------------------------------


def test_aws_access_key_fires() -> None:
    secret = _aws_access_key()
    findings = scan_js(f'const key = "{secret}";', URL)
    assert _keys(findings) == {"aws_access_key"}
    assert findings[0]["severity"] == "high"
    assert findings[0]["confidence"] == "high"
    assert findings[0]["line"] == 1
    assert findings[0]["url"] == URL
    _assert_redacted(findings, [secret])


def test_aws_example_key_fires_at_low_confidence() -> None:
    # The AWS-documented example key still fires (it is the documented
    # synthetic fixture style) but is downgraded: it is not a live secret.
    secret = _aws_example_key()
    findings = scan_js(f'const key = "{secret}";', URL)
    assert _keys(findings) == {"aws_access_key"}
    assert findings[0]["confidence"] == "low"
    assert findings[0]["severity"] == "medium"
    _assert_redacted(findings, [secret])


def test_aws_secret_key_fires() -> None:
    secret = _b64("aws-secret-fixture")
    assert shannon_entropy(secret) > 4.5
    findings = scan_js(f'aws_secret_access_key = "{secret}"', URL)
    assert _keys(findings) == {"aws_secret_key"}
    assert findings[0]["severity"] == "high"
    _assert_redacted(findings, [secret])


def test_aws_docs_example_secret_downgraded() -> None:
    # AWS docs example secret (contains EXAMPLE): fires, low confidence.
    # Assembled from parts on a separate line: no key-assignment literal
    # in source (the CI secret scanner flags that shape); value unchanged.
    parts = ["wJalrXUtnFEMI/", "K7MDENG/bPxRfiCY", "EXAMPLEKEY"]
    secret = "".join(parts)
    assert len(secret) == 40
    assert shannon_entropy(secret) > 4.5
    findings = scan_js(f'aws_secret_access_key = "{secret}"', URL)
    assert _keys(findings) == {"aws_secret_key"}
    assert findings[0]["confidence"] == "low"
    _assert_redacted(findings, [secret])


def test_generic_api_key_fires() -> None:
    secret = _b64("api-key-fixture")
    findings = scan_js(f'const api_key = "{secret}";', URL)
    assert _keys(findings) == {"generic_api_key"}
    assert findings[0]["confidence"] == "medium"
    _assert_redacted(findings, [secret])


def test_bearer_token_fires() -> None:
    secret = _b64("bearer-fixture", 44)
    findings = scan_js(f"Authorization: Bearer {secret}", URL)
    assert _keys(findings) == {"bearer_token"}
    _assert_redacted(findings, [secret])


def test_github_token_fires() -> None:
    secret = "ghp_" + _hex("github-fixture", 36)
    findings = scan_js(f'const token = "{secret}";', URL)
    assert _keys(findings) == {"github_token"}
    assert findings[0]["severity"] == "high"
    _assert_redacted(findings, [secret])


def test_github_pat_fires() -> None:
    secret = "github_pat_" + _hex("github-pat-fixture", 22)
    findings = scan_js(f'const token = "{secret}";', URL)
    assert _keys(findings) == {"github_token"}
    _assert_redacted(findings, [secret])


def test_slack_token_fires() -> None:
    secret = "xoxb-" + _hex("slack-fixture", 24)
    findings = scan_js(f'const token = "{secret}";', URL)
    assert _keys(findings) == {"slack_token"}
    _assert_redacted(findings, [secret])


def test_stripe_live_key_fires() -> None:
    secret = "sk_live_" + _hex("stripe-fixture", 24)
    findings = scan_js(f'const key = "{secret}";', URL)
    assert _keys(findings) == {"stripe_live_key"}
    assert findings[0]["severity"] == "high"
    _assert_redacted(findings, [secret])


def test_private_key_fires() -> None:
    # PEM markers built at runtime so the literal header never appears in
    # source (the CI secret scanner flags the literal); the scanned content
    # is identical.
    begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
    end = "-----END " + "RSA PRIVATE KEY-----"
    content = begin + "\n" + "A" * 64 + "\n" + end
    findings = scan_js(content, URL)
    assert _keys(findings) == {"private_key"}
    assert findings[0]["severity"] == "high"
    assert "PRIVATE KEY" in str(findings[0]["redacted_snippet"])
    # The snippet holds no key material at all.
    assert "A" * 9 not in str(findings[0]["redacted_snippet"])


def test_jwt_fires() -> None:
    secret = _jwt()
    findings = scan_js(f'const token = "{secret}";', URL)
    assert _keys(findings) == {"jwt"}
    _assert_redacted(findings, [secret])


def test_google_api_key_fires() -> None:
    secret = "AIza" + _hex("google-fixture", 35)
    findings = scan_js(f'const key = "{secret}";', URL)
    assert _keys(findings) == {"google_api_key"}
    _assert_redacted(findings, [secret])


def test_database_url_fires() -> None:
    password = _b64("db-fixture", 24)
    url = f"postgres://app_user:{password}@db.example.com:5432/appdb"
    findings = scan_js(f'const dsn = "{url}";', URL)
    assert _keys(findings) == {"database_url"}
    assert findings[0]["severity"] == "high"
    assert str(findings[0]["redacted_snippet"]) == "postgres://[redacted]"
    # The scheme is public context, not secret material: the redaction
    # assertion covers the password; the full URL must still be absent.
    joined = " ".join(str(v) for f in findings for v in f.values())
    assert url not in joined
    _assert_redacted(findings, [password])


def test_mongodb_srv_url_fires() -> None:
    password = _b64("mongo-fixture", 24)
    url = f"mongodb+srv://app_user:{password}@cluster.example.net/appdb"
    findings = scan_js(f'const dsn = "{url}";', URL)
    assert _keys(findings) == {"database_url"}
    joined = " ".join(str(v) for f in findings for v in f.values())
    assert url not in joined
    _assert_redacted(findings, [password])


def test_generic_password_fires() -> None:
    secret = _b64("password-fixture", 32)
    assert shannon_entropy(secret) > 4.5
    findings = scan_js(f'password = "{secret}"', URL)
    assert _keys(findings) == {"generic_password"}
    _assert_redacted(findings, [secret])


# ---------------------------------------------------------------------------
# Entropy threshold + context scoring
# ---------------------------------------------------------------------------


def test_low_entropy_password_does_not_flag() -> None:
    # "password123" is below the 4.5 entropy gate for the generic path.
    assert shannon_entropy("password123") < 4.5
    assert scan_js('password = "password123"', URL) == []


def test_low_entropy_api_key_does_not_flag() -> None:
    # Built via a variable so no key-assignment literal sits in source (the
    # CI secret scanner flags that shape); the scanned snippet is identical.
    low = "my-test-api-key-123"
    assert scan_js(f'api_key = "{low}"', URL) == []


def test_high_entropy_api_key_flags() -> None:
    secret = _b64("api-key-fixture")
    assert shannon_entropy(secret) > 4.5
    findings = scan_js(f'api_key = "{secret}"', URL)
    assert len(findings) == 1
    assert findings[0]["pattern_name"] == "generic_api_key"


def test_placeholder_api_key_does_not_flag() -> None:
    # High entropy AND a placeholder marker: the placeholder rule (not
    # the entropy gate) must be what suppresses this — proven by the
    # entropy assertion.
    secret = "test" + _b64("api-key-fixture", 36)
    assert shannon_entropy(secret) > 4.5
    assert scan_js(f'api_key = "{secret}"', URL) == []


def test_placeholder_password_does_not_flag() -> None:
    secret = "changeme" + _b64("password-fixture", 32)
    assert shannon_entropy(secret) > 4.5
    assert scan_js(f'password = "{secret}"', URL) == []


def test_plain_placeholder_values_do_not_flag() -> None:
    assert scan_js('api_key = "your-api-key-here"', URL) == []
    assert scan_js('password = "changeme"', URL) == []
    assert scan_js('api_key = "TODO"', URL) == []


def test_service_context_raises_confidence() -> None:
    secret = _b64("api-key-fixture")
    plain = scan_js(f'const api_key = "{secret}";', URL)
    assert plain[0]["confidence"] == "medium"
    named = scan_js(f'const api_key = "{secret}"; // stripe secret', URL)
    assert named[0]["confidence"] == "high"
    assert named[0]["pattern_name"] == "generic_api_key"
    _assert_redacted(named, [secret])


def test_bearer_jwt_reported_as_jwt_only() -> None:
    # A JWT after "Bearer" is one jwt finding, not a bearer_token too.
    secret = _jwt()
    findings = scan_js(f"Authorization: Bearer {secret}", URL)
    assert _keys(findings) == {"jwt"}
    _assert_redacted(findings, [secret])


# ---------------------------------------------------------------------------
# Shape, dedupe, caps, line numbers
# ---------------------------------------------------------------------------


def test_finding_shape_exact_keys() -> None:
    secret = _b64("api-key-fixture")
    findings = scan_js(f'api_key = "{secret}"', URL)
    assert len(findings) == 1
    assert set(findings[0]) == {
        "pattern_name",
        "url",
        "line",
        "redacted_snippet",
        "entropy",
        "confidence",
        "severity",
    }
    assert findings[0]["confidence"] in ("high", "medium", "low")
    assert findings[0]["severity"] in ("high", "medium", "low", "info")


def test_line_numbers_are_one_based() -> None:
    secret = _b64("api-key-fixture")
    content = "// line one\n// line two\n" + f'api_key = "{secret}"\n'
    findings = scan_js(content, URL)
    assert [f["line"] for f in findings] == [3]


def test_empty_content_returns_no_findings() -> None:
    assert scan_js("", URL) == []
    assert scan_js("// just a comment, nothing here\n", URL) == []


def test_same_pattern_same_line_deduped() -> None:
    first = "ghp_" + _hex("github-one", 36)
    second = "ghp_" + _hex("github-two", 36)
    findings = scan_js(f'const a = "{first}"; const b = "{second}";', URL)
    assert len(findings) == 1
    assert findings[0]["pattern_name"] == "github_token"


def test_input_over_2mib_raises() -> None:
    import pytest

    with pytest.raises(ValueError, match="exceeds"):
        scan_js("x" * (MAX_CONTENT_BYTES + 1), URL)


def test_input_at_2mib_cap_passes() -> None:
    assert scan_js("x" * MAX_CONTENT_BYTES, URL) == []


def test_max_200_findings_per_file() -> None:
    lines = [f'const t{i} = "ghp_' + _hex(f"github-{i}", 36) + '";' for i in range(250)]
    findings = scan_js("\n".join(lines), URL)
    assert len(findings) == 200


# ---------------------------------------------------------------------------
# M10 review fix: line numbers from precomputed offsets (bisect), not a
# per-match rescan of the file
# ---------------------------------------------------------------------------


def test_line_numbers_correct_on_large_multiline_file() -> None:
    """M10 regression: identical line numbers to the naive per-match
    ``count("\\n")`` algorithm on a large multi-line file — the
    precomputed-offset change must not move any finding."""
    secret_early = _b64("large-file-early")
    secret_late = _b64("large-file-second")
    lines = [f"// filler line {index}" for index in range(5000)]
    lines[10] = f'api_key = "{secret_early}"'
    lines[4990] = f'api_key = "{secret_late}"'
    content = "\n".join(lines)
    findings = scan_js(content, URL)
    assert len(findings) == 2
    assert [str(f["pattern_name"]) for f in findings] == [
        "generic_api_key",
        "generic_api_key",
    ]
    assert [f["line"] for f in findings] == [11, 4991]
    # Cross-check each finding against the naive algorithm directly.
    for finding, secret in zip(findings, [secret_early, secret_late]):
        offset = content.index(secret)
        assert finding["line"] == content.count("\n", 0, offset) + 1
        _assert_redacted([finding], [secret])
