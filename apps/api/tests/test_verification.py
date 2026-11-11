"""Verification service tests. Network is NEVER touched: the DNS resolver
and the HTTP fetcher are both mocked.
"""

import hashlib

import dns.resolver
import pytest

from app.services import verification


def test_token_entropy_two_tokens_differ() -> None:
    t1 = verification.generate_verification_token()
    t2 = verification.generate_verification_token()
    assert t1 != t2
    # 32 random bytes -> token_urlsafe gives 43 URL-safe chars, no padding.
    assert len(t1) == 43 and len(t2) == 43
    assert all(c.isalnum() or c in "-_" for c in t1)
    # Hashing is deterministic and never returns the raw token.
    assert verification.hash_token(t1) == hashlib.sha256(t1.encode()).hexdigest()
    assert t1 not in verification.hash_token(t1)


class _FakeRdata:
    def __init__(self, *parts: bytes) -> None:
        self.strings = parts


def _fake_resolve(records: dict[str, list[_FakeRdata]]) -> object:
    def _resolve(domain: str, rdtype: str, **kwargs: object) -> list[_FakeRdata]:
        if domain in records:
            return records[domain]
        raise Exception("NXDOMAIN")

    return _resolve


def test_verify_dns_txt_exact_match(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "tok-abc-123"
    records = {
        "example.com": [_FakeRdata(b"websurfacehq-verify=" + token.encode())],
    }
    monkeypatch.setattr(dns.resolver, "resolve", _fake_resolve(records))
    assert verification.verify_dns_txt("example.com", token) is True
    assert verification.verify_dns_txt("example.com", "wrong-token") is False
    assert verification.verify_dns_txt("other.com", token) is False


def test_verify_dns_txt_split_strings_joined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A TXT record split across two strings must still match.
    token = "split-token"
    records = {
        "example.com": [
            _FakeRdata(b"websurfacehq-verify=split-", b"token"),
        ],
    }
    monkeypatch.setattr(dns.resolver, "resolve", _fake_resolve(records))
    assert verification.verify_dns_txt("example.com", token) is True


def test_verify_dns_txt_wrong_prefix_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The blueprint's old `scan-verify=` prefix must NOT verify.
    records = {"example.com": [_FakeRdata(b"scan-verify=tok-abc-123")]}
    monkeypatch.setattr(dns.resolver, "resolve", _fake_resolve(records))
    assert verification.verify_dns_txt("example.com", "tok-abc-123") is False


class _FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def test_verify_well_known_file_exact_trimmed_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "file-token-1"

    def _fake_safe_get(url: str, timeout: float = 10.0) -> _FakeResponse:
        assert url == "https://example.com/.well-known/scan-verify.txt"
        assert url.startswith("https://")  # HTTPS only, no http fallback
        return _FakeResponse(200, f"  {token}\n")

    monkeypatch.setattr(verification, "safe_get", _fake_safe_get)
    assert verification.verify_well_known_file("example.com", token) is True
    assert verification.verify_well_known_file("example.com", "other") is False


def test_verify_well_known_file_non_200_is_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(verification, "safe_get", lambda url, timeout=10.0: _FakeResponse(404, ""))
    assert verification.verify_well_known_file("example.com", "x") is False


def test_verify_well_known_file_ssrf_block_is_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.ssrf import UnsafeUrlError

    def _blocked(url: str, timeout: float = 10.0) -> _FakeResponse:
        raise UnsafeUrlError("blocked")

    monkeypatch.setattr(verification, "safe_get", _blocked)
    assert verification.verify_well_known_file("localhost", "x") is False


def test_check_verification_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        verification,
        "fetch_dns_txt_value",
        lambda domain: "tok" if domain == "example.com" else None,
    )
    monkeypatch.setattr(
        verification,
        "fetch_well_known_value",
        lambda domain: "tok" if domain == "example.com" else None,
    )
    assert verification.check_verification("example.com", "tok", "dns") is True
    assert verification.check_verification("example.com", "tok", "file") is True
    assert verification.check_verification("example.com", "nope", "dns") is False
    with pytest.raises(ValueError):
        verification.check_verification("example.com", "tok", "meta")


def test_check_verification_hash_against_stored_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "hash-token-9"
    stored = verification.hash_token(token)
    monkeypatch.setattr(verification, "fetch_dns_txt_value", lambda domain: token)
    matched, published = verification.check_verification_hash("example.com", stored, "dns")
    assert (matched, published) == (True, True)
    # Wrong published value: present, but not matching.
    monkeypatch.setattr(verification, "fetch_dns_txt_value", lambda domain: "someone-elses-token")
    matched, published = verification.check_verification_hash("example.com", stored, "dns")
    assert (matched, published) == (False, True)
    # Nothing published at all.
    monkeypatch.setattr(verification, "fetch_dns_txt_value", lambda domain: None)
    matched, published = verification.check_verification_hash("example.com", stored, "dns")
    assert (matched, published) == (False, False)
    with pytest.raises(ValueError):
        verification.check_verification_hash("example.com", stored, "meta")


def test_check_verification_hash_with_no_stored_hash_never_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Round-3 review, Low: a target with no stored hash (inserted directly,
    # never issued a token) used to crash verify with TypeError inside
    # hmac.compare_digest. It must answer (False, True) — something was
    # published, but it cannot match — never a 500.
    monkeypatch.setattr(
        verification, "fetch_dns_txt_value", lambda domain: "someone-published-a-value"
    )
    assert verification.check_verification_hash("example.com", None, "dns") == (
        False,
        True,
    )
    # Nothing published at all: still (False, False).
    monkeypatch.setattr(verification, "fetch_dns_txt_value", lambda domain: None)
    assert verification.check_verification_hash("example.com", None, "dns") == (
        False,
        False,
    )
