"""Target-ownership verification (DNS TXT or well-known file).

Flow (blueprint §0.1, threat-model §3.3):

1. At target creation the API generates a raw token
   (:func:`generate_verification_token`, min 32 random bytes per the
   recorded Week 1 decision), returns it ONCE, and stores only its SHA-256
   hex (:func:`hash_token`) in ``targets.verification_token_hash``.
2. The user publishes the token as a DNS TXT record
   ``websurfacehq-verify=<token>`` on the bare domain, or as the file
   ``https://<domain>/.well-known/scan-verify.txt`` containing exactly the
   token.
3. Verification compares what is PUBLISHED against the stored hash
   (:func:`check_verification_hash`) — the raw token is never needed again,
   so a database read alone can never leak a live token.

All network calls go through the SSRF guard (``app.core.ssrf``). The
well-known fetch is HTTPS ONLY — no ``http://`` fallback (an http fetch
could be intercepted or redirected to a private host).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import dns.resolver

from app.core.config import settings
from app.core.ssrf import safe_get

DNS_TXT_PREFIX = "websurfacehq-verify="
WELL_KNOWN_PATH = "/.well-known/scan-verify.txt"


def generate_verification_token() -> str:
    """A fresh URL-safe token from ``settings.verification_token_bytes``
    (32) random bytes — 43 characters, returned once, never logged."""
    return secrets.token_urlsafe(settings.verification_token_bytes)


def hash_token(token: str) -> str:
    """SHA-256 hex of a token — the only form ever stored."""
    return hashlib.sha256(token.encode()).hexdigest()


def fetch_dns_txt_value(domain: str) -> str | None:
    """The published ``websurfacehq-verify=`` TXT value for ``domain``,
    or None when no such record exists / DNS fails. TXT strings are
    joined before comparing (a record may be split across strings).
    The lookup has an explicit 5s lifetime (L15 review fix): the default
    resolver has no bound, and a slow resolver could stall the worker."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
    except Exception:
        return None
    for rdata in answers:
        parts = getattr(rdata, "strings", ())
        try:
            value = b"".join(parts).decode()
        except (UnicodeDecodeError, TypeError):
            continue
        if value.startswith(DNS_TXT_PREFIX):
            return value[len(DNS_TXT_PREFIX) :]
    return None


def verify_dns_txt(domain: str, token: str) -> bool:
    """True iff the bare domain publishes exactly
    ``websurfacehq-verify=<token>`` as a TXT record."""
    published = fetch_dns_txt_value(domain)
    if published is None:
        return False
    return hmac.compare_digest(published, token)


def fetch_well_known_value(domain: str) -> str | None:
    """The trimmed body of ``https://<domain>/.well-known/scan-verify.txt``,
    or None when the fetch fails / is not a 200 / is SSRF-unsafe."""
    url = f"https://{domain}{WELL_KNOWN_PATH}"
    try:
        response = safe_get(url, timeout=10.0)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    return response.text.strip()


def verify_well_known_file(domain: str, token: str) -> bool:
    """True iff the well-known file exists over HTTPS and its trimmed body
    is exactly ``token``. HTTP fallback is NOT allowed."""
    published = fetch_well_known_value(domain)
    if published is None:
        return False
    return hmac.compare_digest(published, token)


def check_verification(domain: str, token: str, method: str) -> bool:
    """Dispatch on method (``'dns'`` | ``'file'``). Raises ValueError on an
    unknown method."""
    if method == "dns":
        return verify_dns_txt(domain, token)
    if method == "file":
        return verify_well_known_file(domain, token)
    raise ValueError(f"Unknown verification method: {method!r}")


def check_verification_hash(domain: str, token_hash: str | None, method: str) -> tuple[bool, bool]:
    """Verify against the STORED hash (the router path — the raw token is
    gone by verification time). Returns ``(matched, published_present)``:
    ``matched`` is True when the published value hashes to ``token_hash``;
    ``published_present`` says whether anything was published at all, so
    the API can tell the user "nothing found" vs "wrong value" without
    ever echoing the expected token. Raises ValueError on unknown method.

    A target with no stored hash (e.g. inserted directly, never issued
    a token) can never match — return (False, True) when something was
    published instead of crashing in ``hmac.compare_digest`` (round-3
    review, Low: NULL-hash verify was an unhandled 500).
    """
    if method == "dns":
        published = fetch_dns_txt_value(domain)
    elif method == "file":
        published = fetch_well_known_value(domain)
    else:
        raise ValueError(f"Unknown verification method: {method!r}")
    if published is None:
        return False, False
    if token_hash is None:
        return False, True
    matched = hmac.compare_digest(hash_token(published), token_hash)
    return matched, True
