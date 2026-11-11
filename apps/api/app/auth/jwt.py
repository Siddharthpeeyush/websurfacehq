"""Verify Supabase JWTs (ES256 via the project's JWKS) and represent the authenticated user.

Supabase signs access tokens with ES256 (asymmetric, EC P-256) under the
new JWT Signing Keys. The API verifies each token against the project's
public JWKS (``<supabase_url>/auth/v1/.well-known/jwks.json``), selecting
the key by the token header's ``kid``.

Never accept a token that cannot be verified: a missing ``kid``, an
unknown ``kid``, a non-ES256 ``alg`` (HS256 included — there is NO shared-
secret fallback), a bad signature, an expired token, a non-UUID subject,
a missing or mismatched issuer / audience, or a ``role`` claim that is
present but not ``"authenticated"`` all raise 401 ``UNAUTHORIZED``.
No fallback, no unsigned acceptance, no hand-rolled session.

The JWKS is cached in memory with a TTL and refreshed on an unknown
``kid`` so a key rotation never bricks auth: a token signed by a newly
rotated key triggers exactly one refresh and then verifies. If the fetch
fails, the previously cached keys are still served — but ONLY while the
cache is at most 24 hours old (``_JWKS_STALE_MAX_SECONDS``); an older
cache is discarded and the token 401s. A rotated-away key can therefore
never verify a token more than 24 hours after rotation during a fetch
outage — and in practice the bound is far tighter, because a token's own
``exp`` (Supabase: 3600 s) bounds any token a stale key can verify.
Only a ``kid`` absent from every key set we hold is rejected.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from app.core.config import settings
from app.core.errors import ApiError
from app.core.http import proxy_safe_httpx_client

# How long a fetched JWKS is trusted before the next verification
# re-fetches it. Supabase rotates signing keys rarely (a manual dashboard
# action); 1 hour bounds staleness without a fetch on every request.
_JWKS_TTL_SECONDS = 3600.0
# Maximum age of a cached JWKS that may still be served when a refresh
# fetch FAILS (review fix F-L3). A fetch outage must not let a
# rotated-away key verify tokens indefinitely: beyond this age the
# fallback is refused and verification 401s. 24 hours is generous for
# an outage (Supabase rotation is a manual dashboard action) while
# still a real bound — and the practical risk is negligible anyway,
# because a token's own exp (Supabase: 3600 s) bounds any token a
# stale key can verify.
_JWKS_STALE_MAX_SECONDS = 24 * 3600.0
_JWKS_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class User:
    """An authenticated WebSurfaceHQ account (MVP: exactly one role)."""

    id: uuid.UUID
    email: str
    role: str = "owner"


def _unauthorized() -> ApiError:
    return ApiError(401, "UNAUTHORIZED", "Invalid or expired token")


class _JwksFetchError(Exception):
    """The JWKS could not be fetched or parsed (transport / HTTP / JSON)."""


def _jwks_url() -> str | None:
    """The project's JWKS endpoint, or None when no project is configured."""
    if not settings.supabase_url:
        return None
    return settings.supabase_url.rstrip("/") + "/auth/v1/.well-known/jwks.json"


def _fetch_jwks() -> dict[str, Any]:
    """Fetch the project's JWKS document (one HTTP GET, no retries).

    Uses the shared proxy-safe client (``app/core/http.py``): it ignores
    the (possibly malformed) proxy env for parsing, but re-applies the
    operator's explicit proxy and CA bundle when configured — on this VM
    the egress proxy is required to reach Supabase at all, and a bare
    ``trust_env=False`` client cannot connect (verified 11 Nov 2026).
    On Render (no proxy/CA env) it is exactly a bare direct client.
    """
    url = _jwks_url()
    if url is None:
        raise _JwksFetchError("no supabase_url configured")
    try:
        with proxy_safe_httpx_client(timeout=_JWKS_TIMEOUT_SECONDS) as client:
            response = client.get(url)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise _JwksFetchError(f"JWKS fetch failed: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise _JwksFetchError("JWKS document has no 'keys' list")
    return data


def _index_jwks(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index a JWKS document by ``kid``, keeping only ES256 P-256 keys."""
    keys: dict[str, dict[str, Any]] = {}
    for entry in raw.get("keys", []):
        if not isinstance(entry, dict):
            continue
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        if entry.get("kty") != "EC" or entry.get("crv") != "P-256":
            continue
        alg = entry.get("alg")
        if alg is not None and alg != "ES256":
            continue
        keys[kid] = entry
    return keys


class _JwksCache:
    """In-memory JWKS cache with TTL and refresh on an unknown ``kid``."""

    def __init__(self) -> None:
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def get(self, kid: str) -> dict[str, Any] | None:
        """Return the JWK for ``kid``, refreshing once when it is missing.

        A fresh cache hit needs no fetch. Any other case (stale cache, or
        a ``kid`` the cache has never seen — the rotation case) fetches
        once and re-checks. A failed fetch falls back to the cached keys
        only while the cache is at most 24 hours old
        (``_JWKS_STALE_MAX_SECONDS``); an older cache is refused and the
        lookup returns None, so a transient outage does not 401 every
        authenticated request for a day, but a rotated-away key can never
        verify tokens indefinitely. A ``kid`` absent from every key set
        we hold still returns None.
        """
        with self._lock:
            fresh = bool(self._keys) and (time.monotonic() - self._fetched_at < _JWKS_TTL_SECONDS)
            if fresh and kid in self._keys:
                return self._keys[kid]
        try:
            raw = _fetch_jwks()
        except _JwksFetchError:
            # Fetch failed: serve the cached keys ONLY while the cache is
            # at most _JWKS_STALE_MAX_SECONDS old (F-L3). An older cache
            # is refused — a rotated-away key must not verify tokens
            # indefinitely during a fetch outage.
            with self._lock:
                if self._keys and (time.monotonic() - self._fetched_at <= _JWKS_STALE_MAX_SECONDS):
                    return self._keys.get(kid)
                return None
        with self._lock:
            self._keys = _index_jwks(raw)
            self._fetched_at = time.monotonic()
            return self._keys.get(kid)

    def clear(self) -> None:
        """Drop the cached keys (tests; the next lookup re-fetches)."""
        with self._lock:
            self._keys = {}
            self._fetched_at = 0.0


_JWKS_CACHE = _JwksCache()


def reset_jwks_cache() -> None:
    """Drop the cached JWKS (tests; the next lookup re-fetches)."""
    _JWKS_CACHE.clear()


def verify_token(token: str, *, jwks: dict[str, dict[str, Any]] | None = None) -> User:
    """Verify a Supabase access token and return the ``User`` it names.

    Args:
        token: The raw ``Authorization: Bearer <token>`` value (no scheme).
        jwks: Test-only override: a ``kid`` -> JWK mapping used instead of
            the live JWKS fetch. Production callers never pass this.

    Raises:
        ApiError: 401 ``UNAUTHORIZED`` on any verification failure.
    """
    if not token or not token.strip():
        raise _unauthorized()
    if jwks is None and not settings.supabase_url:
        # No project configured means no JWKS to verify against — reject,
        # never accept an unverifiable token.
        raise _unauthorized()
    try:
        header: dict[str, Any] = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise _unauthorized() from None
    # Only ES256 is accepted. HS256 (or any other alg) is rejected here,
    # before any key lookup — there is no shared-secret fallback.
    if header.get("alg") != "ES256":
        raise _unauthorized()
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise _unauthorized()

    if jwks is not None:
        jwk = jwks.get(kid)
    else:
        jwk = _JWKS_CACHE.get(kid)
    if jwk is None:
        # Unknown kid (after one JWKS refresh inside the cache) — the
        # token was signed by a key this project does not publish.
        raise _unauthorized()

    try:
        loaded_key = ECAlgorithm.from_jwk(json.dumps(jwk))
        # from_jwk can return a private key if the JWK carried "d" (a
        # public JWKS never should); verify with the public half only.
        key = (
            loaded_key.public_key()
            if isinstance(loaded_key, ec.EllipticCurvePrivateKey)
            else loaded_key
        )
        claims: dict[str, Any] = jwt.decode(
            token,
            key,
            algorithms=["ES256"],
            # verify_aud is False here because PyJWT raises when the token
            # carries an aud claim but no expected audience is passed; the
            # audience is checked manually below ("authenticated").
            options={"require": ["exp", "sub"], "verify_aud": False},
        )
    except jwt.PyJWTError:
        raise _unauthorized() from None
    except (ValueError, TypeError):
        raise _unauthorized() from None

    # Issuer: Supabase access tokens are issued by
    # ``<supabase_url>/auth/v1``. REQUIRED when a project URL is
    # configured (F-L4): a token with no ``iss``, or an ``iss`` for a
    # different project, is a foreign token and 401s. When no URL is
    # configured, ``verify_token`` already 401s above (no JWKS to
    # verify against) unless the caller passed an explicit test ``jwks``
    # override — in that case there is no expected issuer to check
    # against, so the claim is not required.
    issuer = claims.get("iss")
    if settings.supabase_url:
        expected_issuer = settings.supabase_url.rstrip("/") + "/auth/v1"
        if not isinstance(issuer, str) or issuer != expected_issuer:
            raise _unauthorized()

    # Audience: Supabase access tokens carry ``aud: "authenticated"``.
    # REQUIRED (F-L4): a token with no ``aud``, or an ``aud`` that does
    # not contain ``"authenticated"`` (it may be a string or a list),
    # 401s. A token minted for another audience must never verify.
    audience = claims.get("aud")
    if audience is None:
        raise _unauthorized()
    audiences = audience if isinstance(audience, list) else [audience]
    if "authenticated" not in audiences:
        raise _unauthorized()

    # Role claim: Supabase access tokens carry ``role: "authenticated"``.
    # Checked only WHEN PRESENT (F-L4 / ADR-0007): ``role`` is redundant
    # with ``aud`` (both carry the same "authenticated" value from the
    # same issuer), so a present-but-wrong role still 401s, but a token
    # without the claim is not rejected for that alone.
    role_claim = claims.get("role")
    if role_claim is not None and role_claim != "authenticated":
        raise _unauthorized()

    try:
        user_id = uuid.UUID(str(claims["sub"]))
    except (KeyError, ValueError, AttributeError, TypeError):
        raise _unauthorized() from None
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        raise _unauthorized()
    return User(id=user_id, email=email, role="owner")
