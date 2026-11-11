"""Verify Supabase JWTs (HS256) and represent the authenticated user.

Never accept a token that cannot be verified: a missing secret, a bad
signature, an expired token, a non-UUID subject, or a mismatched issuer /
audience (when those claims are present) all raise 401 ``UNAUTHORIZED``.
No fallback, no unsigned acceptance, no hand-rolled session.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import jwt
from pydantic import SecretStr

from app.core.config import settings
from app.core.errors import ApiError


@dataclass(frozen=True)
class User:
    """An authenticated WebSurfaceHQ account (MVP: exactly one role)."""

    id: uuid.UUID
    email: str
    role: str = "owner"


def _unauthorized() -> ApiError:
    return ApiError(401, "UNAUTHORIZED", "Invalid or expired token")


def _resolve_secret(secret: str | SecretStr | None) -> str | None:
    """Explicit override wins; otherwise the configured JWT secret."""
    if secret is None:
        configured = settings.supabase_jwt_secret
        return configured.get_secret_value() if configured is not None else None
    if isinstance(secret, SecretStr):
        return secret.get_secret_value()
    return secret


def verify_token(token: str, secret: str | SecretStr | None = None) -> User:
    """Verify a Supabase access token and return the ``User`` it names.

    Args:
        token: The raw ``Authorization: Bearer <token>`` value (no scheme).
        secret: HS256 secret override (tests only). Defaults to
            ``settings.supabase_jwt_secret``.

    Raises:
        ApiError: 401 ``UNAUTHORIZED`` on any verification failure.
    """
    if not token or not token.strip():
        raise _unauthorized()
    key = _resolve_secret(secret)
    if not key:
        # No secret configured means no token can be verified — reject,
        # never accept an unverifiable token.
        raise _unauthorized()
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key,
            algorithms=["HS256"],
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
    # ``<supabase_url>/auth/v1``. Verify it when we know the project URL
    # and the token carries the claim; a mismatch is a foreign token.
    issuer = claims.get("iss")
    if isinstance(issuer, str) and settings.supabase_url:
        expected_issuer = settings.supabase_url.rstrip("/") + "/auth/v1"
        if issuer != expected_issuer:
            raise _unauthorized()

    # Audience: Supabase access tokens carry ``aud: "authenticated"``.
    # Verify it when present (it may be a string or a list).
    audience = claims.get("aud")
    if audience is not None:
        audiences = audience if isinstance(audience, list) else [audience]
        if "authenticated" not in audiences:
            raise _unauthorized()

    # Role claim: Supabase access tokens carry ``role: "authenticated"``.
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
