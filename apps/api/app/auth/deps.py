"""FastAPI dependencies that turn an ``Authorization`` header into a ``User``.

``get_current_user`` is the gate for every protected endpoint: no header,
a malformed header, or an unverifiable token all become 401
``UNAUTHORIZED``. ``get_optional_user`` never raises — it exists for
handlers that serve both anonymous and authenticated callers, and must
never be used to bypass auth on a protected endpoint.
"""

from __future__ import annotations

from fastapi import Header

from app.auth.jwt import User, verify_token
from app.core.errors import ApiError


def _extract_bearer(authorization: str | None) -> str:
    """Pull the token out of ``Authorization: Bearer <token>``.

    Raises:
        ApiError: 401 ``UNAUTHORIZED`` when the header is missing,
            malformed, or carries an empty token.
    """
    if not authorization:
        raise ApiError(401, "UNAUTHORIZED", "Missing authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ApiError(401, "UNAUTHORIZED", "Invalid authorization header")
    return token.strip()


async def get_current_user(
    authorization: str | None = Header(default=None),
) -> User:
    """Return the authenticated user, or raise 401 ``UNAUTHORIZED``."""
    return verify_token(_extract_bearer(authorization))


async def get_bearer_token(
    authorization: str | None = Header(default=None),
) -> str:
    """Return the raw bearer token (for logout revocation), or raise 401."""
    return _extract_bearer(authorization)


async def get_optional_user(
    authorization: str | None = Header(default=None),
) -> User | None:
    """Return the authenticated user, or ``None`` when anonymous/invalid.

    Never raises: a missing or unverifiable token simply means anonymous.
    """
    if not authorization:
        return None
    try:
        return verify_token(_extract_bearer(authorization))
    except ApiError:
        return None
