"""Authentication package: JWT verification, dependencies, ``can()``,
rate limiting, and the Supabase Auth provider.
"""

from __future__ import annotations

from app.auth.deps import get_current_user, get_optional_user
from app.auth.jwt import User, verify_token
from app.auth.permissions import can
from app.auth.provider import (
    AuthProvider,
    AuthSession,
    AuthUser,
    SupabaseAuthProvider,
    get_auth_provider,
    set_auth_provider,
)
from app.auth.rate_limit import RateLimiter, get_rate_limiter, set_rate_limiter

__all__ = [
    "AuthProvider",
    "AuthSession",
    "AuthUser",
    "RateLimiter",
    "SupabaseAuthProvider",
    "User",
    "can",
    "get_auth_provider",
    "get_current_user",
    "get_optional_user",
    "get_rate_limiter",
    "set_auth_provider",
    "set_rate_limiter",
    "verify_token",
]
