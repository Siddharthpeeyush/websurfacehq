"""Auth endpoints (``/api/v1/auth``).

Public endpoints (signup / login / reset / callback) do NOT call ``can()``
— they are rate-limited instead (5 attempts / 15 min per IP **and** per
email; a denial answers 429 ``RATE_LIMITED`` with a ``Retry-After``
header). Protected endpoints (logout / me) require a valid Supabase JWT
via ``get_current_user``.

Password rules: minimum 8 characters, enforced by Pydantic at the
boundary. Passwords are never logged or echoed: the app's validation
handler already strips ``input``/``ctx`` from 422 details, and no handler
below includes a password in any response, log line, or error detail.

Logout is always audited (best-effort store audit log + a log line), even
when session revocation fails.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

from app.auth.deps import get_bearer_token, get_current_user
from app.auth.jwt import User
from app.auth.provider import get_auth_provider
from app.auth.rate_limit import get_rate_limiter
from app.core.config import settings
from app.core.errors import ApiError
from app.core.logging import logger

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# --- Request / response models ----------------------------------------------
# Passwords: min 8 chars (blueprint), max 128 (DoS guard on hashing cost).
# EmailStr validates the address shape; nothing here ever echoes a password.


class SignupRequest(BaseModel):
    """POST /signup body."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    """POST /login body."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class ResetRequest(BaseModel):
    """POST /reset body."""

    email: EmailStr


class CallbackRequest(BaseModel):
    """POST /callback body: the PKCE code from an email link."""

    code: str = Field(min_length=1, max_length=2048)


class UserResponse(BaseModel):
    """A public user profile (never contains secrets)."""

    id: str
    email: str


class SessionResponse(BaseModel):
    """A signed-in session."""

    access_token: str
    token_type: str
    expires_in: int
    user: UserResponse


class MessageResponse(BaseModel):
    """A human-readable confirmation message."""

    message: str


# --- Rate limiting ------------------------------------------------------------


def _client_ip(request: Request) -> str:
    """Best-effort client IP for rate limiting.

    ``X-Forwarded-For`` is trusted ONLY when
    ``settings.trust_x_forwarded_for`` is True (the app runs behind a
    trusted reverse proxy that is the sole ingress — Render in prod).
    Otherwise the header is attacker-controlled and ignored: trusting it
    unconditionally lets anyone mint a fresh per-IP bucket per request
    (rate-limit bypass) or fill a victim's bucket (lockout DoS).
    """
    peer = request.client.host if request.client is not None else "unknown"
    if not settings.trust_x_forwarded_for:
        return peer
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return peer


def _rate_limited_response(retry_after: int) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        headers={"Retry-After": str(retry_after)},
        content={
            "code": "RATE_LIMITED",
            "message": "Too many attempts. Try again later.",
            "details": {"retry_after_seconds": retry_after},
        },
    )


def _enforce_auth_rate_limit(request: Request, email: str | None) -> JSONResponse | None:
    """Check the per-IP key, then (when an email is known) the per-email
    key. Returns a 429 response on denial, else ``None``."""
    limiter = get_rate_limiter()
    allowed, retry_after = limiter.check(f"login:ip:{_client_ip(request)}")
    if not allowed:
        return _rate_limited_response(retry_after)
    if email is not None:
        allowed, retry_after = limiter.check(f"login:email:{email.lower()}")
        if not allowed:
            return _rate_limited_response(retry_after)
    return None


# --- Audit --------------------------------------------------------------------


def _audit_auth_event(user_id: uuid.UUID, action: str, metadata: dict[str, Any]) -> None:
    """Best-effort audit: store audit log when available, always a log line.
    Never raises, never carries secrets."""
    try:
        from app.db import get_store

        get_store().log_audit(user_id=user_id, action=action, target_domain=None, metadata=metadata)
    except Exception:  # noqa: BLE001 - audit must never break the endpoint
        logging.getLogger("websurfacehq").warning(
            "audit log unavailable for auth event",
            extra={"user_id": user_id, "action": action, **metadata},
        )
    logger.info("auth event", extra={"user_id": user_id, "action": action, **metadata})


# --- Endpoints ------------------------------------------------------------------


@router.post("/signup", status_code=201, response_model=MessageResponse)
def signup(body: SignupRequest, request: Request) -> MessageResponse | JSONResponse:
    """Create an account. Supabase sends the verification email.

    The response is IDENTICAL for a fresh signup and an already-registered
    email (same 201, same message, no user id): distinguishing them would
    let anyone probe whether an address has an account (threat-model §3.1).
    No session is created here — the user verifies by email first.
    """
    denied = _enforce_auth_rate_limit(request, body.email)
    if denied is not None:
        return denied
    get_auth_provider().sign_up(body.email, body.password)
    return MessageResponse(
        message="If this email is new, a verification link has been sent. Check your inbox."
    )


@router.post("/login", response_model=SessionResponse)
def login(body: LoginRequest, request: Request) -> SessionResponse | JSONResponse:
    """Sign in. Wrong credentials answer with the generic 401 (no
    enumeration oracle — unknown email and wrong password are identical)."""
    denied = _enforce_auth_rate_limit(request, body.email)
    if denied is not None:
        return denied
    session = get_auth_provider().sign_in(body.email, body.password)
    return SessionResponse(
        access_token=session.access_token,
        token_type=session.token_type,
        expires_in=session.expires_in,
        user=UserResponse(id=str(session.user.id), email=session.user.email),
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    user: User = Depends(get_current_user),
    token: str = Depends(get_bearer_token),
) -> MessageResponse:
    """Sign out: revoke the server-side session, then always audit.

    Revocation failure is reported (502 from the provider) — a logout that
    silently leaves the token valid would be a lie — but the audit runs
    either way.
    """
    try:
        get_auth_provider().sign_out(token)
    except ApiError:
        _audit_auth_event(user.id, "auth.logout", {"revoked": False, "error": True})
        raise
    _audit_auth_event(user.id, "auth.logout", {"revoked": True})
    return MessageResponse(message="Signed out")


@router.post("/reset", response_model=MessageResponse)
def reset(body: ResetRequest, request: Request) -> MessageResponse | JSONResponse:
    """Request a password-reset email. Always 200 — even for unknown
    emails — so the endpoint cannot probe whether an address exists."""
    denied = _enforce_auth_rate_limit(request, body.email)
    if denied is not None:
        return denied
    get_auth_provider().reset_password(body.email)
    return MessageResponse(
        message="If an account exists for this email, a password reset link has been sent."
    )


@router.post("/callback", response_model=SessionResponse)
def callback(body: CallbackRequest, request: Request) -> SessionResponse | JSONResponse:
    """Exchange a Supabase PKCE code (email verification / password-reset
    link) for a session. An invalid or expired code is 401."""
    denied = _enforce_auth_rate_limit(request, None)
    if denied is not None:
        return denied
    session = get_auth_provider().exchange_code(body.code)
    return SessionResponse(
        access_token=session.access_token,
        token_type=session.token_type,
        expires_in=session.expires_in,
        user=UserResponse(id=str(session.user.id), email=session.user.email),
    )


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)) -> UserResponse:
    """Return the current user's profile."""
    return UserResponse(id=str(user.id), email=user.email)
