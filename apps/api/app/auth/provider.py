"""Authentication provider: Supabase Auth (GoTrue) behind a protocol.

``SupabaseAuthProvider`` is the only production provider: it talks to the
Supabase project's GoTrue endpoints through supabase-py (signup / login /
reset / PKCE code exchange) and through GoTrue's REST ``/logout`` endpoint
for server-side session revocation (supabase-py's ``sign_out`` revokes the
client's own loaded session, which a stateless API never has).

When Supabase is not configured (``settings.supabase_configured`` is
``False`` — the project does not exist yet), every method raises 503
``SUPABASE_NOT_CONFIGURED``. Credentials are never invented, and no fake
provider is ever used as a production fallback: selection is explicit —
tests construct the app with a fake provider, production never sees one.

``FakeAuthProvider`` lives in the test suite only (``tests/test_auth.py``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol

import httpx
from gotrue.errors import AuthApiError
from supabase import Client, create_client

from app.core.config import Settings, settings
from app.core.errors import ApiError
from app.core.logging import logger


@dataclass(frozen=True)
class AuthUser:
    """A user as returned by the auth provider (id + email only)."""

    id: uuid.UUID
    email: str


@dataclass(frozen=True)
class AuthSession:
    """A signed-in session: bearer token + the user it belongs to."""

    access_token: str
    token_type: str
    expires_in: int
    user: AuthUser


class AuthProvider(Protocol):
    """The auth operations the API needs. Implemented by Supabase (prod)
    and by an in-memory fake (tests only)."""

    def sign_up(self, email: str, password: str) -> AuthUser | None: ...

    def sign_in(self, email: str, password: str) -> AuthSession: ...

    def sign_out(self, access_token: str) -> None: ...

    def reset_password(self, email: str) -> None: ...

    def exchange_code(self, code: str) -> AuthSession: ...


def _not_configured() -> ApiError:
    return ApiError(
        503,
        "SUPABASE_NOT_CONFIGURED",
        "Authentication is not configured yet",
    )


def _bad_gateway() -> ApiError:
    return ApiError(502, "BAD_GATEWAY", "Authentication service unavailable")


class SupabaseAuthProvider:
    """Real provider: Supabase Auth (GoTrue) via supabase-py + REST."""

    def __init__(self, app_settings: Settings | None = None) -> None:
        self._settings = app_settings or settings
        self._client: Client | None = None

    def _require_configured(self) -> None:
        if not self._settings.supabase_configured:
            raise _not_configured()

    def _get_client(self) -> Client:
        self._require_configured()
        if self._client is None:
            # supabase_url / supabase_anon_key are non-None here: the
            # configured check above guarantees it.
            url = self._settings.supabase_url or ""
            key = self._settings.supabase_anon_key or ""
            self._client = create_client(url, key)
        return self._client

    @staticmethod
    def _to_auth_user(user_id: object, email: str | None) -> AuthUser:
        return AuthUser(id=uuid.UUID(str(user_id)), email=email or "")

    def sign_up(self, email: str, password: str) -> AuthUser | None:
        """Create the user; Supabase sends the verification email.

        Returns ``None`` when the email is already registered — the caller
        MUST answer exactly as for a fresh signup (same status, same
        message): the endpoint must never distinguish "new account" from
        "existing account", or it becomes an email-enumeration oracle
        (threat-model §3.1). Returning ``None`` here is the honest signal
        for "no new account was created" without leaking it to the client.
        """
        client = self._get_client()
        try:
            response = client.auth.sign_up({"email": email, "password": password})
        except AuthApiError as exc:
            if exc.status == 429:
                raise ApiError(429, "RATE_LIMITED", "Too many attempts. Try again later.") from exc
            # Duplicate detection matches the stable machine-readable code
            # FIRST (gotrue-py AuthApiError.code, e.g. "user_already_exists");
            # the human message is only a fallback, so a GoTrue rewording
            # cannot silently resurrect the enumeration oracle (round-2
            # review finding — the message-only match was the only check).
            if exc.status in (400, 422) and (
                getattr(exc, "code", None) == "user_already_exists"
                or "already registered" in exc.message.lower()
            ):
                logger.info("sign_up for an already-registered email")
                return None
            logger.warning("supabase sign_up failed", extra={"status": exc.status})
            raise _bad_gateway() from exc
        if response.user is None:
            raise _bad_gateway()
        return self._to_auth_user(response.user.id, response.user.email)

    def sign_in(self, email: str, password: str) -> AuthSession:
        """Sign in. Wrong credentials and unconfirmed email both map to the
        same generic 401 — no enumeration oracle."""
        client = self._get_client()
        try:
            response = client.auth.sign_in_with_password({"email": email, "password": password})
        except AuthApiError as exc:
            if exc.status == 429:
                raise ApiError(429, "RATE_LIMITED", "Too many attempts. Try again later.") from exc
            if exc.status in (400, 401, 422):
                raise ApiError(401, "UNAUTHORIZED", "Invalid email or password") from exc
            logger.warning("supabase sign_in failed", extra={"status": exc.status})
            raise _bad_gateway() from exc
        if response.session is None or response.user is None:
            raise ApiError(401, "UNAUTHORIZED", "Invalid email or password")
        session = response.session
        return AuthSession(
            access_token=session.access_token,
            token_type=session.token_type or "bearer",
            expires_in=session.expires_in or 0,
            user=self._to_auth_user(response.user.id, response.user.email),
        )

    def sign_out(self, access_token: str) -> None:
        """Revoke the session server-side via GoTrue ``POST /logout``.

        A 401/404 means the session is already dead — that is success.
        Transport or upstream failures raise 502: logout must not silently
        pretend a live token was revoked.
        """
        self._require_configured()
        url = (self._settings.supabase_url or "").rstrip("/") + "/auth/v1/logout"
        anon_key = self._settings.supabase_anon_key or ""
        try:
            response = httpx.post(
                url,
                headers={
                    "apikey": anon_key,
                    "Authorization": f"Bearer {access_token}",
                },
                timeout=5.0,
                # Same as safe_get (app/core/ssrf.py): direct fetch, never
                # via a proxy from the environment (round-2 review finding).
                trust_env=False,
            )
        except httpx.HTTPError as exc:
            logger.warning("supabase sign_out transport error")
            raise _bad_gateway() from exc
        if response.status_code in (401, 404):
            return
        if response.status_code >= 400:
            logger.warning("supabase sign_out failed", extra={"status": response.status_code})
            raise _bad_gateway()

    def reset_password(self, email: str) -> None:
        """Request a password-reset email. Unknown emails are swallowed
        (no enumeration oracle — the endpoint always answers 200 for them).

        L14 review fix: only "unknown email" errors are swallowed. A
        missing configuration (503) or a genuine provider failure (502)
        MUST propagate — swallowing everything masked a dead auth service
        as a successful reset.
        """
        # _get_client() raises 503 SUPABASE_NOT_CONFIGURED outside the
        # try: a down/unconfigured auth service is an outage, not a
        # "no such email".
        client = self._get_client()
        try:
            client.auth.reset_password_for_email(email)
        except AuthApiError as exc:
            if exc.status in (400, 404):
                # Unknown email (provider-dependent): no enumeration.
                logger.info("reset requested for an unknown email")
                return
            logger.warning("supabase reset_password failed", extra={"status": exc.status})
            raise _bad_gateway() from exc

    def exchange_code(self, code: str) -> AuthSession:
        """Exchange a Supabase PKCE code (email verification / password
        reset link) for a session. A bad or expired code is 401."""
        client = self._get_client()
        try:
            # CodeExchangeParams requires all three keys; the email-link
            # flow carries no PKCE verifier and no redirect, so both are
            # empty (gotrue treats a falsy verifier / redirect as absent).
            response = client.auth.exchange_code_for_session(
                {"auth_code": code, "code_verifier": "", "redirect_to": ""}
            )
        except AuthApiError as exc:
            if exc.status == 429:
                raise ApiError(429, "RATE_LIMITED", "Too many attempts. Try again later.") from exc
            raise ApiError(401, "UNAUTHORIZED", "Invalid or expired code") from exc
        if response.session is None or response.user is None:
            raise ApiError(401, "UNAUTHORIZED", "Invalid or expired code")
        session = response.session
        return AuthSession(
            access_token=session.access_token,
            token_type=session.token_type or "bearer",
            expires_in=session.expires_in or 0,
            user=self._to_auth_user(response.user.id, response.user.email),
        )


# --- Module-level override (tests / explicit wiring) -----------------------
# Production always uses SupabaseAuthProvider. Tests replace it explicitly
# via ``set_auth_provider``; there is no implicit fake fallback anywhere.

_provider_override: AuthProvider | None = None


def get_auth_provider() -> AuthProvider:
    """Return the active provider (test override wins, else Supabase)."""
    if _provider_override is not None:
        return _provider_override
    return SupabaseAuthProvider()


def set_auth_provider(provider: AuthProvider | None) -> None:
    """Override the active provider (tests only). ``None`` clears it."""
    global _provider_override
    _provider_override = provider
