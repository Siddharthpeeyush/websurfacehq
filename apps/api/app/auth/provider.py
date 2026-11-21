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

import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Protocol

import httpx
from gotrue.errors import AuthApiError
from supabase import Client

from app.auth.mfa import MfaService
from app.core.config import Settings, settings
from app.core.errors import ApiError
from app.core.http import create_supabase_client as create_client
from app.core.http import proxy_safe_httpx_client
from app.core.logging import logger, redact_text


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

    def user_exists(self, email: str) -> bool:
        """True when an Auth user exists for ``email``.

        Timing-equalization lookup (H1 double-count fix, 20 Nov
        2026): after a failed ``sign_in`` the staff login flow
        asks this to decide whether GoTrue ran bcrypt — if the user
        exists, bcrypt ran and the dummy hash must be SKIPPED; if
        not, the dummy runs. The answer is server-internal only
        (never returned to a client) and the lookup itself is one
        cheap Admin API round trip against bcrypt's ~75 ms. On any
        error it returns False (fail towards running the dummy —
        the timing cover stays on, the login still 401s).
        """

    def sign_out(self, access_token: str) -> None: ...

    def reset_password(self, email: str) -> None: ...

    def disable_password(self, user_id: uuid.UUID) -> None:
        """Invalidate a user's password immediately (Admin API).

        Replaces the password with a fresh random unguessable one,
        so the old password stops working at the next sign-in while
        the password-recovery email flow still works (the reset link
        sets a new password — it does not need the old one). Used by
        Owner force-reset (``app.services.staff``).
        """
        ...

    def exchange_code(self, code: str) -> AuthSession: ...


def _not_configured() -> ApiError:
    return ApiError(
        503,
        "SUPABASE_NOT_CONFIGURED",
        "Authentication is not configured yet",
    )


def _bad_gateway() -> ApiError:
    return ApiError(502, "BAD_GATEWAY", "Authentication service unavailable")


# --- Upstream-error logging (live-proof fix F4) ---------------------------
# GoTrue failures were logged with the status only, so the 502 root cause
# could not be diagnosed from the logs. The helpers below log the status,
# the machine-readable error code and a truncated, sanitized message —
# never tokens, passwords, or full JWTs (the logging layer redacts
# ``key=value`` fragments as well; this is defence in depth at the call
# site). The 502 root cause itself stays unproven until the re-proof:
# nothing here guesses it.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_MAX_AUTH_ERROR_CHARS = 200

# Admin user-existence lookup (H1 double-count fix): GoTrue's Admin
# API lists users only (no get-by-email), so user_exists pages the
# list. 5 pages x 1000 users covers the project's scale with room;
# beyond the cap the lookup answers False (run the dummy) rather
# than claim an absence it did not prove.
_ADMIN_USER_LOOKUP_PAGE_SIZE = 1000
_ADMIN_USER_LOOKUP_MAX_PAGES = 5


def _sanitize_auth_message(message: str | None) -> str:
    """Truncate + redact an upstream auth error message for logging."""
    text = message or ""
    text = _JWT_RE.sub("[REDACTED]", text)
    text = redact_text(text)
    return text[:_MAX_AUTH_ERROR_CHARS]


def _log_auth_error(operation: str, exc: AuthApiError) -> None:
    """Log a GoTrue failure at warning level, redacted.

    Fields: HTTP status, machine-readable ``error_code`` (e.g.
    ``over_email_send_rate_limit``), and the truncated sanitized message.
    """
    logger.warning(
        f"supabase {operation} failed",
        extra={
            "status": exc.status,
            "error_code": getattr(exc, "code", None) or "unknown",
            "error": _sanitize_auth_message(exc.message),
        },
    )


class SupabaseAuthProvider:
    """Real provider: Supabase Auth (GoTrue) via supabase-py + REST."""

    def __init__(self, app_settings: Settings | None = None) -> None:
        self._settings = app_settings or settings
        self._client: Client | None = None
        self._mfa_service: MfaService | None = None

    @property
    def mfa(self) -> MfaService:
        """Staff MFA (TOTP via GoTrue MFA REST — see ``app/auth/mfa.py``).

        MFA hook, admin foundation (Child B): the staff login flow
        calls ``provider.mfa.enroll / challenge_and_verify /
        has_verified_totp_factor`` and the Founder gate calls
        ``provider.mfa.verify_step_up``. Deliberately NOT added to the
        ``AuthProvider`` Protocol above: the test fake implementing
        that protocol lives in ``tests/test_auth.py`` (not this
        child's file), and the MFA surface is consumed through
        ``MfaService`` directly by the staff-auth router, not through
        the password-auth protocol.
        """
        if self._mfa_service is None:
            self._mfa_service = MfaService()
        return self._mfa_service

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
            # NOTE: the module-level ``create_client`` name is the
            # proxy-safe wrapper (app.core.http.create_supabase_client),
            # NOT supabase.create_client directly — it injects a
            # trust_env=False httpx client via SyncClientOptions (live-proof
            # fix F1: the VM's bracketed no_proxy entries make a plain
            # httpx.Client() raise InvalidURL). The name is kept so tests
            # can still patch ``app.auth.provider.create_client``.
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

        Test practice: live signup tests must use valid-domain throwaway
        emails (e.g. ``@websurfacehq.com``) — pydantic rejects the
        ``.invalid`` TLD by design (422 VALIDATION_ERROR, working as
        intended), so ``.invalid`` addresses can never reach GoTrue.
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
            _log_auth_error("sign_up", exc)
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
            _log_auth_error("sign_in", exc)
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

    def user_exists(self, email: str) -> bool:
        """True when an Auth user exists for ``email`` (service-role
        Admin API lookup — server-only, never client-visible).

        GoTrue's Admin API has no get-by-email: this pages
        ``GET /auth/v1/admin/users`` (1000/page, at most
        ``_ADMIN_USER_LOOKUP_MAX_PAGES`` pages) and compares
        emails case-insensitively. Soft-deleted users are not
        listed by GoTrue, which is the correct answer here — a
        deleted user cannot sign in (no bcrypt runs for them), so
        the dummy must run. Any transport/upstream error returns
        False (run the dummy — the timing cover stays on) and is
        logged; the caller still answers the generic 401.
        """
        self._require_configured()
        url = (self._settings.supabase_url or "").rstrip("/") + "/auth/v1/admin/users"
        service_key = self._settings.supabase_service_role_key
        key = service_key.get_secret_value() if service_key is not None else ""
        wanted = email.strip().lower()
        try:
            with proxy_safe_httpx_client(timeout=5.0) as client:
                for page in range(1, _ADMIN_USER_LOOKUP_MAX_PAGES + 1):
                    response = client.get(
                        url,
                        params={"page": page, "per_page": _ADMIN_USER_LOOKUP_PAGE_SIZE},
                        headers={
                            "apikey": key,
                            "Authorization": f"Bearer {key}",
                        },
                    )
                    if response.status_code >= 400:
                        logger.warning(
                            "supabase admin user lookup failed",
                            extra={"status": response.status_code},
                        )
                        return False
                    users = response.json().get("users", [])
                    for user in users:
                        if str(user.get("email") or "").strip().lower() == wanted:
                            return True
                    if len(users) < _ADMIN_USER_LOOKUP_PAGE_SIZE:
                        return False
                # Page cap reached without finding the email: answer
                # False (run the dummy) rather than claim absence
                # falsely — the dummy is timing cover, not a decision.
                logger.warning(
                    "supabase admin user lookup hit the page cap; assuming absent",
                    extra={"pages": _ADMIN_USER_LOOKUP_MAX_PAGES},
                )
                return False
        except httpx.HTTPError as exc:
            logger.warning(
                "supabase admin user lookup transport error",
                extra={"error_type": type(exc).__name__},
            )
            return False

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
            # Shared proxy-safe client (app/core/http.py): ignores the
            # malformed proxy env for parsing, re-applies the operator's
            # explicit proxy + CA when configured (required for VM egress;
            # a bare trust_env=False client cannot connect from this VM).
            with proxy_safe_httpx_client(timeout=5.0) as client:
                response = client.post(
                    url,
                    headers={
                        "apikey": anon_key,
                        "Authorization": f"Bearer {access_token}",
                    },
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "supabase sign_out transport error",
                extra={"error_type": type(exc).__name__},
            )
            raise _bad_gateway() from exc
        if response.status_code in (401, 404):
            return
        if response.status_code >= 400:
            logger.warning(
                "supabase sign_out failed",
                extra={
                    "status": response.status_code,
                    "error": _sanitize_auth_message(response.text),
                },
            )
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
            _log_auth_error("reset_password", exc)
            raise _bad_gateway() from exc

    def disable_password(self, user_id: uuid.UUID) -> None:
        """Invalidate the user's password via the GoTrue Admin API.

        F2 fix (red-team, 20 Nov 2026): ``force_password_reset``
        used to only SEND the reset email — the old password kept
        working until the link was used. This replaces the password
        with a fresh 32-byte random one (``PUT
        /auth/v1/admin/users/{id}``, service-role key — same REST
        pattern as :meth:`user_exists`, NOT the anon-key supabase-py
        admin client, which cannot call Admin endpoints).

        Random-password route, NOT a ban: a banned user cannot sign
        in at all — including via the recovery link — until unbanned,
        so a ban would break the reset flow this method exists to
        enable. The random password is unguessable and never stored
        or returned, so the reset link is the only way back in, and
        the reset flow itself restores access with no extra unban
        step. 503 when unconfigured, 502 on any upstream failure
        (the caller must see that the password was NOT invalidated).
        """
        self._require_configured()
        url = (self._settings.supabase_url or "").rstrip("/") + f"/auth/v1/admin/users/{user_id}"
        service_key = self._settings.supabase_service_role_key
        key = service_key.get_secret_value() if service_key is not None else ""
        new_password = secrets.token_urlsafe(32)
        try:
            with proxy_safe_httpx_client(timeout=5.0) as client:
                response = client.put(
                    url,
                    json={"password": new_password},
                    headers={
                        "apikey": key,
                        "Authorization": f"Bearer {key}",
                    },
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "supabase admin disable password transport error",
                extra={"error_type": type(exc).__name__},
            )
            raise _bad_gateway() from exc
        if response.status_code >= 400:
            logger.warning(
                "supabase admin disable password failed",
                extra={"status": response.status_code},
            )
            raise _bad_gateway()

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
