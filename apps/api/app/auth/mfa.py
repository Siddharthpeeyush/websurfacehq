"""Staff MFA (TOTP via Supabase Auth / GoTrue MFA).

MFA is REQUIRED for all staff sessions (admin-foundation plan §1,
DESIGN-LOCK.md "Staff sessions"): TOTP at EVERY staff sign-in, no
trusted-device bypass. This module is the MFA layer Child C's staff-auth
router calls: enroll (setup during invite onboarding), challenge +
verify (sign-in), step-up verify (Founder gate), unenroll (Owner
re-enrollment power).

Transport decision (documented, 20 Nov 2026): supabase-py 2.18.0 /
gotrue-py 2.12.3 DO expose ``client.auth.mfa`` — but every one of those
methods requires a *loaded client session* (``get_session()`` raises
``AuthSessionMissingError`` without one), i.e. a refresh token. A
stateless API only ever holds the caller's Bearer access token, so the
SDK MFA path is unusable here. The production backend below therefore
calls GoTrue's MFA REST endpoints directly — the same endpoints the SDK
calls (``POST /auth/v1/factors``, ``.../challenge``, ``.../verify``,
``DELETE /auth/v1/factors/{id}``, ``GET /auth/v1/user`` for the factor
list) — through the shared proxy-safe httpx client
(``app/core/http.py``), exactly as ``sign_out`` in
``app/auth/provider.py`` already does for ``POST /auth/v1/logout``.
TLS verification is never disabled.

Security rules in this module:

- The TOTP ``secret`` is returned ONCE, at enrollment, and is NEVER
  logged, never stored server-side, never echoed in any error. The
  caller (Child C's router) shows it once and discards it.
- TOTP codes are NEVER logged. A wrong code, a malformed code, and a
  challenge against a nonexistent factor all answer the SAME 401
  ``INVALID_MFA_CODE`` — no oracle distinguishes them.
- MFA is not a password substitute: every method here takes the
  caller's already-verified Bearer access token and only proves
  possession of the TOTP factor. The password check happens first,
  in the login flow.
"""

from __future__ import annotations

import re
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from app.core.config import Settings, settings
from app.core.errors import ApiError
from app.core.http import proxy_safe_httpx_client
from app.core.logging import logger

_MFA_TIMEOUT_SECONDS = 5.0

# One shared httpx client for all MFA GoTrue calls (connection reuse).
# GoTrue binds an MFA challenge to the IP that created it and rejects a
# verify from a different IP (422 mfa_ip_address_mismatch). A fresh
# client per call opens a new connection per call, and an egress proxy
# that rotates IPs per connection (this VM's Hatch proxy does — proven
# live 21 Nov 2026: 6 fresh clients exited via 5 different IPs, one
# shared client via 1) makes challenge and verify exit from different
# IPs, so the confirm fails intermittently. A shared client reuses one
# pooled connection, so the pair shares an egress IP. Also cuts a TLS
# handshake per call. httpx.Client is thread-safe; the lazy init is
# double-checked under a lock. The client lives for the process
# lifetime and is never closed per call.
# The cached client is keyed on the FACTORY function object: tests
# monkeypatch ``proxy_safe_httpx_client`` to inject a fake client, and
# a changed factory discards the cache so the stub takes effect (and
# the real factory is re-resolved when the patch reverts). In
# production the factory never changes, so the client is created once.
_shared_mfa_client: httpx.Client | None = None
_shared_mfa_client_factory: Any = None
_shared_mfa_client_lock = threading.Lock()


def _get_shared_mfa_client() -> httpx.Client:
    global _shared_mfa_client, _shared_mfa_client_factory
    factory = proxy_safe_httpx_client
    if _shared_mfa_client is None or _shared_mfa_client_factory is not factory:
        with _shared_mfa_client_lock:
            factory = proxy_safe_httpx_client
            if _shared_mfa_client is None or _shared_mfa_client_factory is not factory:
                _shared_mfa_client = factory(timeout=_MFA_TIMEOUT_SECONDS)
                _shared_mfa_client_factory = factory
    return _shared_mfa_client


# A TOTP code is exactly 6 decimal digits. Anything else is rejected
# with the same 401 as a wrong code (no oracle, no GoTrue round-trip
# for obvious junk).
_CODE_RE = re.compile(r"^\d{6}$")


def _not_configured() -> ApiError:
    return ApiError(
        503,
        "SUPABASE_NOT_CONFIGURED",
        "Authentication is not configured yet",
    )


def _bad_gateway() -> ApiError:
    return ApiError(502, "BAD_GATEWAY", "Authentication service unavailable")


def _invalid_mfa_code() -> ApiError:
    """One generic 401 for every MFA verification failure.

    Wrong code, malformed code, expired challenge, unknown factor:
    indistinguishable by design, so a wrong-code probe can never learn
    whether the factor exists or the challenge was live.
    """
    return ApiError(401, "INVALID_MFA_CODE", "Invalid verification code")


# ---------------------------------------------------------------------------
# Value shapes (dataclasses, not Pydantic: this layer has no HTTP shape)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MfaEnrollment:
    """A newly enrolled (still UNVERIFIED) TOTP factor.

    ``secret`` is shown ONCE — the caller must display it and discard
    it; it is never logged or stored. ``qr_uri`` is the
    ``otpauth://totp/...`` URI the authenticator app scans. The factor
    becomes active only after a successful ``verify`` (challenge +
    code) against it.
    """

    factor_id: str
    qr_uri: str
    secret: str


@dataclass(frozen=True)
class MfaChallenge:
    """A live TOTP challenge: the ``challenge_id`` the code is verified
    against, plus its expiry (Unix seconds, per GoTrue)."""

    challenge_id: str
    expires_at: int


@dataclass(frozen=True)
class MfaVerifiedSession:
    """The AAL2 session GoTrue returns after a successful MFA verify:
    a fresh access token (the caller trades the AAL1 token for this
    one) plus the user it belongs to."""

    access_token: str
    token_type: str
    expires_in: int
    user_id: uuid.UUID
    email: str


@dataclass(frozen=True)
class MfaFactor:
    """One enrolled factor, as listed by GoTrue."""

    factor_id: str
    friendly_name: str | None
    factor_type: str  # "totp" | "phone"
    status: str  # "verified" | "unverified"


# ---------------------------------------------------------------------------
# Backend protocol (production = GoTrue REST; tests inject a fake)
# ---------------------------------------------------------------------------


class MfaBackend(Protocol):
    """The MFA operations the service needs, keyed by access token."""

    def enroll(self, access_token: str, friendly_name: str) -> MfaEnrollment: ...

    def challenge(self, access_token: str, factor_id: str) -> MfaChallenge: ...

    def verify(
        self, access_token: str, factor_id: str, challenge_id: str, code: str
    ) -> MfaVerifiedSession: ...

    def list_factors(self, access_token: str) -> list[MfaFactor]: ...

    def unenroll(self, access_token: str, factor_id: str) -> None: ...


# ---------------------------------------------------------------------------
# Production backend: GoTrue MFA REST via the proxy-safe httpx client
# ---------------------------------------------------------------------------


class GoTrueMfaBackend:
    """MFA against the live Supabase project's GoTrue endpoints.

    Endpoints (GoTrue MFA API, same paths gotrue-py's ``client.auth.mfa``
    calls internally — verified against gotrue 2.12.3 source):

    - ``POST /auth/v1/factors`` ``{factor_type: "totp",
      friendly_name, issuer}`` -> enroll
    - ``POST /auth/v1/factors/{id}/challenge`` -> challenge
    - ``POST /auth/v1/factors/{id}/verify`` ``{challenge_id, code}``
      -> AAL2 session
    - ``GET /auth/v1/user`` -> user incl. ``factors`` list
    - ``DELETE /auth/v1/factors/{id}`` -> unenroll
    """

    def __init__(self, app_settings: Settings | None = None) -> None:
        self._settings = app_settings or settings

    def _require_configured(self) -> None:
        if not self._settings.supabase_url or not self._settings.supabase_anon_key:
            raise _not_configured()

    def _base_url(self) -> str:
        self._require_configured()
        return (self._settings.supabase_url or "").rstrip("/") + "/auth/v1"

    def _headers(self, access_token: str) -> dict[str, str]:
        return {
            "apikey": self._settings.supabase_anon_key or "",
            "Authorization": f"Bearer {access_token}",
        }

    def _request(
        self,
        method: str,
        path: str,
        access_token: str,
        *,
        operation: str,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """One GoTrue call. Returns the parsed JSON object.

        Raises:
            ApiError: 503 when Supabase is not configured, 502 on
                transport / upstream / malformed-response failures.
                MFA verification failures are mapped by the caller
                (``verify``), not here — a 422 on verify is a wrong
                code, not a gateway error.
        """
        url = self._base_url() + path
        try:
            # Shared client (see _get_shared_mfa_client): challenge and
            # verify must share one connection / egress IP.
            client = _get_shared_mfa_client()
            response = client.request(
                method, url, headers=self._headers(access_token), json=json_body
            )
        except httpx.HTTPError as exc:
            logger.warning(
                f"supabase mfa {operation} transport error",
                extra={"error_type": type(exc).__name__},
            )
            raise _bad_gateway() from exc
        if response.status_code == 429:
            raise ApiError(429, "RATE_LIMITED", "Too many attempts. Try again later.")
        if response.status_code >= 400:
            logger.warning(
                "supabase mfa request failed",
                extra={"operation": operation, "status": response.status_code},
            )
            # The raw body is never surfaced: it can carry GoTrue's
            # error detail (factor ids, challenge state) — the caller
            # maps the status to a generic error.
            raise _MfaHttpError(response.status_code)
        try:
            data = response.json()
        except ValueError as exc:
            logger.warning(
                "supabase mfa response was not JSON",
                extra={"operation": operation, "status": response.status_code},
            )
            raise _bad_gateway() from exc
        if not isinstance(data, dict):
            raise _bad_gateway()
        return data

    def enroll(self, access_token: str, friendly_name: str) -> MfaEnrollment:
        try:
            data = self._request(
                "POST",
                "/factors",
                access_token,
                operation="enroll",
                json_body={
                    "factor_type": "totp",
                    "friendly_name": friendly_name,
                    "issuer": "WebSurfaceHQ",
                },
            )
        except _MfaHttpError as exc:
            if exc.status_code == 401:
                raise ApiError(401, "UNAUTHORIZED", "Invalid or expired token") from exc
            raise _bad_gateway() from exc
        factor_id = data.get("id")
        totp = data.get("totp")
        if not isinstance(factor_id, str) or not factor_id or not isinstance(totp, dict):
            raise _bad_gateway()
        qr_uri = totp.get("uri")
        secret = totp.get("secret")
        if not isinstance(qr_uri, str) or not qr_uri or not isinstance(secret, str) or not secret:
            raise _bad_gateway()
        return MfaEnrollment(factor_id=factor_id, qr_uri=qr_uri, secret=secret)

    def challenge(self, access_token: str, factor_id: str) -> MfaChallenge:
        try:
            data = self._request(
                "POST",
                f"/factors/{factor_id}/challenge",
                access_token,
                operation="challenge",
                json_body={},
            )
        except _MfaHttpError as exc:
            if exc.status_code in (401, 404, 422):
                # Unknown factor / bad token / no such challenge: the
                # caller answers the same generic MFA 401 — a probe
                # must not learn whether the factor exists.
                raise _invalid_mfa_code() from exc
            raise _bad_gateway() from exc
        challenge_id = data.get("id")
        expires_at = data.get("expires_at")
        if not isinstance(challenge_id, str) or not challenge_id:
            raise _bad_gateway()
        if not isinstance(expires_at, int):
            raise _bad_gateway()
        return MfaChallenge(challenge_id=challenge_id, expires_at=expires_at)

    def verify(
        self, access_token: str, factor_id: str, challenge_id: str, code: str
    ) -> MfaVerifiedSession:
        try:
            data = self._request(
                "POST",
                f"/factors/{factor_id}/verify",
                access_token,
                operation="verify",
                json_body={"challenge_id": challenge_id, "code": code},
            )
        except _MfaHttpError as exc:
            if exc.status_code in (400, 401, 404, 422):
                # Wrong code, expired challenge, unknown factor: all
                # the same generic 401 (see _invalid_mfa_code).
                raise _invalid_mfa_code() from exc
            raise _bad_gateway() from exc
        return _parse_verified_session(data)

    def list_factors(self, access_token: str) -> list[MfaFactor]:
        try:
            data = self._request("GET", "/user", access_token, operation="list_factors")
        except _MfaHttpError as exc:
            if exc.status_code == 401:
                raise ApiError(401, "UNAUTHORIZED", "Invalid or expired token") from exc
            raise _bad_gateway() from exc
        factors = data.get("factors")
        if factors is None:
            return []
        if not isinstance(factors, list):
            raise _bad_gateway()
        parsed: list[MfaFactor] = []
        for entry in factors:
            if not isinstance(entry, dict):
                continue
            factor_id = entry.get("id")
            factor_type = entry.get("factor_type")
            status = entry.get("status")
            if (
                not isinstance(factor_id, str)
                or not factor_id
                or not isinstance(factor_type, str)
                or not isinstance(status, str)
            ):
                continue
            friendly_name = entry.get("friendly_name")
            parsed.append(
                MfaFactor(
                    factor_id=factor_id,
                    friendly_name=friendly_name if isinstance(friendly_name, str) else None,
                    factor_type=factor_type,
                    status=status,
                )
            )
        return parsed

    def unenroll(self, access_token: str, factor_id: str) -> None:
        try:
            self._request(
                "DELETE",
                f"/factors/{factor_id}",
                access_token,
                operation="unenroll",
            )
        except _MfaHttpError as exc:
            if exc.status_code in (401, 404):
                # Already unenrolled / unknown factor: success — the
                # end state (no such factor) is what was wanted.
                return
            raise _bad_gateway() from exc


class _MfaHttpError(Exception):
    """Internal: a GoTrue call answered >= 400. Carries only the status —
    the body is never kept (it can carry factor/challenge detail)."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"GoTrue MFA call failed with HTTP {status_code}")
        self.status_code = status_code


def _parse_verified_session(data: dict[str, Any]) -> MfaVerifiedSession:
    """Parse GoTrue's MFA-verify session response, or 502 if malformed."""
    access_token = data.get("access_token")
    user = data.get("user")
    if not isinstance(access_token, str) or not access_token or not isinstance(user, dict):
        raise _bad_gateway()
    user_id = user.get("id")
    email = user.get("email")
    try:
        user_uuid = uuid.UUID(str(user_id))
    except (ValueError, AttributeError, TypeError):
        raise _bad_gateway() from None
    if not isinstance(email, str) or not email:
        raise _bad_gateway()
    expires_in = data.get("expires_in")
    raw_token_type = data.get("token_type")
    token_type = raw_token_type if isinstance(raw_token_type, str) else "bearer"
    return MfaVerifiedSession(
        access_token=access_token,
        token_type=token_type,
        expires_in=expires_in if isinstance(expires_in, int) else 0,
        user_id=user_uuid,
        email=email,
    )


# ---------------------------------------------------------------------------
# Service (the layer Child C's router calls)
# ---------------------------------------------------------------------------


class MfaService:
    """Staff MFA: enroll / challenge / verify / step-up / unenroll.

    Enforces the plan's MFA rules at this layer, independent of the
    backend: codes are format-checked before any upstream call (a
    malformed code is the same 401 as a wrong one), and enrollment is
    TOTP-only (``factor_type`` is never a caller choice — phone/SMS
    factors are out of scope for the staff door).
    """

    def __init__(self, backend: MfaBackend | None = None) -> None:
        self._backend: MfaBackend = backend or GoTrueMfaBackend()

    def enroll(self, access_token: str, friendly_name: str = "WebSurfaceHQ") -> MfaEnrollment:
        """Start TOTP enrollment. Returns the factor id, the
        ``otpauth://`` URI, and the secret — shown ONCE, never logged
        or stored. The factor stays ``unverified`` until a code is
        verified against it (see :meth:`verify`)."""
        if not access_token or not access_token.strip():
            raise ApiError(401, "UNAUTHORIZED", "Invalid or expired token")
        return self._backend.enroll(access_token, friendly_name)

    def challenge(self, access_token: str, factor_id: str) -> MfaChallenge:
        """Open a challenge against an enrolled factor. The returned
        ``challenge_id`` is verified with the user's 6-digit code."""
        if not access_token or not access_token.strip():
            raise ApiError(401, "UNAUTHORIZED", "Invalid or expired token")
        if not factor_id:
            raise _invalid_mfa_code()
        return self._backend.challenge(access_token, factor_id)

    def verify(
        self, access_token: str, factor_id: str, challenge_id: str, code: str
    ) -> MfaVerifiedSession:
        """Verify a 6-digit TOTP code against a challenge.

        Raises:
            ApiError: 401 ``INVALID_MFA_CODE`` on a wrong or malformed
                code, an expired challenge, or an unknown factor.
        """
        if not access_token or not access_token.strip():
            raise ApiError(401, "UNAUTHORIZED", "Invalid or expired token")
        if not factor_id or not challenge_id or not _CODE_RE.match(code or ""):
            raise _invalid_mfa_code()
        return self._backend.verify(access_token, factor_id, challenge_id, code)

    def challenge_and_verify(
        self, access_token: str, factor_id: str, code: str
    ) -> MfaVerifiedSession:
        """One-call sign-in MFA: open a challenge, verify the code
        against it. Used by the login flow (and identically by the
        Founder step-up flow — see :meth:`verify_step_up`)."""
        challenge = self.challenge(access_token, factor_id)
        return self.verify(access_token, factor_id, challenge.challenge_id, code)

    def list_factors(self, access_token: str) -> list[MfaFactor]:
        """All enrolled factors for the token's user."""
        if not access_token or not access_token.strip():
            raise ApiError(401, "UNAUTHORIZED", "Invalid or expired token")
        return self._backend.list_factors(access_token)

    def has_verified_totp_factor(self, access_token: str) -> bool:
        """True when the user has at least one VERIFIED TOTP factor.

        The login flow uses this to decide enroll-vs-challenge: a staff
        account with no verified factor must complete enrollment
        before it can sign in (MFA is required, never optional).
        """
        return any(
            factor.factor_type == "totp" and factor.status == "verified"
            for factor in self.list_factors(access_token)
        )

    def verify_step_up(self, access_token: str, factor_id: str, code: str) -> MfaVerifiedSession:
        """Founder step-up MFA: a fresh TOTP check for the current
        session. Identical mechanics to sign-in MFA; the caller marks
        the staff session step-up-verified via
        ``sessions.SessionManager.mark_step_up_verified`` on success.
        Honoured only when ``settings.staff_step_up_mfa`` is on — the
        flag check itself lives with the caller (the Founder gate),
        this method always performs the check when called."""
        return self.challenge_and_verify(access_token, factor_id, code)

    def unenroll(self, access_token: str, factor_id: str) -> None:
        """Remove a factor (Owner re-enrollment power: unenroll, then
        the staff member enrolls a fresh factor)."""
        if not access_token or not access_token.strip():
            raise ApiError(401, "UNAUTHORIZED", "Invalid or expired token")
        if not factor_id:
            return
        self._backend.unenroll(access_token, factor_id)


# --- Module-level override (tests / explicit wiring) -----------------------
# Mirrors app/auth/provider.py: production uses the GoTrue backend,
# tests replace it explicitly via ``set_mfa_service``; there is no
# implicit fake fallback anywhere.

_mfa_service_override: MfaService | None = None


def get_mfa_service() -> MfaService:
    """Return the active MFA service (test override wins, else GoTrue)."""
    if _mfa_service_override is not None:
        return _mfa_service_override
    return MfaService()


def set_mfa_service(service: MfaService | None) -> None:
    """Override the active MFA service (tests only). ``None`` clears it."""
    global _mfa_service_override
    _mfa_service_override = service
