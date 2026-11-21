"""Staff-door auth endpoints (``/staff/auth``).

Role-first login (DESIGN-LOCK.md "Staff login design", 15 Nov 2026):
the page asks the role first (Owner / Admin / Support cards, none
pre-selected); the server verifies the account's REAL role and refuses
a mismatch with the SAME generic error as a wrong password.

Anti-enumeration (plan §3 — critical): ``POST /login`` returns the
SAME status, code, and message (``401 INVALID_CREDENTIALS`` /
"Invalid role, email, or password") for wrong password, wrong role
card, unknown email, and suspended account — and, as far as practical,
the same timing. The handler ALWAYS runs the password check first
(``provider.sign_in`` — the dominant cost in production, bcrypt via
GoTrue) and ALWAYS runs the staff-role lookup afterwards, on the same
code path, before raising the one generic error. Timing equalization
(H1 fix, 20 Nov 2026): every path performs identical work — on a
failed password check where no Auth user exists for the email (the
unknown-email shape, where GoTrue skipped bcrypt) a time-based
dummy password-hash verification of bcrypt-equivalent duration
runs; when an Auth user exists, bcrypt ran and the dummy is
skipped (provider existence lookup — no double-count); the role
lookup by email is never skipped on failure; and a factor-list-shaped
attempt runs on every path (real list on success, real-token or
dummy-token attempt on failure). Only a non-401 provider error
(429 / 502 / 503) escapes as itself — a rate limit or an outage is
not a credential failure and must not be disguised as one. Customer
accounts at the staff door get the same generic 401 (they have no
staff row).

MFA + sessions (Child B — ``app.auth.mfa`` / ``app.auth.sessions``):
this router calls B's interfaces and duplicates nothing:

- Login flow order (coordinator, 20 Nov 2026): password, then the
  stored factor check (``MfaService.list_factors`` against the
  account's ``current_factor_id`` — unenrolled when there is no
  stored verified factor), then ``challenge_and_verify``, then
  ``SessionManager.issue``. No staff session exists until MFA has
  verified — a session is the proof that password + TOTP both passed.
- The login response carries the Supabase AAL1 access token (the
  client presents it at ``/mfa/verify`` / ``/mfa/enroll`` /
  ``/mfa/confirm``); the staff session UUID is issued only by the
  MFA endpoints. ``get_mfa_service()`` is used (not
  ``provider.mfa``) because it is the overridable access path — in
  production both return the same GoTrue-backed service.
- The stored ``current_factor_id`` is what makes Owner MFA
  re-enrollment EFFECTIVE: login and verify only ever challenge the
  stored factor, so clearing it (``staff.mfa_re_enroll_staff``)
  retires the old factor from the staff flow even though the GoTrue
  factor row itself still exists (Admin-API removal is a Child B
  follow-up). Factors enrolled outside the staff flow are NOT
  adopted — the user enrolls via the staff UI.
- Step-up (Founder gate): ``step_up_required(session)`` is the
  gate (Child D); this endpoint performs the fresh check —
  ``MfaService.verify_step_up`` — then
  ``SessionManager.mark_step_up_verified``. ``verify_step_up`` needs
  a GoTrue access token, which the staff session does not carry, so
  the endpoint re-proves the password (``{password, code}``) to mint
  a fresh AAL1 token — step-up is a sudo-style re-authentication.

CONTRACT CHANGES vs plan §3 (coordinator to confirm — B's interface
requires them; the plan was written before B landed):

1. ``/mfa/verify`` body is ``{code}`` (no ``challenge_id``) — the
   challenge is created server-side inside ``challenge_and_verify``;
   the AAL1 token arrives in the ``Authorization`` header.
2. ``/login`` returns ``{mfa_required, enroll_required,
   supabase_access_token}`` (the AAL1 token) and NO staff session;
   the session is issued only by ``/mfa/verify`` / ``/mfa/confirm``.
3. ``/mfa/enroll`` response adds ``factor_id``; ``/mfa/confirm``
   body adds ``factor_id`` and returns the staff session.
4. ``/invite/accept`` returns ``{user, message}`` — no MFA material:
   enrollment starts at the first login (``enroll_required`` flow).
5. ``/step-up/verify`` body is ``{password, code}`` (see above).
6. ``StaffSessionResponse.access_token`` is the staff session UUID;
   ``supabase_access_token`` (the AAL2 token) is TRANSITIONAL — it
   lets the client call Child D's currently JWT-authed ``/admin``
   routes until D switches them to staff-session auth; it is the
   user's own GoTrue token, not a new exposure.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

from app.auth.deps import get_bearer_token, get_current_user
from app.auth.jwt import User
from app.auth.mfa import MfaService, get_mfa_service
from app.auth.provider import get_auth_provider
from app.auth.rate_limit import (
    INVITE_ACCEPT_MAX_ATTEMPTS,
    INVITE_ACCEPT_WINDOW_SECONDS,
    MFA_MAX_ATTEMPTS,
    MFA_WINDOW_SECONDS,
    get_rate_limiter,
)
from app.auth.sessions import StaffSession
from app.core.config import settings
from app.core.errors import ApiError
from app.core.logging import logger
from app.services.invites import (
    StaffRole,
    claim_invite,
    hash_invite_token,
    is_well_formed_invite_token,
)
from app.services.staff import (
    DuplicateOwnerError,
    DuplicateStaffError,
    StaffAccount,
    activate_staff_factor,
    create_staff_account,
    ensure_staff_account,
    get_staff_account,
    get_staff_account_by_email,
    get_staff_session_manager,
    resolve_staff_role,
    set_staff_pending_factor,
)

router = APIRouter(prefix="/staff/auth", tags=["staff-auth"])

# --- Request / response models -----------------------------------------------
# Passwords: min 8, max 128 (same bounds as the customer auth endpoints).
# The role is the card the user picked — a question, not a permission:
# the server compares it against the stored role and refuses a mismatch
# with the generic 401 (see module docstring).


class StaffLoginRequest(BaseModel):
    """POST /staff/auth/login body."""

    role: Literal["owner", "admin", "support"]
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class MfaVerifyRequest(BaseModel):
    """POST /staff/auth/mfa/verify body (AAL1 token in Authorization)."""

    code: str = Field(pattern=r"^\d{6}$")


class MfaConfirmRequest(BaseModel):
    """POST /staff/auth/mfa/confirm body (AAL1 token in Authorization).

    ``existing_code`` is REQUIRED when the account already has a
    verified factor (C1 defense-in-depth: a replacement factor is
    confirmed only after a code against the EXISTING factor verifies
    — a password-only attacker who somehow holds a pending factor
    cannot displace the victim's factor without the victim's
    authenticator too). It is absent for first enrollment and for
    re-enrollment after the Owner cleared the factor.
    """

    factor_id: str = Field(min_length=1, max_length=128)
    code: str = Field(pattern=r"^\d{6}$")
    existing_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class ForgotPasswordRequest(BaseModel):
    """POST /staff/auth/forgot-password body."""

    email: EmailStr


class InviteAcceptRequest(BaseModel):
    """POST /staff/auth/invite/accept body."""

    token: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=8, max_length=128)


class StepUpVerifyRequest(BaseModel):
    """POST /staff/auth/step-up/verify body (staff session in Authorization)."""

    password: str = Field(min_length=8, max_length=128)
    code: str = Field(pattern=r"^\d{6}$")


class StaffUserResponse(BaseModel):
    """A staff identity (never contains secrets)."""

    id: str
    email: str
    role: StaffRole


class StaffSessionResponse(BaseModel):
    """A signed-in staff session.

    ``access_token`` is the staff session UUID — the staff API
    credential. ``supabase_access_token`` is the user's own GoTrue
    AAL2 token (transitional — see module docstring §6).
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: StaffUserResponse
    supabase_access_token: str | None = None


class StaffLoginResponse(BaseModel):
    """POST /login: MFA is always required for staff.

    - Enrolled account: ``{mfa_required: true,
      supabase_access_token}`` — the client presents the AAL1 token
      at ``/mfa/verify`` with the TOTP code.
    - Not-yet-enrolled account: ``{mfa_required: true,
      enroll_required: true, supabase_access_token}`` — the client
      presents the AAL1 token at ``/mfa/enroll`` to start enrollment.
    No staff session is issued before MFA verifies.
    """

    mfa_required: bool
    enroll_required: bool = False
    supabase_access_token: str | None = None


class MfaEnrollResponse(BaseModel):
    """POST /mfa/enroll: enrollment material, shown ONCE."""

    qr_uri: str
    secret: str
    factor_id: str


class InviteAcceptResponse(BaseModel):
    """POST /invite/accept: the created account + next step."""

    user: StaffUserResponse
    message: str


class StepUpVerifyResponse(BaseModel):
    """POST /step-up/verify."""

    step_up_verified: bool


class MessageResponse(BaseModel):
    """A human-readable confirmation message."""

    message: str


# --- Helpers -------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _email_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def _invalid_credentials() -> ApiError:
    """The ONE login error — same for wrong password / wrong role /
    unknown email / suspended account / customer account."""
    return ApiError(401, "INVALID_CREDENTIALS", "Invalid role, email, or password")


def _invalid_session() -> ApiError:
    """The ONE staff-session error (same as Child B's INVALID_SESSION)."""
    return ApiError(401, "INVALID_SESSION", "Session is invalid or expired")


def _client_ip(request: Request) -> str:
    """Best-effort client IP (same rule as the customer auth router:
    X-Forwarded-For is trusted only behind a trusted reverse proxy)."""
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


def _enforce_staff_rate_limit(request: Request, email: str | None) -> JSONResponse | None:
    """Login/signup/reset limits (5 attempts / 15 min per IP + per email).

    Same contract as the customer auth endpoints. ``email=None`` checks
    the per-IP key only (MFA verify / confirm / invite accept / step-up,
    where no email is in the body).
    """
    limiter = get_rate_limiter()
    allowed, retry_after = limiter.check(f"staff-login:ip:{_client_ip(request)}")
    if not allowed:
        return _rate_limited_response(retry_after)
    if email is not None:
        allowed, retry_after = limiter.check(f"staff-login:email:{email.lower()}")
        if not allowed:
            return _rate_limited_response(retry_after)
    return None


def _enforce_per_account_rate_limit(
    key: str, *, max_attempts: int = MFA_MAX_ATTEMPTS, window_seconds: int = MFA_WINDOW_SECONDS
) -> JSONResponse | None:
    """Per-account MFA bucket (M2 fix): 5 attempts / 15 min per user
    id (verify / confirm / enroll / step-up) or per invite-token hash
    (invite accept — pass that bucket's constants). Applies IN
    ADDITION to the shared per-IP bucket — an attacker spraying TOTP
    codes from many IPs still hits this wall. Returns the 429
    response, or None when allowed."""
    allowed, retry_after = get_rate_limiter().check_account(
        key, max_attempts=max_attempts, window_seconds=window_seconds
    )
    if not allowed:
        return _rate_limited_response(retry_after)
    return None


# --- Timing equalization (H1 fix) -------------------------------------------
# GoTrue runs bcrypt only when the user EXISTS. A remote timing probe
# could therefore tell "unknown email" (fast 401, no bcrypt) from
# "wrong password" (bcrypt-time 401) from "correct password"
# (bcrypt + PostgREST role read + GoTrue factor list). The login
# handler below performs IDENTICAL work on every path:
#   * password check first (always — GoTrue sign_in);
#   * on a failed password check where NO Auth user exists for the
#     email (the unknown-email shape, where GoTrue skipped bcrypt),
#     a dummy password-hash verification of the same duration as
#     bcrypt (see _dummy_password_verification);
#   * the dummy runs ONLY when bcrypt did not — after a failed
#     sign-in the handler asks the provider whether an Auth user
#     exists for the email (service-role Admin API lookup, cheap,
#     no bcrypt): exists means bcrypt ran, so the dummy is SKIPPED
#     (H1 double-count fix, 20 Nov 2026 — a customer email with a
#     wrong password used to pay bcrypt AND the dummy, ~one
#     dummy-hash slower than a staff wrong-password);
#   * role lookup by email on every path (never skipped on failure);
#   * a factor-list-shaped attempt on every path (the real list when
#     an AAL1 token exists, a dummy-token attempt otherwise).
# The dummy hash uses PBKDF2-HMAC-SHA256, not bcrypt: no bcrypt
# library is a dependency of this repo (adding one needs owner
# approval per the repo rules), and the real check happens in GoTrue
# anyway — the dummy only needs the same DURATION. It is TIME-BASED
# (H1 retune, 20 Nov 2026): it loops PBKDF2 blocks until the
# configured target (``STAFF_DUMMY_HASH_TARGET_MS``, default 75 ms)
# has elapsed, so it self-calibrates to any host CPU instead of
# assuming a fixed iteration count costs what bcrypt costs. The
# target is the measured GoTrue bcrypt component: live probe 20 Nov
# 2026 (3 runs x 10 attempts per path against the real project)
# gave wrong-password medians 403/479/453 ms vs unknown-email
# 344/406/363 ms — bcrypt ≈ 59/73/90 ms (median-of-diffs ~73 ms,
# rounded to 75). Exact equality is impossible remotely; the goal
# is to close the unknown-vs-known gap to within network jitter.
# RESIDUAL (documented): the equalizer's target is a single number
# while real bcrypt varies a little per attempt, and the Admin-API
# lookup adds a few ms on the failure path only — both are far
# below the ~400 ms network baseline from a remote prober, so the
# residual gap is within jitter, not a usable oracle.

_DUMMY_HASH_BLOCK_ITERATIONS = 20_000
_DUMMY_HASH_SALT = b"websurfacehq-staff-login-dummy"
_DUMMY_HASH = hashlib.pbkdf2_hmac(
    "sha256", b"websurfacehq-dummy-password", _DUMMY_HASH_SALT, _DUMMY_HASH_BLOCK_ITERATIONS
)


def _dummy_password_verification(password: str, *, target_ms: float | None = None) -> None:
    """Burn ~one bcrypt worth of wall-clock time on the unknown-email path.

    Loops PBKDF2 blocks (20k iterations each, ~10 ms on this VM)
    until ``target_ms`` (default
    ``settings.staff_dummy_hash_target_ms``) has elapsed, then
    constant-time-compares the last block against a fixed dummy
    hash. The result is DISCARDED — this is timing cover, never an
    authentication decision: the caller raises the generic 401
    either way. Time-based, not iteration-count-based, so the same
    target burns the same duration on any host CPU; the block size
    bounds the overshoot past the target to ~one block (~10 ms).
    """
    target = target_ms if target_ms is not None else settings.staff_dummy_hash_target_ms
    deadline = time.monotonic() + target / 1000.0
    derived = _DUMMY_HASH
    while True:
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8", "ignore"),
            _DUMMY_HASH_SALT,
            _DUMMY_HASH_BLOCK_ITERATIONS,
        )
        hmac.compare_digest(derived, _DUMMY_HASH)
        if time.monotonic() >= deadline:
            return


def _auth_user_exists(email: str) -> bool:
    """True when an Auth user exists for ``email`` (provider lookup).

    Never raises: a lookup failure answers False (run the dummy —
    the timing cover stays on) and is logged by the provider. The
    answer is server-internal only and never reaches a response.
    """
    try:
        return get_auth_provider().user_exists(email)
    except Exception:  # noqa: BLE001 - lookup failure must not break login
        logger.warning("auth user-existence lookup failed; running dummy hash")
        return False


def _dummy_factor_list_attempt(access_token: str | None) -> None:
    """A factor-list-shaped attempt for the failure paths (H1).

    The success path calls ``MfaService.list_factors`` with the real
    AAL1 token; failure paths call it with the AAL1 token when one
    exists (wrong role / suspended — password was correct) or with a
    dummy token otherwise (unknown email / wrong password — GoTrue
    answers 401 after one round trip, the same work shape). Any
    error is swallowed: this is timing cover, and the caller raises
    the generic 401 either way."""
    try:
        get_mfa_service().list_factors(access_token or "invalid-dummy-token")
    except Exception:  # noqa: BLE001 - timing cover only, never a decision
        pass


# Namespace for the synthetic failed-login actor (F4 fix): UUIDv5
# over the email hash, so the actor is deterministic per address
# (failures group) without storing the address. Derived from a
# fixed string, not random — the same address always maps to the
# same actor id on every replica and every restart.
_FAILED_LOGIN_ACTOR_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "websurfacehq:staff-login-failed-actor"
)


def _audit_staff_auth(user_id: UUID | None, action: str, metadata: dict[str, Any]) -> None:
    """Best-effort audit for auth-flow events (same rule as the customer
    auth router): store audit log when available, always a log line.
    Never raises — a down audit store must not 500 a sign-in. (Admin
    MUTATIONS in app.services.staff use audit.write, which is loud by
    Child A's contract; auth events are not mutations.)

    F4 fix (red-team, 20 Nov 2026): failed logins used to write
    NOTHING — this helper skipped the store write whenever
    ``user_id`` was None, and ``staff.login_failed`` was always
    called with None. A failed login now always writes one row:

    - Known staff account: the account's real user id is the actor
      (the caller passes it) — the row persists on every backend.
    - Unknown email (no account, no actor): the actor is a
      deterministic UUIDv5 derived from the email hash (never the
      plaintext email), so repeated failures for one address group
      under one actor without ever storing the address itself.

    Documented limit: ``audit_logs.user_id`` is ``NOT NULL
    REFERENCES auth.users(id)``, so on the Supabase path a synthetic
    actor satisfies no FK row — the insert fails and is swallowed
    here (best-effort), leaving unknown-email failures as log lines
    only in production. Known-account failures persist with the real
    actor id. A NULL actor is not an option (the column forbids it),
    and attributing the failure to any real user (e.g. the Owner)
    would be false attribution. Lifting this limit needs a schema
    change (nullable actor or a dedicated failed-login table) — a
    Week 3 hardening item, not this fix.
    """
    actor = user_id
    if actor is None:
        email_hash = metadata.get("email_hash")
        if isinstance(email_hash, str) and email_hash:
            actor = uuid.uuid5(_FAILED_LOGIN_ACTOR_NAMESPACE, f"staff-login-failed:{email_hash}")
    try:
        if actor is not None:
            from app.db import get_store

            get_store().log_audit(
                user_id=actor, action=action, target_domain=None, metadata=metadata
            )
    except Exception:  # noqa: BLE001 - audit must never break the endpoint
        logging.getLogger("websurfacehq").warning(
            "audit log unavailable for staff auth event",
            extra={"action": action, **metadata},
        )
    logger.info("staff auth event", extra={"action": action, **metadata})


def _build_session_response(
    session: StaffSession,
    account: StaffAccount,
    now: datetime,
    supabase_access_token: str | None,
) -> StaffSessionResponse:
    """The MFA-verify / MFA-confirm response for a freshly issued session."""
    remaining = int(
        (session.issued_at + timedelta(hours=session.absolute_hours) - now).total_seconds()
    )
    return StaffSessionResponse(
        access_token=str(session.id),
        expires_in=max(remaining, 0),
        user=StaffUserResponse(
            id=str(account.user_id),
            email=account.email,
            role=cast(StaffRole, account.role),
        ),
        supabase_access_token=supabase_access_token,
    )


def _account_for_session(session: StaffSession) -> StaffAccount:
    """The staff account behind a session, or 401 when it is gone."""
    account = get_staff_account(session.user_id)
    if account is None:
        raise _invalid_session()
    return account


def _require_active_staff(user: User) -> StaffAccount:
    """The staff account behind a verified JWT, or 403 (mirrors Child
    D's ``get_current_staff``: a valid token naming no active staff
    account is forbidden, not unauthenticated).

    The row is resolved store-first (``ensure_staff_account``): a
    staff user the store knows but the provisional registry lost
    (restart) is re-created from the authoritative store row."""
    account = ensure_staff_account(user.id, user.email)
    if account is None or account.status != "active":
        raise ApiError(403, "FORBIDDEN", "This account is not an active staff account")
    return account


def _resolve_enrolled_factor(
    mfa: MfaService, access_token: str, account: StaffAccount
) -> str | None:
    """The account's stored factor id when it is a VERIFIED TOTP factor
    in GoTrue, else None (unenrolled — the login flow must enroll).

    Only the STORED factor ever counts: clearing it (Owner MFA
    re-enrollment) retires the old factor from the staff flow, and
    factors enrolled outside the staff flow are not adopted.
    """
    if account.current_factor_id is None:
        return None
    for factor in mfa.list_factors(access_token):
        if (
            factor.factor_id == account.current_factor_id
            and factor.factor_type == "totp"
            and factor.status == "verified"
        ):
            return factor.factor_id
    return None


# --- Session dependency ----------------------------------------------------------


async def get_staff_session(
    authorization: str | None = Header(default=None),
) -> StaffSession:
    """Return the live staff session behind ``Authorization: Bearer``.

    The bearer is the session UUID (Child B's opaque token). Unknown,
    malformed, revoked, expired, idle-timed-out, or stale-prefix
    sessions all raise the same generic 401 ``INVALID_SESSION``.
    """
    if not authorization:
        raise _invalid_session()
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _invalid_session()
    try:
        session_id = UUID(token.strip())
    except ValueError:
        raise _invalid_session() from None
    return get_staff_session_manager().validate(session_id)


# --- Endpoints -------------------------------------------------------------------


@router.post("/login", response_model=StaffLoginResponse)
def staff_login(body: StaffLoginRequest, request: Request) -> StaffLoginResponse | JSONResponse:
    """Role-first staff sign-in.

    The password check ALWAYS runs first; the role/status checks ALWAYS
    run after it, on the same code path; every failure raises the one
    generic 401 (see module docstring). A successful password + role
    match returns the AAL1 token and whether MFA enrollment is still
    needed — no staff session is issued before MFA verifies.

    TIMING (H1 fix): every path performs the same work — sign_in,
    then (on a failed password check where no Auth user exists for
    the email) a time-based dummy password-hash verification
    standing in for the bcrypt GoTrue skipped, then the role
    lookup by email, then a factor-list-shaped attempt — before
    the one generic error is raised. The success path's
    list_factors call is the real one. When an Auth user exists,
    bcrypt ran and the dummy is skipped (no double-count).
    """
    denied = _enforce_staff_rate_limit(request, body.email)
    if denied is not None:
        return denied
    email = body.email.strip().lower()
    auth_session = None
    try:
        auth_session = get_auth_provider().sign_in(email, body.password)
    except ApiError as exc:
        # Only a 401 is a credential failure. A 429 / 502 / 503 is a
        # limiter or provider outage and must propagate as itself.
        if exc.status_code != 401:
            raise
        auth_session = None
    # The staff row by email is read on EVERY path (it decides the
    # role check — never skipped on failure, so no path is cheaper
    # for lacking a row).
    account_by_email = get_staff_account_by_email(email)
    if auth_session is None and not _auth_user_exists(email):
        # Unknown-email shape: GoTrue answered fast (no bcrypt for
        # a user that does not exist). Burn one bcrypt-equivalent
        # dummy verification so this path costs what a
        # wrong-password path costs. The result is discarded — the
        # generic 401 follows. When an Auth user DOES exist, bcrypt
        # already ran inside GoTrue, so the dummy is skipped — a
        # customer email with a wrong password no longer pays
        # bcrypt AND the dummy (H1 double-count fix).
        _dummy_password_verification(body.password)
    # Role + status checks run on the SAME path whether or not the
    # password matched: wrong role, suspended, customer account, and
    # unknown email all land on the one generic error. Platform
    # role/status resolve STORE-FIRST (``Store.get_staff_role``,
    # migration 0007's staff_roles table) via resolve_staff_role
    # when a session exists; on the failure path the row read above
    # supplies the same (role, status).
    if auth_session is not None:
        resolved = resolve_staff_role(auth_session.user.id)
        account = ensure_staff_account(auth_session.user.id, email)
    else:
        account = account_by_email
        resolved = (account.role, account.status) if account is not None else None
    if (
        auth_session is None
        or account is None
        or resolved is None
        or resolved != (body.role, "active")
    ):
        # Factor-list-shaped attempt: the success path lists factors
        # for real; every failure path performs the same-shaped
        # attempt (real token when one exists, dummy token otherwise)
        # before the generic error — no path skips the GoTrue round
        # trip. The audit + 401 below are byte-identical on all
        # failure paths.
        _dummy_factor_list_attempt(auth_session.access_token if auth_session is not None else None)
        # F4 fix: the failed login IS audited. A known staff account
        # audits under its real user id; an unknown email audits
        # under the deterministic synthetic actor
        # (``_audit_staff_auth`` derives it from the email hash) —
        # never the plaintext email, never no row at all.
        _audit_staff_auth(
            account.user_id if account is not None else None,
            "staff.login_failed",
            {"email_hash": _email_hash(email)},
        )
        raise _invalid_credentials()
    _audit_staff_auth(account.user_id, "staff.login", {"role": account.role})
    enrolled_factor = _resolve_enrolled_factor(
        get_mfa_service(), auth_session.access_token, account
    )
    return StaffLoginResponse(
        mfa_required=True,
        enroll_required=enrolled_factor is None,
        supabase_access_token=auth_session.access_token,
    )


@router.post("/mfa/verify", response_model=StaffSessionResponse)
def mfa_verify(
    body: MfaVerifyRequest,
    request: Request,
    user: User = Depends(get_current_user),
    token: str = Depends(get_bearer_token),
) -> StaffSessionResponse | JSONResponse:
    """Complete sign-in: verify the TOTP code for the stored factor.

    The AAL1 token (from ``/login``) arrives in ``Authorization``.
    Success issues the MFA-verified staff session. A wrong code, an
    unknown/expired challenge, or an unknown factor all answer the
    same 401 ``INVALID_MFA_CODE`` (Child B's generic error).
    """
    denied = _enforce_staff_rate_limit(request, None)
    if denied is not None:
        return denied
    account = _require_active_staff(user)
    denied = _enforce_per_account_rate_limit(f"mfa-verify:user:{user.id}")
    if denied is not None:
        return denied
    factor_id = account.current_factor_id
    if factor_id is None:
        raise ApiError(401, "INVALID_MFA_CODE", "Invalid verification code")
    verified = get_mfa_service().challenge_and_verify(token, factor_id, body.code)
    now = _now()
    session = get_staff_session_manager().issue(
        user.id,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _audit_staff_auth(account.user_id, "staff.mfa_verified", {})
    return _build_session_response(session, account, now, verified.access_token)


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
def mfa_enroll(
    request: Request,
    user: User = Depends(get_current_user),
    token: str = Depends(get_bearer_token),
) -> MfaEnrollResponse | JSONResponse:
    """Start MFA enrollment: fresh factor + QR URI + secret.

    The AAL1 token (from ``/login``) arrives in ``Authorization``.
    The secret is shown ONCE; the factor id is stored as the account's
    pending factor until ``/mfa/confirm`` activates it.

    C1 fix: enrollment is refused (409) when the account ALREADY has
    a verified factor — a password-only attacker holding a victim's
    AAL1 token must not be able to enroll a NEW factor and displace
    the victim's. Re-enrollment happens ONLY through the
    Owner-initiated path (``POST /admin/users/{id}/mfa-re-enroll``,
    which clears the stored factor first); this endpoint never
    replaces an enrolled factor. A per-account rate limit also
    applies, so enrollment cannot be sprayed.
    """
    # F5 fix (red-team, 20 Nov 2026): the per-IP bucket was missing
    # here — verify / confirm / step-up all enforce it, enroll did
    # not. Same call shape as the siblings (email=None: IP key only).
    denied = _enforce_staff_rate_limit(request, None)
    if denied is not None:
        return denied
    account = _require_active_staff(user)
    denied = _enforce_per_account_rate_limit(f"mfa-enroll:user:{user.id}")
    if denied is not None:
        return denied
    if account.current_factor_id is not None:
        raise ApiError(
            409,
            "MFA_ALREADY_ENROLLED",
            "Multi-factor authentication is already enrolled. Ask the "
            "Owner to re-enroll it (admin MFA re-enrollment).",
        )
    enrollment = get_mfa_service().enroll(token)
    set_staff_pending_factor(user.id, enrollment.factor_id)
    return MfaEnrollResponse(
        qr_uri=enrollment.qr_uri, secret=enrollment.secret, factor_id=enrollment.factor_id
    )


@router.post("/mfa/confirm", response_model=StaffSessionResponse)
def mfa_confirm(
    body: MfaConfirmRequest,
    request: Request,
    user: User = Depends(get_current_user),
    token: str = Depends(get_bearer_token),
) -> StaffSessionResponse | JSONResponse:
    """Activate the pending MFA factor with a valid TOTP code.

    Verifying the code against the pending factor marks it the
    account's current factor (and the account enrolled), then issues
    the MFA-verified staff session — the sign-in completes here.

    C1 defense-in-depth: when the account ALREADY has a verified
    factor (a replacement pending factor exists alongside it), the
    caller must ALSO present a code against the EXISTING factor
    (``existing_code``) — verified FIRST. Without it (or with a
    wrong one) the confirm fails with the same generic 401, and the
    existing factor is untouched. First enrollment and post-Owner-
    re-enrollment (current factor cleared) need no existing code.
    """
    denied = _enforce_staff_rate_limit(request, None)
    if denied is not None:
        return denied
    account = _require_active_staff(user)
    denied = _enforce_per_account_rate_limit(f"mfa-confirm:user:{user.id}")
    if denied is not None:
        return denied
    pending = account.pending_factor_id
    if pending is None or body.factor_id != pending:
        raise ApiError(401, "INVALID_MFA_CODE", "Invalid verification code")
    existing_factor = account.current_factor_id
    if existing_factor is not None:
        # Replacement confirm: prove possession of the EXISTING
        # factor before the pending one can displace it. A missing
        # or wrong existing code is the same generic 401 as a wrong
        # pending code (no oracle).
        if body.existing_code is None:
            raise ApiError(401, "INVALID_MFA_CODE", "Invalid verification code")
        get_mfa_service().challenge_and_verify(token, existing_factor, body.existing_code)
    verified = get_mfa_service().challenge_and_verify(token, pending, body.code)
    updated = activate_staff_factor(user.id, pending)
    account = updated if updated is not None else account
    now = _now()
    session = get_staff_session_manager().issue(
        user.id,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _audit_staff_auth(account.user_id, "staff.mfa_enrolled", {})
    return _build_session_response(session, account, now, verified.access_token)


@router.post("/logout", response_model=MessageResponse)
def staff_logout(session: StaffSession = Depends(get_staff_session)) -> MessageResponse:
    """Sign out: revoke the staff session row."""
    get_staff_session_manager().revoke(session.id)
    _audit_staff_auth(session.user_id, "staff.logout", {})
    return MessageResponse(message="Signed out")


@router.post("/forgot-password", response_model=MessageResponse)
def staff_forgot_password(
    body: ForgotPasswordRequest, request: Request
) -> MessageResponse | JSONResponse:
    """Request a password-reset email. ALWAYS 200 — known and unknown
    emails answer identically (no enumeration oracle).

    Carve-out (same rule as the customer reset endpoint): only
    unknown-email errors (400/404) are swallowed. A 503 (auth not
    configured) or 502 (provider failure) propagates — an outage must
    not be disguised as a sent email.
    """
    denied = _enforce_staff_rate_limit(request, body.email)
    if denied is not None:
        return denied
    try:
        get_auth_provider().reset_password(body.email)
    except ApiError as exc:
        if exc.status_code not in (400, 404):
            raise
    return MessageResponse(
        message="If an account exists for this email, a password reset link has been sent."
    )


@router.post("/invite/accept", status_code=201, response_model=InviteAcceptResponse)
def invite_accept(
    body: InviteAcceptRequest, request: Request
) -> InviteAcceptResponse | JSONResponse:
    """Accept an invite: claim the token, create the Auth user + staff
    row. MFA enrollment starts at the first login (``enroll_required``
    flow) — GoTrue holds the factor, so there is no enrollment
    material to return here.

    The token is claimed FIRST (atomic single-use) so a lost race or a
    provider failure cannot leave the invite reusable; a consumed
    invite needs a fresh one from the Owner. Expired / used / invalid
    tokens answer the same 404. An already-registered email also
    answers that 404 (the invite is consumed) — linking an existing
    Auth user to a staff role needs an Admin-API lookup the provider
    protocol does not have yet (recorded gap, not silently worked
    around).
    """
    denied = _enforce_staff_rate_limit(request, None)
    if denied is not None:
        return denied
    # Per-invite-token bucket (M2 fix): repeated accepts against one
    # token are throttled by the token's hash (the raw token never
    # enters a key, a log, or a response). N-NEW5: the bucket applies
    # ONLY to well-formed tokens — a garbage string never earns a
    # 429, so the 429 fires only after the token was already
    # validated as well-formed; expired / used / invalid tokens
    # still share the one 404 below. (The per-IP bucket above still
    # throttles garbage-token spam — this gate only narrows the
    # per-token bucket.)
    if is_well_formed_invite_token(body.token):
        denied = _enforce_per_account_rate_limit(
            f"invite-accept:token:{hash_invite_token(body.token)}",
            max_attempts=INVITE_ACCEPT_MAX_ATTEMPTS,
            window_seconds=INVITE_ACCEPT_WINDOW_SECONDS,
        )
        if denied is not None:
            return denied
    invite = claim_invite(body.token)
    if invite is None:
        raise ApiError(404, "NOT_FOUND", "Invalid or expired invite link")
    # sign_up propagates 429 / 502 / 503 as itself (the invite stays
    # consumed — the Owner re-invites; a half-accepted invite must never
    # be reusable).
    created = get_auth_provider().sign_up(invite.email, body.password)
    if created is None:
        # Already registered: same generic 404, no enumeration.
        raise ApiError(404, "NOT_FOUND", "Invalid or expired invite link")
    try:
        account = create_staff_account(created.id, invite.email, invite.role, invite.invited_by)
    except (DuplicateOwnerError, DuplicateStaffError):
        raise ApiError(404, "NOT_FOUND", "Invalid or expired invite link") from None
    _audit_staff_auth(account.user_id, "staff.invite_accepted", {"role": account.role})
    return InviteAcceptResponse(
        user=StaffUserResponse(
            id=str(account.user_id),
            email=account.email,
            role=cast(StaffRole, account.role),
        ),
        message=(
            "Account created. Check your inbox to confirm your email, then "
            "sign in to set up multi-factor authentication."
        ),
    )


@router.post("/step-up/verify", response_model=StepUpVerifyResponse)
def step_up_verify(
    body: StepUpVerifyRequest,
    request: Request,
    session: StaffSession = Depends(get_staff_session),
) -> StepUpVerifyResponse | JSONResponse:
    """Step-up MFA for the Founder screen (flag-gated, default ON).

    The staff session carries no GoTrue token, so the password is
    re-proved here (sudo-style) to mint a fresh AAL1 token, then a
    fresh TOTP check runs (``MfaService.verify_step_up``) and the
    session is marked step-up-verified (Child B's
    ``SessionManager.mark_step_up_verified``). The Founder gate
    (Child D) checks ``step_up_required(session)`` before calling
    this endpoint.
    """
    denied = _enforce_staff_rate_limit(request, None)
    if denied is not None:
        return denied
    account = _account_for_session(session)
    denied = _enforce_per_account_rate_limit(f"step-up:user:{session.user_id}")
    if denied is not None:
        return denied
    factor_id = account.current_factor_id
    if factor_id is None:
        raise ApiError(409, "MFA_NOT_ENROLLED", "Multi-factor authentication is not enrolled")
    try:
        auth_session = get_auth_provider().sign_in(account.email, body.password)
    except ApiError as exc:
        if exc.status_code != 401:
            raise
        # F8 fix (red-team, 20 Nov 2026): this used to answer
        # "Invalid password" — a different message from the
        # login-generic 401, breaking the generic-401 discipline
        # (a prober could tell a step-up password failure from a
        # login failure by the body). Same error as login failures.
        raise _invalid_credentials() from exc
    get_mfa_service().verify_step_up(auth_session.access_token, factor_id, body.code)
    get_staff_session_manager().mark_step_up_verified(session.id)
    _audit_staff_auth(account.user_id, "staff.step_up_verified", {})
    return StepUpVerifyResponse(step_up_verified=True)
