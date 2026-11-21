/**
 * Staff-door API client — `/staff/auth/*` endpoints ONLY.
 *
 * Contract: docs/admin-foundation-plan.md §3 (Child C owns the server side).
 * All staff endpoints are written exactly as specified there — no `/api/v1`
 * prefix.
 *
 * SAME-ORIGIN ONLY (NEW1 fix, 20 Nov 2026): the browser calls
 * `/api/staff/...` on its own origin — never the API origin directly.
 * The web middleware (`apps/web/src/middleware.ts`) proxies those calls
 * to the API and adds the secret staff path prefix SERVER-SIDE. The
 * client never sees the prefix, and `NEXT_PUBLIC_API_URL` is NOT used
 * here at all: putting the prefix into a public env var would bake the
 * secret into the JS bundle. The customer client in `./api` still uses
 * `NEXT_PUBLIC_API_URL` directly — staff calls are the exception.
 *
 * STAFF SESSION IS SEPARATE from the customer session: the staff token is
 * kept under its own key (`wshq_staff_token`) and is never mixed with the
 * customer token (`wshq_access_token`). A 401 here clears only the staff
 * token and never fires the customer unauthorized handler — a staff 401
 * just means "sign in again at the staff door".
 *
 * ERROR SHAPE: the API returns the one standard error format
 * `{ code, message, details }`. Callers MUST NOT surface the API's 401
 * message verbatim: the server deliberately returns the same generic
 * `INVALID_CREDENTIALS` message for a wrong password, a wrong role, an
 * unknown email, and a suspended account (no enumeration — messages AND
 * timing). The login page shows its own fixed generic string for any 401.
 */

import { ApiError, type ApiErrorBody } from "./api";

/** Platform roles, server values (lowercase). The login page shows the
 * display labels "Owner" / "Admin" / "Support Staff" for these. */
export type StaffRole = "owner" | "admin" | "support";

export interface StaffUser {
  id: string;
  email: string;
  role: StaffRole;
}

export interface StaffSession {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  user?: StaffUser;
}

/**
 * `POST /staff/auth/login` response (real contract, Child C):
 * MFA is always required for staff, so a successful login returns
 * the AAL1 token and NO staff session — the session is issued only
 * by `/mfa/verify` (enrolled account) or `/mfa/confirm` (after
 * enrollment). `enroll_required` is true when the account has no
 * verified TOTP factor yet and must finish MFA setup first.
 */
export interface StaffLoginResponse {
  mfa_required: boolean;
  enroll_required?: boolean;
  supabase_access_token?: string | null;
}

/** `POST /staff/auth/mfa/verify` returns the staff session directly. */
export type StaffMfaVerifyResponse = StaffSession;

/**
 * `POST /staff/auth/invite/accept` returns the created account + next
 * step. NOTE: no MFA material and NO AAL1 token — enrollment starts at
 * the first login, when `/login` returns `enroll_required` + the AAL1
 * token (see `staff_auth.py` contract change §4). The invite page
 * therefore sends the user to staff sign-in on success; it cannot jump
 * straight to MFA setup.
 */
export interface StaffInviteAcceptResponse {
  user: StaffUser;
  message: string;
}

/** `POST /staff/auth/mfa/enroll` returns enrollment material, shown ONCE. */
export interface StaffMfaEnrollResponse {
  qr_uri: string;
  secret: string;
  factor_id: string;
}

/** `POST /staff/auth/mfa/confirm` returns the staff session directly. */
export type StaffMfaConfirmResponse = StaffSession;

export const STAFF_TOKEN_STORAGE_KEY = "wshq_staff_token";

/**
 * The AAL1 token (from `/login`, `enroll_required` accounts) is
 * TRANSITIONAL: it only exists to carry the user from staff sign-in to
 * the MFA setup screen. It lives in `sessionStorage` (tab-scoped, gone
 * when the tab closes) — never in the URL, never in `localStorage`
 * next to the long-lived staff token. Cleared on sign-out and as soon
 * as MFA confirms.
 */
export const STAFF_AAL1_STORAGE_KEY = "wshq_staff_aal1";

/** In-memory copy of the staff token — the source of truth at runtime. */
let inMemoryStaffToken: string | null = null;

/** In-memory copy of the AAL1 token — mirrors the sessionStorage value. */
let inMemoryAal1Token: string | null = null;

export function setStaffToken(token: string | null): void {
  inMemoryStaffToken = token;
  if (typeof window === "undefined") return;
  if (token) {
    window.localStorage.setItem(STAFF_TOKEN_STORAGE_KEY, token);
  } else {
    window.localStorage.removeItem(STAFF_TOKEN_STORAGE_KEY);
  }
}

export function getStaffToken(): string | null {
  if (inMemoryStaffToken) return inMemoryStaffToken;
  if (typeof window === "undefined") return null;
  inMemoryStaffToken = window.localStorage.getItem(STAFF_TOKEN_STORAGE_KEY);
  return inMemoryStaffToken;
}

export function clearStaffToken(): void {
  setStaffToken(null);
}

export function setStaffAal1Token(token: string | null): void {
  inMemoryAal1Token = token;
  if (typeof window === "undefined") return;
  if (token) {
    window.sessionStorage.setItem(STAFF_AAL1_STORAGE_KEY, token);
  } else {
    window.sessionStorage.removeItem(STAFF_AAL1_STORAGE_KEY);
  }
}

export function getStaffAal1Token(): string | null {
  if (inMemoryAal1Token) return inMemoryAal1Token;
  if (typeof window === "undefined") return null;
  inMemoryAal1Token = window.sessionStorage.getItem(STAFF_AAL1_STORAGE_KEY);
  return inMemoryAal1Token;
}

export function clearStaffAal1Token(): void {
  setStaffAal1Token(null);
}

/**
 * Same-origin staff API base: the browser calls `/api/staff/...` on its
 * own origin and the web middleware proxies to the API, adding the
 * secret staff path prefix server-side. There is deliberately NO
 * `NEXT_PUBLIC_API_URL` here — the prefix must never reach the bundle.
 */
function staffApiBaseUrl(): string {
  return "/api";
}

/**
 * Accept the session in either shape the contract allows: the documented
 * `{ access_token, ... }` object, or a bare token string. Anything else
 * is a server bug — return null instead of inventing a session.
 */
function asStaffSession(value: unknown): StaffSession | null {
  if (typeof value === "string" && value.length > 0) {
    return { access_token: value };
  }
  if (
    typeof value === "object" &&
    value !== null &&
    typeof (value as StaffSession).access_token === "string" &&
    (value as StaffSession).access_token.length > 0
  ) {
    return value as StaffSession;
  }
  return null;
}

interface StaffRequestOptions {
  method?: string;
  body?: unknown;
  /** Set false for public auth endpoints so a 401 does not clear a session. */
  auth?: boolean;
  /** Explicit bearer token (e.g. the AAL1 token from login) — used
   * instead of the stored staff token when set. */
  bearer?: string;
}

async function staffRequest<T>(
  path: string,
  options: StaffRequestOptions = {},
): Promise<T> {
  const { method = "GET", body, auth = true, bearer } = options;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const token = bearer ?? (auth ? getStaffToken() : null);
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(`${staffApiBaseUrl()}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, {
      code: "NETWORK_ERROR",
      message:
        "Could not reach the WebSurfaceHQ API. Check your connection and try again.",
    });
  }

  const retryAfterHeader = res.headers.get("Retry-After");
  const retryAfter = retryAfterHeader
    ? Number.parseInt(retryAfterHeader, 10)
    : null;

  if (!res.ok) {
    if (res.status === 401 && auth) {
      // Staff session invalid/expired: drop it locally. No redirect here —
      // the staff page shows its own generic sign-in-again state.
      clearStaffToken();
    }
    let parsed: ApiErrorBody = {
      code: "INTERNAL_ERROR",
      message: "Something went wrong. Please try again.",
    };
    try {
      const json: unknown = await res.json();
      if (
        typeof json === "object" &&
        json !== null &&
        typeof (json as ApiErrorBody).code === "string" &&
        typeof (json as ApiErrorBody).message === "string"
      ) {
        parsed = json as ApiErrorBody;
      }
    } catch {
      // Non-JSON error body: keep the generic message above.
    }
    throw new ApiError(
      res.status,
      parsed,
      Number.isNaN(retryAfter) ? null : retryAfter,
    );
  }

  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

/* ---- Staff auth endpoints (contract: admin-foundation-plan.md §3) ---- */

/**
 * Role-first staff sign-in. The server verifies the account's REAL role
 * and refuses a mismatch with the same generic 401 as a wrong password.
 * Always returns `{ mfa_required: true, ... }` with the AAL1 token —
 * no staff session exists until MFA verifies. When `enroll_required`
 * is true the account has no verified TOTP factor yet (MFA setup not
 * complete); the caller must not attempt a verify.
 */
export async function staffLogin(
  role: StaffRole,
  email: string,
  password: string,
): Promise<StaffLoginResponse> {
  return staffRequest<StaffLoginResponse>("/staff/auth/login", {
    method: "POST",
    body: { role, email, password },
    auth: false,
  });
}

/**
 * Verifies the TOTP code for a login. Body is `{ code }` only — the
 * challenge is created server-side; the AAL1 token from `staffLogin`
 * goes in the `Authorization` header. Returns the staff session on
 * success. The caller stores it via `setStaffToken(session.access_token)`.
 */
export async function staffMfaVerify(
  code: string,
  aal1Token: string,
): Promise<StaffSession> {
  const res = await staffRequest<StaffMfaVerifyResponse>(
    "/staff/auth/mfa/verify",
    {
      method: "POST",
      body: { code },
      auth: false,
      bearer: aal1Token,
    },
  );
  const session = asStaffSession(res);
  if (!session) {
    throw new ApiError(500, {
      code: "INTERNAL_ERROR",
      message: "Something went wrong. Please try again.",
    });
  }
  return session;
}

/** Revokes the server-side staff session row. The local token is cleared
 * by the caller regardless of the result (see the login page). */
export function staffLogout(): Promise<void> {
  return staffRequest<void>("/staff/auth/logout", { method: "POST" });
}

/**
 * Password recovery (email), not registration. The server always answers
 * 200 — no enumeration — so callers show the same confirmation whether
 * or not an account exists for the email.
 */
export function staffForgotPassword(email: string): Promise<void> {
  return staffRequest<void>("/staff/auth/forgot-password", {
    method: "POST",
    body: { email },
    auth: false,
  });
}

/**
 * Accept a staff invite: claim the single-use token and create the
 * account with the staff member's own password. The server answers the
 * SAME 404 for an expired, used, or invalid token — callers show one
 * generic message for any failure and never say which case it was.
 * Returns the created account (email + role); MFA enrollment starts
 * at the first sign-in, not here.
 */
export function staffInviteAccept(
  token: string,
  password: string,
): Promise<StaffInviteAcceptResponse> {
  return staffRequest<StaffInviteAcceptResponse>("/staff/auth/invite/accept", {
    method: "POST",
    body: { token, password },
    auth: false,
  });
}

/**
 * Start MFA enrollment for an account that has not enrolled yet. The
 * AAL1 token (from `staffLogin`, `enroll_required` accounts) goes in
 * the `Authorization` header. Returns the enrollment material — QR URI,
 * secret, factor id — shown ONCE; the caller must not store it beyond
 * this screen.
 */
export function staffMfaEnroll(
  aal1Token: string,
): Promise<StaffMfaEnrollResponse> {
  return staffRequest<StaffMfaEnrollResponse>("/staff/auth/mfa/enroll", {
    method: "POST",
    auth: false,
    bearer: aal1Token,
  });
}

/**
 * Activate the pending MFA factor with a valid TOTP code. Body is
 * `{ factor_id, code }`; the AAL1 token goes in the `Authorization`
 * header. Returns the staff session on success — the sign-in
 * completes here. The caller stores it via
 * `setStaffToken(session.access_token)` and clears the AAL1 token.
 */
export async function staffMfaConfirm(
  factorId: string,
  code: string,
  aal1Token: string,
): Promise<StaffSession> {
  const res = await staffRequest<StaffMfaConfirmResponse>(
    "/staff/auth/mfa/confirm",
    {
      method: "POST",
      body: { factor_id: factorId, code },
      auth: false,
      bearer: aal1Token,
    },
  );
  const session = asStaffSession(res);
  if (!session) {
    throw new ApiError(500, {
      code: "INTERNAL_ERROR",
      message: "Something went wrong. Please try again.",
    });
  }
  return session;
}

/**
 * Founder step-up check (flag `STAFF_STEP_UP_MFA`, default ON): marks the
 * current staff session step-up-verified so the Owner may open the Founder
 * screen. Used by the Founder screen, not by the login page. The staff
 * session carries no GoTrue token, so the password is re-proved here
 * (sudo-style) alongside the fresh TOTP code.
 */
export function staffStepUpVerify(
  password: string,
  code: string,
): Promise<void> {
  return staffRequest<void>("/staff/auth/step-up/verify", {
    method: "POST",
    body: { password, code },
  });
}
