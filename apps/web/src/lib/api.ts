/**
 * WebSurfaceHQ typed API client.
 *
 * Base URL comes ONLY from `NEXT_PUBLIC_API_URL` (env) — never hard-coded.
 * All product endpoints live under `/api/v1/...` (see docs/api-conventions.md).
 * All errors follow the one error format: { code, message, details }.
 *
 * TOKEN STORAGE TRADE-OFF (MVP, deliberate — see also src/lib/auth.tsx):
 * the access token lives in localStorage (`wshq_access_token`) AND in memory
 * in this module. That is the pragmatic choice while the frontend (Vercel)
 * and the API (Render) are on different origins with no shared cookie domain,
 * so an httpOnly cookie cannot be shared. Mitigations: CSP + no inline
 * scripts (see next.config.mjs) reduce XSS exposure, the token is never put
 * in a URL or a log line, and it is cleared on 401. When frontend + API share
 * a domain, move the token to an httpOnly, Secure, SameSite=Lax cookie and
 * delete the localStorage path.
 */

export interface ApiErrorBody {
  code: string;
  message: string;
  /** Pydantic 422s send a LIST of {loc, msg, type}; other errors send a dict. */
  details?: unknown;
}

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details?: unknown;
  /** Seconds from the Retry-After header on 429, null when absent. */
  readonly retryAfter: number | null;

  constructor(
    status: number,
    body: ApiErrorBody,
    retryAfter: number | null = null,
  ) {
    super(body.message);
    this.name = "ApiError";
    this.status = status;
    this.code = body.code;
    this.details = body.details;
    this.retryAfter = retryAfter;
  }
}

export interface User {
  id: string;
  email: string;
  email_verified?: boolean;
  created_at?: string;
}

export interface AuthTokens {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface Target {
  id: string;
  domain: string;
  verification_status: string;
  verification_method?: string | null;
  /** Issued on create; shown to the user ONCE (dashboard), never logged. */
  verification_token?: string;
  created_at: string;
}

export interface Paginated<T> {
  data: T[];
  next_cursor: string | null;
  has_more: boolean;
}

export const TOKEN_STORAGE_KEY = "wshq_access_token";

/** In-memory copy of the token — the source of truth at runtime. */
let inMemoryToken: string | null = null;

export function setToken(token: string | null): void {
  inMemoryToken = token;
  if (typeof window === "undefined") return;
  if (token) {
    window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } else {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

export function getToken(): string | null {
  if (inMemoryToken) return inMemoryToken;
  if (typeof window === "undefined") return null;
  inMemoryToken = window.localStorage.getItem(TOKEN_STORAGE_KEY);
  return inMemoryToken;
}

export function clearToken(): void {
  setToken(null);
}

/**
 * Called on a 401 from an authenticated request (after the token is
 * cleared). Registered by <AuthProvider>, which navigates with Next's
 * router — the client itself never touches window.location.
 */
let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(fn: (() => void) | null): void {
  unauthorizedHandler = fn;
}

function apiBaseUrl(): string {
  const base = process.env.NEXT_PUBLIC_API_URL;
  if (!base) {
    throw new Error(
      "NEXT_PUBLIC_API_URL is not set. Set it to the API origin (e.g. https://api.websurfacehq.com).",
    );
  }
  return base.replace(/\/$/, "");
}

/**
 * Per-field errors from a 422 VALIDATION_ERROR.
 * The API sends Pydantic's list shape: details = [{ loc: ["body", "email"], msg, type }].
 * A dict shape ({ fields: { email: [...] } }) is accepted defensively.
 */
export function fieldErrors(details: unknown): Record<string, string> {
  if (!details) return {};
  if (Array.isArray(details)) {
    const out: Record<string, string> = {};
    for (const entry of details) {
      if (typeof entry !== "object" || entry === null) continue;
      const loc = (entry as { loc?: unknown }).loc;
      const msg = (entry as { msg?: unknown }).msg;
      if (!Array.isArray(loc) || typeof msg !== "string") continue;
      // loc is ["body", "email"] (or ["query", ...] / ["path", ...]).
      const field = [...loc].reverse().find((part) => typeof part === "string");
      if (field) out[field] = msg;
    }
    return out;
  }
  if (typeof details === "object") {
    const fields = (details as Record<string, unknown>).fields;
    if (typeof fields !== "object" || fields === null) return {};
    const out: Record<string, string> = {};
    for (const [field, messages] of Object.entries(
      fields as Record<string, unknown>,
    )) {
      if (Array.isArray(messages) && typeof messages[0] === "string") {
        out[field] = messages[0];
      } else if (typeof messages === "string") {
        out[field] = messages;
      }
    }
    return out;
  }
  return {};
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  /** Set false for public auth endpoints so a 401 does not bounce to /login. */
  auth?: boolean;
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { method = "GET", body, auth = true } = options;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const token = auth ? getToken() : null;
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(`${apiBaseUrl()}${path}`, {
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

  if (res.status === 401 && auth && token) {
    // Session expired/invalid: drop the token and let the registered
    // handler (AuthProvider) send the user to log in.
    // (No token is ever written to a log line here.)
    clearToken();
    unauthorizedHandler?.();
    throw new ApiError(401, {
      code: "UNAUTHORIZED",
      message: "Your session has expired. Please log in again.",
    });
  }

  const retryAfterHeader = res.headers.get("Retry-After");
  const retryAfter = retryAfterHeader
    ? Number.parseInt(retryAfterHeader, 10)
    : null;

  if (!res.ok) {
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

/* ---- Auth endpoints (contract: Builder B) ---- */

/** Signup never returns a user: the response is identical for a fresh
 * signup and an already-registered email (no enumeration oracle). */
export interface SignupResponse {
  message: string;
}

export function signup(email: string, password: string): Promise<SignupResponse> {
  return apiRequest<SignupResponse>("/api/v1/auth/signup", {
    method: "POST",
    body: { email, password },
    auth: false,
  });
}

export function logout(): Promise<void> {
  return apiRequest<void>("/api/v1/auth/logout", { method: "POST" });
}

export function login(email: string, password: string): Promise<AuthTokens> {
  return apiRequest<AuthTokens>("/api/v1/auth/login", {
    method: "POST",
    body: { email, password },
    auth: false,
  });
}

export function requestPasswordReset(email: string): Promise<void> {
  return apiRequest<void>("/api/v1/auth/reset", {
    method: "POST",
    body: { email },
    auth: false,
  });
}

export function authCallback(code: string): Promise<AuthTokens> {
  return apiRequest<AuthTokens>("/api/v1/auth/callback", {
    method: "POST",
    body: { code },
    auth: false,
  });
}

export function fetchMe(): Promise<User> {
  return apiRequest<User>("/api/v1/auth/me");
}

/* ---- Target endpoints (contract: Builder C) ---- */

export function listTargets(): Promise<Paginated<Target>> {
  return apiRequest<Paginated<Target>>("/api/v1/targets");
}

export function createTarget(domain: string): Promise<Target> {
  return apiRequest<Target>("/api/v1/targets", {
    method: "POST",
    body: { domain },
  });
}
