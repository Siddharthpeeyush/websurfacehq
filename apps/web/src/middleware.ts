/**
 * Host-based routing — the two doors (DESIGN-LOCK.md, "URL scheme").
 *
 * - Staff host (`admin.websurfacehq.com`, EXACT match): serves staff
 *   pages ONLY, and ONLY under the secret path prefix (see below).
 *   Every other path answers a generic 404 — customer pages never
 *   render there, and nothing outside the staff paths is even
 *   acknowledged. The match is equality, not a prefix: any `admin.*`
 *   hostname that is not exactly `admin.websurfacehq.com` is treated
 *   as a customer host.
 * - Customer host (any other non-local host): staff pages NEVER render.
 *   A customer typing a staff path gets the same generic 404.
 * - Local dev (`localhost` / `127.0.0.1`): both doors are reachable, so
 *   the staff pages can be tested directly at `/staff-login`,
 *   `/staff-invite`, `/staff-mfa-setup`.
 *
 * FAIL-CLOSED staff namespace: the staff paths all live under the
 * `/staff` namespace (`/staff-*` and `/staff/*`). A path in that
 * namespace that is NOT explicitly registered in `STAFF_PATHS`
 * answers a generic 404 on EVERY host — including local dev — until
 * it is registered. A future staff page that is built but not added
 * to the list can never leak onto the customer host (or anywhere
 * else) by omission.
 *
 * Staff pages known today: `/staff-login`, `/staff-invite`,
 * `/staff-mfa-setup`. Extend `STAFF_PATHS` as staff screens land
 * (Weeks 3–4).
 *
 * SECRET-PATH PREFIX (NEW1 fix, 20 Nov 2026): the production staff
 * site lives under a secret random path prefix on the admin subdomain
 * (server config only — the value is NEVER in this repo, never in the
 * browser, never in a log). `STAFF_URL_PREFIX` is read here from
 * server env at request time; it is NOT a `NEXT_PUBLIC_` variable and
 * must never become one — a build-time value would be baked into the
 * JS bundle. Empty means prefix enforcement is OFF (local dev only;
 * production refuses to start without it — the API fail-fasts, and
 * the deploy must set the same value here).
 *
 * On the staff host, with a prefix configured:
 *   (a) a path under the prefix (`/<prefix>/staff-login`) is rewritten
 *       INTERNALLY to the bare staff route — the browser URL keeps the
 *       prefix, the page renders from the bare route;
 *   (b) a staff page WITHOUT the prefix (`/staff-login`) answers a
 *       generic 404 with NO redirect — a redirect would hand the
 *       secret prefix to anyone probing the bare path;
 *   (c) `/api/staff/*` (same-origin, called by the staff client) is
 *       proxied to the API origin with the prefix added SERVER-SIDE
 *       (`<STAFF_API_URL>/<prefix>/staff/...`), so the browser never
 *       sees the prefix. The API origin is server env `STAFF_API_URL`
 *       (dev default `http://localhost:8000`); it is never exposed to
 *       the browser either. In local dev with an empty prefix the
 *       proxy forwards without a prefix and bare staff pages work
 *       unchanged.
 * The prefix is stripped ONLY on the staff host, and ONLY when the
 * remainder is a staff route (a staff page, the `/api/staff/*` proxy,
 * or a staff-namespace path so the fail-closed rule still fires) —
 * anything else under the prefix is a plain 404.
 *
 * Staff responses also carry `X-Robots-Tag: noindex` and
 * `Referrer-Policy: no-referrer` (design: no sitemap entry, noindex,
 * no-referrer on staff pages).
 */

import { NextResponse, type NextRequest } from "next/server";

/** Paths that belong to the staff door. Extend as staff screens land. */
const STAFF_PATHS = ["/staff-login", "/staff-invite", "/staff-mfa-setup"];

const STAFF_HOSTNAME = "admin.websurfacehq.com";

/** Dev default for the API origin when `STAFF_API_URL` is unset. */
const DEV_STAFF_API_ORIGIN = "http://localhost:8000";

/**
 * The secret staff path prefix, server env only, read at request time.
 * Surrounding slashes are stripped so `/abc/` and `abc` behave the
 * same. Empty = enforcement off (local dev only). The VALUE is never
 * logged, never returned, never echoed in any response.
 */
function staffUrlPrefix(): string {
  return (process.env.STAFF_URL_PREFIX ?? "")
    .trim()
    .replace(/^\/+|\/+$/g, "");
}

/** The API origin the staff proxy forwards to (server env only). */
function staffApiOrigin(): string {
  return (process.env.STAFF_API_URL ?? DEV_STAFF_API_ORIGIN)
    .trim()
    .replace(/\/$/, "");
}

function isStaffPath(pathname: string): boolean {
  return STAFF_PATHS.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );
}

/**
 * The staff namespace: every current and future staff path lives
 * here (`/staff-*` and `/staff/*`). Used for the fail-closed rule —
 * a namespace path that is not a registered staff path 404s
 * everywhere, instead of falling through to whatever host it is on.
 */
function isStaffNamespace(pathname: string): boolean {
  return (
    pathname === "/staff" ||
    pathname.startsWith("/staff-") ||
    pathname.startsWith("/staff/")
  );
}

function hostnameOf(host: string | null): string {
  if (!host) return "";
  // Host may carry a port (localhost:3000, admin.websurfacehq.com:443).
  const hostPart = host.split(":")[0];
  return hostPart ? hostPart.toLowerCase() : "";
}

function isLocalDev(hostname: string): boolean {
  return (
    hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]"
  );
}

function isStaffHost(hostname: string): boolean {
  // EXACT match only — a prefix match (`startsWith("admin.")`) would
  // treat ANY admin.* hostname (e.g. admin.evil.example) as the staff
  // door. Local dev is handled separately by isLocalDev.
  return hostname === STAFF_HOSTNAME;
}

/**
 * Strip the secret prefix, staff host ONLY. Returns the remainder
 * (`/staff-login` for `/<prefix>/staff-login`) when the path is under
 * the prefix AND the remainder is a staff route; null otherwise. The
 * remainder check matters: without it, a path like `/<prefix>/x`
 * would strip to `/x` and could fall through to non-staff routing.
 * A remainder of exactly `/` (bare `/<prefix>`) is not a staff route,
 * so it returns null and 404s like everything else on the staff host.
 */
function stripStaffPrefix(pathname: string, prefix: string): string | null {
  if (!prefix) return null;
  if (pathname === `/${prefix}`) return null;
  if (!pathname.startsWith(`/${prefix}/`)) return null;
  const rest = pathname.slice(prefix.length + 1);
  if (
    isStaffPath(rest) ||
    rest.startsWith("/api/staff/") ||
    isStaffNamespace(rest)
  ) {
    return rest;
  }
  return null;
}

/** The generic 404: same body and status on both doors, so a probe
 * learns nothing about which paths exist. */
function generic404(): NextResponse {
  return new NextResponse("Not found", {
    status: 404,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}

/**
 * Proxy a same-origin `/api/staff/*` call to the API, adding the
 * secret prefix server-side. The browser called `/api/staff/...`
 * with no prefix; the API receives `/<prefix>/staff/...` (or the
 * bare path when no prefix is configured in local dev). The `/api`
 * segment is the web proxy's namespace only — it is stripped before
 * the prefix is added, so `/api/staff/auth/login` becomes
 * `<origin>/<prefix>/staff/auth/login`, the route the API mounts.
 * Method, headers, and body ride the rewrite; the query string is
 * preserved.
 */
function proxyStaffApi(
  request: NextRequest,
  apiPath: string,
  prefix: string,
): NextResponse {
  const upstreamPath = apiPath.slice("/api".length);
  const target = new URL(
    `${staffApiOrigin()}${prefix ? `/${prefix}` : ""}${upstreamPath}`,
  );
  target.search = request.nextUrl.search;
  return NextResponse.rewrite(target);
}

export function middleware(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl;
  const hostname = hostnameOf(request.headers.get("host"));
  const prefix = staffUrlPrefix();

  // Framework internals are never gated (the matcher already excludes
  // them; this is belt-and-braces so a matcher change cannot break the
  // staff page's own JS/CSS).
  if (pathname.startsWith("/_next") || pathname === "/favicon.ico") {
    return NextResponse.next();
  }

  const local = isLocalDev(hostname);
  const staffHost = isStaffHost(hostname);

  // Staff host ONLY: strip the secret prefix before any other routing
  // decision. The browser URL keeps the prefix; the remainder is the
  // route that is actually served. Never stripped on the customer
  // host — a customer-host request that guesses the prefix must not
  // be served, and must not learn anything from the answer.
  const stripped = staffHost ? stripStaffPrefix(pathname, prefix) : null;
  const effective = stripped ?? pathname;

  // Same-origin staff API proxy (staff host + local dev only — never
  // the customer host, where no staff page renders and no staff call
  // is legitimate). Checked BEFORE the local-dev bypass so the proxy
  // works in dev too, and before the fail-closed namespace rule so
  // `/api/staff/*` is not mistaken for a staff-namespace page.
  if (effective.startsWith("/api/staff/") && (staffHost || local)) {
    return proxyStaffApi(request, effective, prefix);
  }

  // FAIL-CLOSED: a staff-namespace path that is not a registered staff
  // page 404s on EVERY host — including local dev — until it is
  // registered in STAFF_PATHS. Checked on the effective (prefix-
  // stripped) path, so `/<prefix>/staff-evil` 404s exactly like
  // `/staff-evil`. Checked before the local-dev bypass so dev cannot
  // accidentally serve an unregistered staff page either.
  if (isStaffNamespace(effective) && !isStaffPath(effective)) {
    return generic404();
  }

  // Local dev: both doors reachable for testing.
  if (local) {
    return NextResponse.next();
  }

  if (staffHost) {
    // Staff door: a staff page is served ONLY under the prefix. A bare
    // staff path 404s with NO redirect — a redirect would hand the
    // secret prefix to anyone probing the bare path.
    if (stripped === null || !isStaffPath(effective)) {
      return generic404();
    }
    const url = request.nextUrl.clone();
    url.pathname = effective;
    const res = NextResponse.rewrite(url);
    res.headers.set("X-Robots-Tag", "noindex, nofollow");
    res.headers.set("Referrer-Policy", "no-referrer");
    return res;
  }

  // Customer host: staff pages never render here.
  if (isStaffPath(effective)) {
    return generic404();
  }
  return NextResponse.next();
}

export const config = {
  // Skip framework internals and static assets so the staff page's own
  // JS/CSS still load on the staff host. Everything else goes through
  // the host gate above.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
