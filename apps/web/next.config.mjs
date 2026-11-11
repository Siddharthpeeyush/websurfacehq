/**
 * WebSurfaceHQ — Next.js configuration (Phase 0 scaffold).
 *
 * Security headers applied to every response (see ENGINEERING-PLAN.md §2
 * and blueprint §1.9 / §8.1). Values are deliberate, not random:
 *
 * - Strict-Transport-Security: force HTTPS for 2 years, include subdomains.
 *   (Preload intentionally NOT set in scaffold — only enable once the
 *   production domain is confirmed served over HTTPS everywhere.)
 * - Content-Security-Policy: default-deny; scripts/styles only from self.
 *   NOTE (Phase 0 concession, fix before real integrations land): the
 *   'unsafe-inline' entries below neuter the CSP against inline-script XSS —
 *   the code uses no hashes/nonces yet. Next.js needs inline scripts for its
 *   own runtime, so this stays for the scaffold; replace with Next.js-managed
 *   hashes/nonces and drop 'unsafe-inline' when real integrations (Supabase,
 *   Sentry, fonts) land. Do not loosen further.
 * - X-Content-Type-Options: nosniff — stop MIME-sniffing attacks.
 * - Referrer-Policy: strict-origin-when-cross-origin — full URL only to
 *   same origin, origin only cross-origin.
 * - X-Frame-Options: DENY — no framing (clickjacking defence).
 * - Permissions-Policy: disable camera / microphone / geolocation — the
 *   scaffold needs none of them.
 */
const securityHeaders = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains",
  },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
