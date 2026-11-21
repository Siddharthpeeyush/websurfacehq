"""Application settings, loaded from the environment (fail-fast).

Week 1: Supabase / Redis / Celery variables land here. Rules:

- In ``staging`` / ``production``, Supabase credentials and the internal
  signing secret are REQUIRED — the app refuses to start without them.
- In ``development`` they are optional: the app starts, auth endpoints that
  need Supabase answer 503 ``SUPABASE_NOT_CONFIGURED``, and tests use the
  in-memory fakes. Never invent a Supabase URL or key to make dev "work".
- ``extra="forbid"`` (Phase 0 review note, applied Week 1): a mistyped
  variable name fails startup loudly instead of running on defaults.
"""

from enum import Enum

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Deployment environment. Anything other than these three is rejected."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """All settings come from environment variables (or a .env file)."""

    model_config = SettingsConfigDict(env_file=".env", extra="forbid")

    environment: Environment = Environment.DEVELOPMENT

    # --- Supabase (required in staging/production, optional in dev) --------
    # Project URL + keys. The project does not exist yet (owner creates it in
    # the dashboard, Week 1). The service-role key is server-only: it must
    # NEVER appear in frontend code, the frontend bundle, or any committed
    # file. Supabase JWTs are verified ES256 against the project's public
    # JWKS (see app/auth/jwt.py) — there is NO shared JWT secret: the
    # legacy SUPABASE_JWT_SECRET was removed (ADR-0007) and must not be
    # reintroduced as a verification fallback.
    supabase_url: str | None = None
    supabase_anon_key: str | None = None
    supabase_service_role_key: SecretStr | None = None

    # --- API ----------------------------------------------------------------
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_public_url: str | None = None
    # The API's own public hostname (e.g. the Render hostname,
    # ``websurfacehq-api.onrender.com`` — host only, no scheme).
    # The staff API host gate (``app/core/staff_prefix.py``) must
    # accept it: the Host header arriving at the API is ALWAYS the
    # API origin — the web middleware proxies staff calls with
    # ``Host: <API origin>`` (the staff web host arrives only as
    # X-Forwarded-Host, which the API deliberately does not trust),
    # and direct clients (live-proof curls, health checks) address
    # the API by its own hostname too. Without this, every staff
    # API call 404s in production. The gate ALSO accepts the host
    # parsed from ``api_public_url`` when that is set, so either
    # variable alone is enough. Empty in local dev (localhost is
    # allowed there); set it in staging/production.
    api_public_host: str | None = None
    # Comma-separated allowed browser origins (CORS). No wildcard in prod.
    cors_origins: list[str] = ["http://localhost:3000"]
    # Trust X-Forwarded-For for the client IP (rate limiting) ONLY when
    # the app runs behind a trusted reverse proxy that is the sole ingress
    # (Render in production). NEVER true in dev or when directly exposed:
    # an attacker can spoof XFF to mint fresh per-IP rate-limit buckets
    # (or fill a victim's bucket — lockout DoS). Default False.
    # ROUND-2 REVIEW (M1, tracked): the router takes the LEFTMOST XFF
    # entry, which is correct only if the trusted proxy OVERWRITES
    # X-Forwarded-For. If Render APPENDS instead, a spoofed leftmost
    # entry is trusted. VERIFY Render's behaviour at deploy time; if it
    # appends, take the entry the proxy added (rightmost trusted hop),
    # not the leftmost.
    trust_x_forwarded_for: bool = False
    # Secret for signing internal tokens (e.g. report share links).
    # Random 32+ bytes. Required in staging/production.
    internal_signing_secret: SecretStr | None = None
    log_level: str = "INFO"

    # --- Queue: Celery + Redis ----------------------------------------------
    # Dev defaults point at a local Redis. Production uses Upstash (broker)
    # and the Upstash REST endpoint for rate limits; see .env.example.
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # --- Rate limits (ENGINEERING-PLAN.md rule 9) ---------------------------
    # Login/signup/reset: 5 attempts / 15 min per IP + per email.
    rate_limit_login_attempts: int = 5
    rate_limit_login_window_seconds: int = 900

    # --- Target verification (recorded decisions, Week 1) -------------------
    # Verification token entropy: min 32 random bytes (proposed value in the
    # plan, locked as the decision in Week 1). Token TTL 7 days — after that
    # the API answers 410 VERIFICATION_EXPIRED (docs/api-conventions.md).
    verification_token_bytes: int = 32
    verification_token_ttl_days: int = 7

    # --- Staff door (admin foundation, 20 Nov 2026) -----------------------
    # The staff site lives under a SECRET random path prefix on the admin
    # subdomain (DESIGN-LOCK.md, "Secret staff address"). The prefix is
    # generated once at setup (128-bit random), stored in server config
    # ONLY, never committed. Empty = prefix enforcement OFF — local dev
    # only; staging/production refuse to start without it (see
    # _require_prod_secrets below).
    staff_url_prefix: str = ""
    # Step-up MFA for the Founder screen: when True (default ON — owner
    # decision still open, ON is the recommended default), opening
    # Founder requires a fresh MFA check once per staff session.
    staff_step_up_mfa: bool = True
    # Staff session lifetimes (DESIGN-LOCK.md, "Staff sessions"): absolute
    # lifetime 12h, idle 60 min -> sign in again. TOTP at EVERY staff
    # sign-in; no trusted-device bypass (enforced in app/auth/sessions.py).
    staff_session_absolute_hours: int = 12
    staff_session_idle_minutes: int = 60
    # Dummy-hash target (H1 retune, 20 Nov 2026): the unknown-email
    # login path burns a time-based PBKDF2 equalizer for this many
    # milliseconds, standing in for the bcrypt GoTrue runs on the
    # known-email path and skips (``app/auth/provider.py`` lookup).
    # Measured live against the real GoTrue project
    # (dpwfshafzyxyfoktsggo, 3 runs x 10 attempts per path, 20 Nov
    # 2026): wrong-password median 403/479/453 ms vs unknown-email
    # median 344/406/363 ms — the bcrypt component is the
    # difference, 59/73/90 ms (median-of-diffs ~73 ms, network
    # baseline ~400 ms from this VM dominates both). Default 75 ms
    # is that measured value, rounded. The equalizer loop
    # self-calibrates to any host CPU (it burns wall-clock time,
    # not a fixed iteration count), so the target — not the host —
    # is what needs retuning if GoTrue's cost changes.
    staff_dummy_hash_target_ms: int = 75

    # --- Storage -------------------------------------------------------------
    # Signed-URL expiry for private report downloads: 15 min (proposed value
    # in the plan, locked as the decision in Week 1).
    signed_url_expiry_minutes: int = 15

    # --- Quotas (owner-locked 11 Nov 2026: Free = 3 scans/month) ------------
    max_scans_free_per_month: int = 3
    # Free plan: 1 domain (blueprint Part 5). Enforced in POST /targets
    # (duplicate domain -> 409 first, then the cap -> 429 QUOTA_EXCEEDED).
    max_targets_free: int = 1

    @property
    def is_production(self) -> bool:
        """True only when running in production."""
        return self.environment is Environment.PRODUCTION

    @property
    def supabase_configured(self) -> bool:
        """True when the Supabase project is wired in (URL + both keys).

        The JWT secret is deliberately NOT part of this check (ADR-0007):
        tokens are verified ES256 against the project's public JWKS, so
        auth needs the URL (which locates the JWKS), not a shared secret.
        """
        return bool(self.supabase_url and self.supabase_anon_key and self.supabase_service_role_key)

    @model_validator(mode="after")
    def _require_prod_secrets(self) -> "Settings":
        """Fail fast in staging/production when a required secret is missing."""
        if "*" in self.cors_origins:
            raise ValueError("cors_origins must not contain '*' (L1 review fix)")
        if self.environment is Environment.DEVELOPMENT:
            return self
        missing = [
            name
            for name, value in (
                ("SUPABASE_URL", self.supabase_url),
                ("SUPABASE_ANON_KEY", self.supabase_anon_key),
                ("SUPABASE_SERVICE_ROLE_KEY", self.supabase_service_role_key),
                ("INTERNAL_SIGNING_SECRET", self.internal_signing_secret),
                # Staff door: a production deploy without the secret
                # prefix would serve the staff site at a guessable path.
                ("STAFF_URL_PREFIX", self.staff_url_prefix),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"Missing required settings in {self.environment.value}: " + ", ".join(missing)
            )
        # N9: a short or guessable staff prefix is a live hole — the
        # prefix is the staff door's obscurity layer, and a 4-char
        # prefix is brute-forceable. Staging/production refuse to
        # start unless it meets the minimum entropy rule (16+ chars,
        # URL-path-safe charset only). The setup generator issues
        # 128-bit (22 chars); this is the floor, not the target.
        from app.core.staff_prefix import staff_url_prefix_is_strong

        if not staff_url_prefix_is_strong(self.staff_url_prefix):
            raise ValueError(
                "STAFF_URL_PREFIX must be at least 16 characters of "
                "[A-Za-z0-9_-] in staging/production (128-bit random, "
                "22 chars, generated at setup)"
            )
        # B1 (re-review #3): the staff API host gate
        # (app/core/staff_prefix.py, get_api_public_hosts) accepts no
        # host when neither API_PUBLIC_HOST nor API_PUBLIC_URL is set,
        # so every staff API call 404s — fail fast here like the
        # sibling STAFF_URL_PREFIX check, instead of starting cleanly
        # and dying at the first staff login. Either variable alone
        # is enough.
        if not (self.api_public_host or self.api_public_url):
            raise ValueError(
                "API_PUBLIC_HOST or API_PUBLIC_URL must be set in "
                "staging/production (the staff API host gate rejects "
                "every staff call without one)"
            )
        return self


def get_settings() -> Settings:
    """Build settings from the environment.

    Raises pydantic ValidationError at import/startup time if a required
    variable is missing or invalid — fail-fast, never a half-configured app.
    """
    return Settings()


settings = get_settings()
