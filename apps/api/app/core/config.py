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
    # file. SUPABASE_JWT_SECRET verifies Supabase JWTs in the API.
    supabase_url: str | None = None
    supabase_anon_key: str | None = None
    supabase_service_role_key: SecretStr | None = None
    supabase_jwt_secret: SecretStr | None = None

    # --- API ----------------------------------------------------------------
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_public_url: str | None = None
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
        """True when the Supabase project is wired in (URL + both keys)."""
        return bool(
            self.supabase_url
            and self.supabase_anon_key
            and self.supabase_service_role_key
            and self.supabase_jwt_secret
        )

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
                ("SUPABASE_JWT_SECRET", self.supabase_jwt_secret),
                ("INTERNAL_SIGNING_SECRET", self.internal_signing_secret),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"Missing required settings in {self.environment.value}: " + ", ".join(missing)
            )
        return self


def get_settings() -> Settings:
    """Build settings from the environment.

    Raises pydantic ValidationError at import/startup time if a required
    variable is missing or invalid — fail-fast, never a half-configured app.
    """
    return Settings()


settings = get_settings()
