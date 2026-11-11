"""Application settings, loaded from the environment (fail-fast).

Phase 0: the only required variable is ``ENVIRONMENT`` (default
``"development"``). Supabase / Redis / Celery keys are NOT required yet —
they land in Week 1 per the engineering plan, at which point they become
required here and the app will refuse to start without them.
"""

from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Deployment environment. Anything other than these three is rejected."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """All settings come from environment variables (or a .env file)."""

    # NOTE (review, Phase 0): extra="ignore" silently swallows a mistyped
    # variable name. Switch to extra="forbid" in Week 1 once the Supabase /
    # Redis / Celery variables land in Settings — then a typo fails startup
    # loudly instead of running on defaults.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Environment = Environment.DEVELOPMENT

    @property
    def is_production(self) -> bool:
        """True only when running in production."""
        return self.environment is Environment.PRODUCTION


def get_settings() -> Settings:
    """Build settings from the environment.

    Raises pydantic ValidationError at import/startup time if a required
    variable is missing or invalid — fail-fast, never a half-configured app.
    """
    return Settings()


settings = get_settings()
