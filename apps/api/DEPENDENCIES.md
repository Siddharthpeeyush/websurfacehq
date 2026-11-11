# WebSurfaceHQ API — Dependency reasons (Week 1)

Every dependency in `requirements.txt`, with the one-line reason it is here.
Nothing else is installed. Week 1 adds the Supabase / Celery / Redis
packages the Phase 0 note promised.

| Dependency | Reason |
| --- | --- |
| fastapi==0.162.4 | The API framework itself — routing, validation, OpenAPI. |
| uvicorn[standard]==0.54.0 | ASGI server that runs the app (with uvloop/httptools via the `standard` extra). |
| pydantic==2.14.3 | Data validation for request/response models and settings (FastAPI's base). |
| pydantic-settings==2.16.2 | Loads settings from environment variables with fail-fast validation. |
| httpx==0.28.1 | Async HTTP client for future outbound calls; also the transport `TestClient` needs. |
| PyJWT==2.10.1 | HS256 verification of Supabase JWTs in `app/auth/jwt.py` (Week 1). |
| supabase==2.18.0 | Supabase-py: GoTrue Auth (signup/login/reset/PKCE) + PostgREST store (Week 1). |
| gotrue==2.12.3 | Direct import in `app/auth/provider.py` (`gotrue.errors.AuthApiError`) — a direct dependency, not a transitive one (L8 review fix). |
| redis==5.2.1 | redis-py: rate-limit backend + Celery broker/backend + DLQ/vuln locks (Week 1). |
| email-validator==2.3.0 | Required by Pydantic `EmailStr` for the auth endpoints (Week 1). |
| dnspython==2.9.2 | DNS TXT lookups for target verification (Week 1). |
| celery==5.7.0 | The worker queue: 3 routed queues, idempotent tasks, retries + DLQ (Week 1). |
| pytest==9.2.0 | Test runner for the real pytest suite in `tests/`. |
| ruff==0.17.4 | Linter + formatter (single tool, replaces flake8/black/isort). |
| mypy==2.4.1 | Static type checker, run in strict mode. |
| fakeredis==2.40.0 | Test-only: in-memory Redis for DLQ/lock tests — never a real Redis in tests (Week 1). |
