# WebSurfaceHQ API — Dependency reasons (Phase 0)

Every dependency in `requirements.txt`, with the one-line reason it is here.
Nothing else is installed. No Supabase / Celery / Redis packages yet — Phase 0
is the skeleton only; those land in Week 1 per the engineering plan.

| Dependency | Reason |
| --- | --- |
| fastapi==0.162.4 | The API framework itself — routing, validation, OpenAPI. |
| uvicorn[standard]==0.54.0 | ASGI server that runs the app (with uvloop/httptools via the `standard` extra). |
| pydantic==2.14.3 | Data validation for request/response models and settings (FastAPI's base). |
| pydantic-settings==2.16.2 | Loads settings from environment variables with fail-fast validation. |
| httpx==0.28.1 | Async HTTP client for future outbound calls; also the transport `TestClient` needs. |
| pytest==9.2.0 | Test runner for the real pytest suite in `tests/`. |
| ruff==0.17.4 | Linter + formatter (single tool, replaces flake8/black/isort). |
| mypy==2.4.1 | Static type checker, run in strict mode. |
