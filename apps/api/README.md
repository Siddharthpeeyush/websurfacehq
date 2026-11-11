# WebSurfaceHQ API

FastAPI (Python 3.12) backend for the WebSurfaceHQ vulnerability-scanner SaaS.
**Phase 0 skeleton** — health/liveness endpoints, structured JSON logging with
redaction, security headers, one standard error shape, environment-based
settings. No database, queue, or auth yet — those land in Week 1 per
`../ENGINEERING-PLAN.md`.

## Setup

```bash
cd apps/api
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Requires Python 3.12 (see `.python-version`).

## Run the dev server

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Then:

```bash
curl -s http://127.0.0.1:8000/health   # {"status":"ok"}
curl -s http://127.0.0.1:8000/live     # {"status":"alive"}
```

## Quality checks

Run in this order, from `apps/api/` with the venv active:

```bash
ruff check .            # lint
ruff format --check .   # format check
mypy .                  # strict typecheck
pytest -v               # real tests (TestClient, no mocks)
```

All four must pass before any change is reported as done.

## Configuration

Settings live in `app/core/config.py` and load from environment variables
via pydantic-settings (fail-fast on missing/invalid values). Phase 0 has one
variable:

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `ENVIRONMENT` | No | `development` | `development` / `staging` / `production`. Production disables the interactive API docs. |

Supabase / Redis / Celery variables are **not** required yet — they become
required in Week 1 when those services are wired in. Do not create `.env`
files with real secrets; `.env.example` lives at the repo root (another
phase's job).

## Layout

| Path | What it is |
| --- | --- |
| `app/main.py` | App factory, routes (`/health`, `/live`), middleware, error handlers |
| `app/core/config.py` | Environment settings (pydantic-settings) |
| `app/core/logging.py` | Structured JSON logging, request-id, secret redaction |
| `app/core/errors.py` | Standard error shape `{"code","message","details"}` + `ApiError` |
| `tests/test_health.py` | Real pytest tests via TestClient |
| `requirements.txt` / `DEPENDENCIES.md` | Pinned deps + one-line reason for each |
| `pyproject.toml` | Ruff (line-length 100, py312) + mypy strict config |
