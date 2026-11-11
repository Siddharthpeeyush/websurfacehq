"""WebSurfaceHQ API — FastAPI application (Phase 0 skeleton).

Endpoints:
- ``GET /health`` — liveness + component checks (Week 1: DB / Redis /
  queue, each with a timeout; a component that is not configured reports
  ``"not_configured"`` rather than failing the check). Returns 200 with
  ``{"status": "ok" | "degraded", "components": {...}}``.
- ``GET /live`` — lightweight endpoint for load balancers / uptime monitors.

Every request gets a request-id (``X-Request-ID`` response header, and on
every JSON log line). Security headers are set on every response. All errors
use the single ``{"code", "message", "details"}`` shape from app.core.errors.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import Environment, settings
from app.core.errors import ApiError, ErrorResponse
from app.core.health import health_payload
from app.core.logging import configure_logging, logger, request_id_var
from app.routers import auth as auth_router
from app.routers import findings as findings_router
from app.routers import scans as scans_router
from app.routers import targets as targets_router

configure_logging(logging.INFO)

# Security headers applied to every response. Values are deliberately
# restrictive for an API that serves no browser-rendered content.
SECURITY_HEADERS: dict[str, str] = {
    # HTTPS only, for 2 years, including subdomains. Browsers ignore this
    # over plain HTTP (local dev), which is fine — it bites only in prod.
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    # NOTE: no `preload` until the production domain is confirmed served
    # over HTTPS everywhere (same rule as the web app) — only then submit
    # the domain to the HSTS preload list.
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # API serves JSON only: no scripts, frames, or external resources at all.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
}

# Map of HTTP status code -> stable error code. Codes are UPPER_SNAKE_CASE,
# per docs/api-conventions.md (the single contract clients branch on).
_HTTP_STATUS_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    502: "BAD_GATEWAY",
    503: "SERVICE_UNAVAILABLE",
}


def _error_body(
    status_code: int, code: str, message: str, details: object = None
) -> dict[str, object]:
    return ErrorResponse(code=code, message=message, details=details).model_dump()


class RequestContextMiddleware(BaseHTTPMiddleware):
    """One middleware for: request-id, security headers, access logging.

    - Generates a UUID request-id per request, puts it on the contextvar so
      every JSON log line carries it, and returns it as ``X-Request-ID``.
    - Adds the security headers from SECURITY_HEADERS to every response,
      including error responses (they pass through ``call_next`` here).
    - Logs one JSON line per request: method, path, status, duration.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Trust no client-supplied id: accept it only if it parses as a UUID
        # (normalised to canonical form); anything else gets a fresh server
        # UUID, so an attacker cannot inject colliding or crafted request ids.
        incoming_id = request.headers.get("X-Request-ID")
        try:
            request_id = str(uuid.UUID(incoming_id)) if incoming_id else str(uuid.uuid4())
        except (ValueError, AttributeError, TypeError):
            request_id = str(uuid.uuid4())
        token = request_id_var.set(request_id)
        started = time.monotonic()
        try:
            response = await call_next(request)
            duration_ms = round((time.monotonic() - started) * 1000, 2)
            for header, value in SECURITY_HEADERS.items():
                response.headers[header] = value
            response.headers["X-Request-ID"] = request_id
            logger.info(
                "request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                },
            )
            return response
        finally:
            request_id_var.reset(token)


def create_app() -> FastAPI:
    """Application factory (also lets tests build a fresh app)."""
    app = FastAPI(
        title="WebSurfaceHQ API",
        description="Vulnerability-scanner SaaS backend.",
        version="0.1.0",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
    )
    # CORS first, so RequestContextMiddleware (added next) is outermost and
    # its security headers + request-id land on every response, including
    # CORS preflight responses (CORSMiddleware short-circuits OPTIONS).
    # Bearer tokens only — no cookies — so allow_credentials stays False.
    # Origins come from settings.cors_origins (no wildcard in prod).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )
    app.add_middleware(RequestContextMiddleware)

    # Rate limiter backend (M6 review fix): staging/production share
    # buckets across replicas via Redis; development keeps the in-memory
    # limiter. The Redis client connects lazily — a down Redis at startup
    # does not crash the app; the limiter fails OPEN at runtime (loudly
    # logged) so a cache outage never locks every user out of login.
    if settings.environment is Environment.DEVELOPMENT:
        logger.info("rate limiter: in-memory backend (development)")
    else:
        from app.auth.rate_limit import (
            RateLimiter,
            redis_client_from_settings,
            set_rate_limiter,
        )

        try:
            set_rate_limiter(RateLimiter(redis_client_from_settings()))
            logger.info("rate limiter: Redis backend")
        except Exception:  # noqa: BLE001 - fall back to in-memory, loudly
            logger.warning("rate limiter: Redis client build failed; using in-memory")

    # Week 1 routers (all under /api/v1; see docs/api-conventions.md).
    app.include_router(auth_router.router)
    app.include_router(targets_router.router)
    app.include_router(scans_router.router)
    app.include_router(findings_router.router)

    @app.exception_handler(ApiError)
    async def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.status_code, exc.code, exc.message, exc.details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _HTTP_STATUS_CODES.get(exc.status_code, "HTTP_ERROR")
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.status_code, code, str(exc.detail)),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Strip "input" and "ctx" from every error: Pydantic echoes the
        # submitted value there, and once login/signup bodies exist a 422
        # could otherwise return a password back to the client.
        safe_details = [
            {key: value for key, value in err.items() if key not in ("input", "ctx")}
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=_error_body(
                422,
                "VALIDATION_ERROR",
                "Request validation failed",
                details=safe_details,
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(_request: Request, _exc: Exception) -> JSONResponse:
        # Full detail goes to the log; the client gets the generic shape only.
        logger.exception("unhandled error")
        return JSONResponse(
            status_code=500,
            content=_error_body(500, "INTERNAL_ERROR", "Internal server error"),
        )

    @app.get("/health")
    async def health() -> dict[str, object]:
        # Week 1: liveness + per-component status (DB / Redis / queue).
        # Always 200 while the process is up — the body carries "ok" vs
        # "degraded"; monitors alert on the body, not the status code.
        return health_payload()

    @app.get("/live")
    async def live() -> dict[str, str]:
        # Lightweight endpoint for load balancers / uptime monitors.
        return {"status": "alive"}

    return app


app = create_app()
