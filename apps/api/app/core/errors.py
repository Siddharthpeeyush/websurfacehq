"""One standard error response shape for the whole API.

Every error, from any endpoint, looks like::

    {"code": "NOT_FOUND", "message": "Resource not found", "details": null}

``code`` is a stable machine-readable slug in UPPER_SNAKE_CASE (per
docs/api-conventions.md — the single contract clients branch on).
``details`` carries optional structured context (validation errors, etc.).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """The single error envelope returned by every error path."""

    code: str
    message: str
    details: Any = None


class ApiError(Exception):
    """An error the API raises deliberately, with an HTTP status + code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
