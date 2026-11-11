"""Structured JSON logging with a request-id on every line and automatic
redaction of sensitive fields.

Every log record is one JSON object: ``{"ts", "level", "logger", "message",
"request_id", ...extra}``. Sensitive keys (password / token / secret /
authorization, and anything containing them) are replaced with
``"[REDACTED]"`` wherever they appear in structured fields, in a
``key=value`` fragment of the message text, in a bare ``key <long-token>``
fragment (a secret logged as a positional arg), or in an exception
traceback — so a credential can never leak into a log line by accident.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

# Keys whose values must never appear in logs. Any key containing one of
# these substrings (case-insensitive) is redacted.
SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "session",
    "cookie",
)

REDACTED = "[REDACTED]"

# Matches key=value / key: value fragments in free text, e.g.
# "password=hunter2" or "Authorization: Bearer abc".
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|authorization|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|session|cookie)\b\s*[=:]\s*[^\s,;\"']+"
)

# Matches a bare sensitive key followed by a long token with no separator,
# e.g. a positional log arg rendering as "token abcdefgh12345678". Narrow
# on purpose: only the high-risk keys, and only a following token of 8+
# non-space characters — so ordinary phrases like "token expired" (7 chars)
# are left alone. "session"/"cookie" are excluded here: too common as words.
_BARE_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|authorization|api[_-]?key|access[_-]?key"
    r"|private[_-]?key)\b\s+[^\s,;\"']{8,}"
)

# Per-request id, set by the middleware in app.main for every request.
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(sub in lowered for sub in SENSITIVE_KEY_SUBSTRINGS)


def redact_value(value: Any) -> Any:
    """Recursively replace sensitive values in dicts/lists with [REDACTED]."""
    if isinstance(value, dict):
        return {
            key: REDACTED if _is_sensitive_key(str(key)) else redact_value(val)
            for key, val in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value


def redact_text(text: str) -> str:
    """Scrub sensitive values out of free text.

    Covers both ``key=value`` fragments and bare ``key <long-token>``
    fragments (the latter catches a secret logged as a positional arg).
    """
    text = _SENSITIVE_VALUE_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    return _BARE_SENSITIVE_VALUE_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", text)


class RedactionFilter(logging.Filter):
    """Logging filter that redacts sensitive data before a record is emitted.

    - Dict ``record.args``: sensitive keys replaced (recursively).
    - The rendered message: sensitive ``key=value`` fragments scrubbed.
    - Structured ``extra`` fields attached to the record: same treatment.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, dict):
            record.args = redact_value(record.args)
        record.msg = redact_text(str(record.msg))
        for attr in ("extra", "context"):
            value = getattr(record, attr, None)
            if isinstance(value, dict):
                setattr(record, attr, redact_value(value))
        return True


class JsonFormatter(logging.Formatter):
    """Render a log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
            "request_id": request_id_var.get(),
        }
        # Structured fields passed via `extra={...}` (minus logging internals).
        reserved = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
            "asctime",
            "taskName",
        }
        extra = {
            key: redact_value(value)
            for key, value in record.__dict__.items()
            if key not in reserved
        }
        if extra:
            payload.update(extra)
        if record.exc_info:
            # Traceback text goes through the same redaction: an exception
            # message can carry a secret, and formatException is unredacted
            # by default.
            payload["exc_info"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Install the JSON formatter + redaction filter on the root logger.

    Idempotent: safe to call more than once (e.g. from tests).
    """
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    return logging.getLogger("websurfacehq")


logger = logging.getLogger("websurfacehq")
