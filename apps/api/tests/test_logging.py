"""Tests for the log-redaction guarantees (Phase 0 review fix).

A secret must never reach a log line — not as a key=value fragment, not as
a positional arg, and not inside an exception traceback.
"""

import logging

from app.core.logging import JsonFormatter, redact_text


def test_redact_text_key_value_fragment() -> None:
    assert redact_text("password=hunter2") == "password=[REDACTED]"
    assert "hunter2" not in redact_text("password=hunter2")


def test_redact_text_bare_positional_token() -> None:
    # A secret logged as a positional arg renders as "token <value>".
    redacted = redact_text("token abcdefgh12345678")
    assert "abcdefgh12345678" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_text_leaves_ordinary_words_alone() -> None:
    # The bare-value pattern is narrow on purpose: short following words
    # (e.g. "token expired") are ordinary log text, not secrets.
    assert redact_text("token expired") == "token expired"
    assert redact_text("session started") == "session started"


def test_formatter_redacts_traceback() -> None:
    try:
        raise ValueError("password=hunter2 leaked in exception")
    except ValueError:
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="boom",
            args=(),
            exc_info=None,
        )
        import sys

        record.exc_info = sys.exc_info()
        output = JsonFormatter().format(record)
        assert "hunter2" not in output
        assert "[REDACTED]" in output
