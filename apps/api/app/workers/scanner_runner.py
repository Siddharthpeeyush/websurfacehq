"""Runner for the Go ``scanner-agent`` binary (Week 2 recon).

The agent is a thin wrapper around the ProjectDiscovery tools; it reads
ONE JSON object on stdin and emits JSONL on stdout:

- ``{"type": "result", "stage": ..., "data": {...}}`` — one result record.
- ``{"type": "log", "message": ...}`` — a progress line.
- ``{"type": "error", "message": ...}`` — a stage failure detail.

Contract (docs/week-2-plan.md §1 + the Week 2 CLI contract): exit 0 =
success, non-zero = stage failure. This module is unit-testable without
Celery: it is plain ``subprocess`` + JSONL parsing, and the Celery tasks
in :mod:`app.workers.tasks` call :func:`run_stage`.

Binary resolution: ``SCANNER_AGENT_BIN`` env var first, then the
checked-out path ``packages/scanner-agent/scanner-agent`` (repo root is
two levels above ``apps/api``), then ``scanner-agent`` on ``PATH``. A
missing binary is a loud :class:`ScannerAgentUnavailable`, never a
silent success — a scan must not report "done" when nothing ran.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default per-stage timeout (seconds) when the caller does not say
# otherwise. Individual tasks pass tighter values where they know them.
DEFAULT_TIMEOUT_SECONDS = 120

# Cap on the error text carried into ScannerAgentError: the agent's error
# line is the only stdout content ever surfaced, and it is truncated so a
# chatty agent cannot smuggle a long body (which might contain a secret
# the target served) into a task result or log.
_ERROR_TEXT_MAX_CHARS = 500

# Cap on agent stdout kept for parsing (8 MiB). Output past the cap is
# dropped and counted (``truncated_lines`` in the returned counts) so a
# chatty or compromised target cannot bloat worker memory without bound.
_MAX_STDOUT_BYTES = 8 * 1024 * 1024

# Grace added to the Python-side wait on top of the timeout passed to
# the agent (B1 review fix). The agent enforces ``timeout_seconds``
# internally with its own context, so its timeout fires FIRST and the
# agent exits cleanly; Python waits ``timeout_seconds`` +
# ``TIMEOUT_GRACE_SECONDS`` so it only kills the process group when the
# agent itself fails to stop on time. Never wait less than the agent's
# own timeout — that would kill a healthy agent mid-stage.
TIMEOUT_GRACE_SECONDS = 30

# Payload keys the caller may NOT override via ``extra`` (M11 review
# fix): they are set by this runner from its own arguments. A reserved
# key in ``extra`` is ignored with a warning, never applied.
_RESERVED_EXTRA_KEYS: frozenset[str] = frozenset(
    {"stage", "domain", "timeout_seconds", "rate_limit", "max_ports"}
)


class ScannerAgentError(Exception):
    """The agent ran but the stage failed (non-zero exit)."""


class ScannerAgentUnavailable(Exception):
    """No agent binary could be found to run."""


class ScannerAgentTimeout(ScannerAgentError):
    """The agent did not finish within the caller's timeout."""


def resolve_agent_binary() -> str:
    """Locate the scanner-agent binary.

    Precedence: ``SCANNER_AGENT_BIN`` env var, the repo's checked-out
    build at ``packages/scanner-agent/scanner-agent``, then
    ``scanner-agent`` on ``PATH``. Raises
    :class:`ScannerAgentUnavailable` when nothing resolves.
    """
    env_bin = os.environ.get("SCANNER_AGENT_BIN")
    if env_bin:
        candidate = Path(env_bin).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        raise ScannerAgentUnavailable(
            f"SCANNER_AGENT_BIN is set to {env_bin!r} but that is not an executable file"
        )
    repo_root = Path(__file__).resolve().parents[4]
    checked_out = repo_root / "packages" / "scanner-agent" / "scanner-agent"
    if checked_out.is_file() and os.access(checked_out, os.X_OK):
        return str(checked_out)
    on_path = shutil.which("scanner-agent")
    if on_path:
        return on_path
    raise ScannerAgentUnavailable(
        "scanner-agent binary not found: set SCANNER_AGENT_BIN, build "
        "packages/scanner-agent, or put scanner-agent on PATH"
    )


def _cap_stdout(raw: str) -> tuple[str, int, bool]:
    """Cap agent stdout at ``_MAX_STDOUT_BYTES`` (UTF-8 bytes).

    Returns ``(kept_text, truncated_lines, was_truncated)`` where
    ``truncated_lines`` counts the lines dropped past the cap (a
    trailing partial line counts as one), so callers can tell output
    was lost without seeing it.
    """
    encoded = raw.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_STDOUT_BYTES:
        return raw, 0, False
    kept = encoded[:_MAX_STDOUT_BYTES].decode("utf-8", errors="ignore")
    dropped = raw[len(kept) :]
    if not dropped:
        truncated_lines = 0
    else:
        # Lines dropped: one per newline, plus a trailing partial line
        # when the tail does not end with a newline.
        truncated_lines = dropped.count("\n")
        if not dropped.endswith("\n"):
            truncated_lines += 1
    return kept, truncated_lines, True


def run_stage(
    stage: str,
    domain: str,
    *,
    hosts: list[str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one recon stage through the agent binary and parse its JSONL.

    Returns ``{"stage", "domain", "results", "logs", "counts"}`` where
    ``results`` is the list of ``data`` payloads from ``result`` lines,
    ``logs`` the ``log`` messages, and ``counts`` carries
    ``results`` / ``logs`` / ``errors`` / ``malformed_lines`` plus
    ``truncated_lines`` / ``stdout_truncated`` when the 8 MiB stdout
    cap was hit.

    - SSRF pre-check: the domain — and every host in ``hosts`` — is
      checked with ``assert_url_safe("https://<host>")`` before the
      binary is invoked, so a blocked target never reaches the agent
      (M11 review fix: the Python side re-asserts the agent's hostname
      rules for each host it passes).
    - Timeout: the agent is launched in its own session
      (``start_new_session=True``) and Python waits
      ``timeout_seconds + TIMEOUT_GRACE_SECONDS`` so the agent's
      internal timeout fires first. If Python's wait still expires, the
      WHOLE process group is killed (``os.killpg``) so the agent's tool
      children (subfinder / naabu / httpx / katana) cannot survive as
      orphans, and :class:`ScannerAgentTimeout` is raised (B1 fix).
      Note: a child that calls ``setsid`` itself escapes its parent's
      process group — that escape is the agent's (Go) side to close,
      not Python's.
    - Stdout is read via ``Popen`` + ``communicate`` and capped at
      8 MiB before parsing (M11 fix); stderr goes to DEVNULL — the
      agent reports failures via JSONL ``error`` lines on stdout.
    - ``extra`` may only add non-reserved keys: ``stage``,
      ``domain``, ``timeout_seconds``, ``rate_limit`` and ``max_ports``
      in ``extra`` are ignored with a warning, never overriding the
      runner's own values (M11 fix).
    - Malformed JSONL lines are skipped and counted, never fatal.
    - Non-zero exit raises :class:`ScannerAgentError` carrying ONLY the
      agent's ``error`` line (truncated) — raw stdout is never included,
      so tool output (which may echo target content) cannot leak into a
      task result or log.
    """
    from app.core.ssrf import assert_url_safe

    assert_url_safe(f"https://{domain}")
    for host in hosts or []:
        assert_url_safe(f"https://{host}")

    binary = resolve_agent_binary()
    payload: dict[str, Any] = {
        "stage": stage,
        "domain": domain,
        "timeout_seconds": timeout_seconds,
        # The agent contract names these fields; the defaults match the
        # plan's politeness rules (5 req/s per domain, 2 concurrent are
        # enforced inside the agent).
        "rate_limit": 5,
        "max_ports": "top-100",
    }
    if hosts is not None:
        payload["hosts"] = hosts
    if extra:
        reserved = sorted(set(extra) & _RESERVED_EXTRA_KEYS)
        if reserved:
            logger.warning(
                "run_stage %s: ignoring reserved extra key(s) %s (payload fields "
                "stage/domain/timeout_seconds/rate_limit/max_ports cannot be overridden)",
                stage,
                reserved,
            )
        for key, value in extra.items():
            if key not in _RESERVED_EXTRA_KEYS:
                payload[key] = value

    # Python waits longer than the agent's own timeout (grace above) so
    # the agent's context fires first and it can exit cleanly.
    python_timeout = timeout_seconds + TIMEOUT_GRACE_SECONDS
    try:
        proc = subprocess.Popen(
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise ScannerAgentUnavailable(
            f"could not execute scanner-agent binary {binary!r}: {exc}"
        ) from exc
    try:
        stdout, _stderr = proc.communicate(
            input=json.dumps(payload),
            timeout=python_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # Kill the WHOLE process group (the agent leads its own session,
        # so its tool children share the group) — killing only the agent
        # binary would orphan subfinder / naabu / httpx / katana.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        raise ScannerAgentTimeout(
            f"scanner-agent stage {stage!r} for {domain} timed out "
            f"(agent timeout {timeout_seconds}s, Python waited {python_timeout}s)"
        ) from exc
    except OSError as exc:
        raise ScannerAgentUnavailable(
            f"could not execute scanner-agent binary {binary!r}: {exc}"
        ) from exc

    stdout_text, truncated_lines, stdout_truncated = _cap_stdout(stdout or "")
    if stdout_truncated:
        logger.warning(
            "scanner-agent stage %s for %s exceeded the %d-byte stdout cap; %d line(s) dropped",
            stage,
            domain,
            _MAX_STDOUT_BYTES,
            truncated_lines,
        )

    results: list[Any] = []
    logs: list[str] = []
    errors: list[str] = []
    malformed_lines = 0
    for line in stdout_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            malformed_lines += 1
            continue
        if not isinstance(record, dict):
            malformed_lines += 1
            continue
        record_type = record.get("type")
        if record_type == "result":
            results.append(record.get("data", {}))
        elif record_type == "log":
            message = record.get("message")
            if isinstance(message, str):
                logs.append(message)
        elif record_type == "error":
            message = record.get("message")
            if isinstance(message, str):
                errors.append(message)
        else:
            malformed_lines += 1

    if proc.returncode != 0:
        detail = errors[-1][:_ERROR_TEXT_MAX_CHARS] if errors else "unknown agent error"
        raise ScannerAgentError(
            f"scanner-agent stage {stage!r} for {domain} failed (exit {proc.returncode}): {detail}"
        )
    if malformed_lines:
        logger.warning(
            "scanner-agent stage %s for %s emitted %d malformed JSONL line(s)",
            stage,
            domain,
            malformed_lines,
        )
    return {
        "stage": stage,
        "domain": domain,
        "results": results,
        "logs": logs,
        "counts": {
            "results": len(results),
            "logs": len(logs),
            "errors": len(errors),
            "malformed_lines": malformed_lines,
            "truncated_lines": truncated_lines,
            "stdout_truncated": stdout_truncated,
        },
    }
