"""Tests for the scanner-agent runner (Week 2).

The runner is exercised against a fake agent: a small Python script
written to tmp_path with a shebang, pointed at via SCANNER_AGENT_BIN.
No real binary and no network are needed; the SSRF pre-check is
patched out only where the test's point is the runner itself (the
guard is covered by test_ssrf.py).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from app.core.ssrf import UnsafeUrlError
from app.workers.scanner_runner import (
    ScannerAgentError,
    ScannerAgentTimeout,
    ScannerAgentUnavailable,
    resolve_agent_binary,
    run_stage,
)


@pytest.fixture()
def _no_ssrf_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.core.ssrf.assert_url_safe", lambda url: None)


def _write_fake_agent(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "scanner-agent"
    script.write_text(f"#!/usr/bin/env python3\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


_SUCCESS_AGENT = """
import json, sys
json.load(sys.stdin)
print(json.dumps({"type": "log", "message": "starting dns_enum"}))
print(json.dumps({"type": "result", "stage": "dns_enum",
                  "data": {"subdomains": ["b.example.com", "a.example.com"]}}))
print(json.dumps({"type": "result", "stage": "dns_enum",
                  "data": {"host": "c.example.com"}}))
print("this is not json")
print(json.dumps({"type": "error", "message": "non-fatal warning"}))
"""

_FAILURE_AGENT = """
import json, sys
json.load(sys.stdin)
print(json.dumps({"type": "result", "stage": "dns_enum",
                  "data": {"secret": "AKIAIOSFODNN7EXAMPLE"}}))
print(json.dumps({"type": "error", "message": "subfinder: exit status 1"}))
sys.exit(3)
"""

_SLEEP_AGENT = """
import json, sys, time
json.load(sys.stdin)
time.sleep(5)
"""


def test_run_stage_success_parses_jsonl_and_counts_malformed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    agent = _write_fake_agent(tmp_path, _SUCCESS_AGENT)
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))

    outcome = run_stage("dns_enum", "example.com")

    assert outcome["stage"] == "dns_enum"
    assert outcome["domain"] == "example.com"
    assert outcome["results"] == [
        {"subdomains": ["b.example.com", "a.example.com"]},
        {"host": "c.example.com"},
    ]
    assert outcome["logs"] == ["starting dns_enum"]
    assert outcome["counts"] == {
        "results": 2,
        "logs": 1,
        "errors": 1,
        "malformed_lines": 1,
        "truncated_lines": 0,
        "stdout_truncated": False,
    }


def test_run_stage_nonzero_exit_raises_with_error_line_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    agent = _write_fake_agent(tmp_path, _FAILURE_AGENT)
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))

    with pytest.raises(ScannerAgentError, match="subfinder: exit status 1"):
        run_stage("dns_enum", "example.com")


def test_run_stage_nonzero_exit_never_leaks_raw_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    agent = _write_fake_agent(tmp_path, _FAILURE_AGENT)
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))

    with pytest.raises(ScannerAgentError) as excinfo:
        run_stage("dns_enum", "example.com")
    # The result line carried a (synthetic, documented-example) secret;
    # only the agent's error line may surface in the exception.
    assert "AKIAIOSFODNN7EXAMPLE" not in str(excinfo.value)


def test_run_stage_timeout_kills_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    agent = _write_fake_agent(tmp_path, _SLEEP_AGENT)
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))
    # The runner waits timeout_seconds + TIMEOUT_GRACE_SECONDS (30 s by
    # default, so the agent's own timeout fires first); shrink the grace
    # for this test only so the 5 s sleeper is killed after ~2 s.
    monkeypatch.setattr("app.workers.scanner_runner.TIMEOUT_GRACE_SECONDS", 1)

    with pytest.raises(ScannerAgentTimeout):
        run_stage("dns_enum", "example.com", timeout_seconds=1)


def test_run_stage_missing_binary_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(tmp_path / "does-not-exist"))

    with pytest.raises(ScannerAgentUnavailable, match="SCANNER_AGENT_BIN"):
        run_stage("dns_enum", "example.com")


def test_run_stage_ssrf_precheck_blocks_before_agent_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "ran"
    agent = _write_fake_agent(
        tmp_path,
        f"import json, sys, pathlib\njson.load(sys.stdin)\npathlib.Path({str(marker)!r}).touch()\n",
    )
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))

    def _blocked(url: str) -> None:
        raise UnsafeUrlError("Blocked hostname: localhost")

    monkeypatch.setattr("app.core.ssrf.assert_url_safe", _blocked)

    with pytest.raises(UnsafeUrlError):
        run_stage("dns_enum", "localhost")
    assert not marker.exists()  # the agent binary was never invoked


def test_run_stage_passes_contract_payload_on_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    agent = _write_fake_agent(
        tmp_path,
        """
import json, sys
payload = json.load(sys.stdin)
assert payload["stage"] == "port_scan"
assert payload["domain"] == "example.com"
assert payload["hosts"] == ["a.example.com"]
assert payload["timeout_seconds"] == 60
assert payload["rate_limit"] == 5
print(json.dumps({"type": "result", "stage": "port_scan", "data": {}}))
""",
    )
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))

    outcome = run_stage("port_scan", "example.com", hosts=["a.example.com"], timeout_seconds=60)
    assert outcome["counts"]["results"] == 1


def test_resolve_agent_binary_prefers_env_over_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _write_fake_agent(tmp_path, "import sys\n")
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))
    monkeypatch.setattr("app.workers.scanner_runner.shutil.which", lambda name: "/usr/bin/other")

    assert resolve_agent_binary() == str(agent)


def test_resolve_agent_binary_raises_when_nothing_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SCANNER_AGENT_BIN", raising=False)
    monkeypatch.setattr("app.workers.scanner_runner.shutil.which", lambda name: None)
    # The checked-out binary may exist in-tree now (workstream A built
    # it, gitignored), so simulate "nothing found" by hiding it from
    # resolution instead of assuming the path is absent. This keeps the
    # test hermetic; the behaviour asserted (loud failure when no binary
    # resolves) is unchanged.
    orig_is_file = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self: False if self.name == "scanner-agent" else orig_is_file(self),
    )
    with pytest.raises(ScannerAgentUnavailable, match="scanner-agent binary not found"):
        resolve_agent_binary()


def test_subprocess_invoked_without_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    """The runner must never pass a shell string to subprocess."""
    agent = _write_fake_agent(tmp_path, _SUCCESS_AGENT)
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))
    calls: list[dict[str, Any]] = []
    real_popen = subprocess.Popen

    def _spy(*args: Any, **kwargs: Any) -> Any:
        calls.append({"args": args, "kwargs": kwargs})
        return real_popen(*args, **kwargs)

    monkeypatch.setattr("app.workers.scanner_runner.subprocess.Popen", _spy)

    run_stage("dns_enum", "example.com")
    assert len(calls) == 1
    assert calls[0]["args"][0] == [str(agent)]  # argv list, no shell
    assert "shell" not in calls[0]["kwargs"]
    assert calls[0]["kwargs"]["start_new_session"] is True


def test_run_stage_uses_python_executable_env(
    monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    # Sanity: sys.executable is a real interpreter (used by the fake
    # agents above through their shebang); the runner itself needs no
    # Python — this just guards the fixture mechanism.
    assert os.path.isfile(sys.executable)


# ---------------------------------------------------------------------------
# B1 review fix: timeout kills the whole process group (no orphaned
# tool children) + the Python wait exceeds the agent's own timeout
# ---------------------------------------------------------------------------

_ORPHAN_AGENT = """
import json, sys, subprocess, time
json.load(sys.stdin)
child_lines = [
    "import os, sys, time",
    "path = sys.argv[1]",
    "with open(path, 'w') as f:",
    "    f.write('pid=' + str(os.getpid()) + chr(10))",
    "    f.flush()",
    "    while True:",
    "        f.write(str(time.time()) + chr(10))",
    "        f.flush()",
    "        time.sleep(0.2)",
]
child_code = chr(10).join(child_lines)
subprocess.Popen([sys.executable, "-c", child_code, "__HEARTBEAT__"])
time.sleep(30)
"""


def test_run_stage_timeout_kills_orphaned_child_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    """B1: on timeout the agent's whole process group dies — a child
    the agent spawned (in the agent's session, as its tools run) must
    stop heartbeating and be gone, not survive as an orphan."""
    heartbeat = tmp_path / "heartbeat.txt"
    agent = _write_fake_agent(tmp_path, _ORPHAN_AGENT.replace("__HEARTBEAT__", str(heartbeat)))
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))
    monkeypatch.setattr("app.workers.scanner_runner.TIMEOUT_GRACE_SECONDS", 1)

    with pytest.raises(ScannerAgentTimeout):
        run_stage("dns_enum", "example.com", timeout_seconds=1)

    # The child wrote its pid + heartbeats before the kill; wait and
    # prove nothing more is written and the pid is gone.
    assert heartbeat.exists()
    first_lines = heartbeat.read_text().splitlines()
    assert first_lines and first_lines[0].startswith("pid=")
    child_pid = int(first_lines[0].split("=", 1)[1])
    assert len(first_lines) >= 2  # at least one heartbeat landed pre-kill
    mtime_before = heartbeat.stat().st_mtime
    size_before = heartbeat.stat().st_size
    time.sleep(0.8)
    assert heartbeat.stat().st_mtime == mtime_before
    assert heartbeat.stat().st_size == size_before
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


# ---------------------------------------------------------------------------
# M11 review fix: per-host SSRF assert, capped stdout, extra allowlist
# ---------------------------------------------------------------------------


def test_run_stage_asserts_each_host_before_agent_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M11: every host in ``hosts=`` is SSRF-checked on the Python side
    — a blocked host means the agent binary is never invoked."""
    marker = tmp_path / "ran"
    agent = _write_fake_agent(
        tmp_path,
        f"import json, sys, pathlib\njson.load(sys.stdin)\npathlib.Path({str(marker)!r}).touch()\n",
    )
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))

    def _selective_block(url: str) -> None:
        if "localhost" in url:
            raise UnsafeUrlError("Blocked hostname: localhost")

    monkeypatch.setattr("app.core.ssrf.assert_url_safe", _selective_block)

    with pytest.raises(UnsafeUrlError):
        run_stage("port_scan", "example.com", hosts=["a.example.com", "localhost"])
    assert not marker.exists()

    # A clean host list reaches the agent.
    run_stage("port_scan", "example.com", hosts=["a.example.com"])
    assert marker.exists()


def test_run_stage_ignores_reserved_extra_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    """M11: ``extra`` can never override the runner's own payload
    fields — reserved keys are ignored, other keys pass through."""
    payload_file = tmp_path / "payload.json"
    agent = _write_fake_agent(
        tmp_path,
        f"""
import json, sys, pathlib
payload = json.load(sys.stdin)
pathlib.Path({str(payload_file)!r}).write_text(json.dumps(payload))
print(json.dumps({{"type": "result", "stage": "port_scan", "data": {{}}}}))
""",
    )
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))

    run_stage(
        "port_scan",
        "example.com",
        hosts=["a.example.com"],
        timeout_seconds=60,
        extra={
            "stage": "nuclei",
            "domain": "evil.example.com",
            "timeout_seconds": 1,
            "rate_limit": 99,
            "max_ports": "all",
            "custom_flag": True,
        },
    )

    payload = json.loads(payload_file.read_text())
    assert payload["stage"] == "port_scan"
    assert payload["domain"] == "example.com"
    assert payload["timeout_seconds"] == 60
    assert payload["rate_limit"] == 5
    assert payload["max_ports"] == "top-100"
    assert payload["hosts"] == ["a.example.com"]
    assert payload["custom_flag"] is True


def test_run_stage_caps_stdout_and_counts_truncated_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    """M11: stdout past the cap is dropped, counted, and flagged —
    the results inside the cap are still parsed."""
    agent = _write_fake_agent(
        tmp_path,
        """
import json, sys
print(json.dumps({"type": "result", "stage": "dns_enum", "data": {"host": "a.example.com"}}))
print(json.dumps({"type": "result", "stage": "dns_enum", "data": {"host": "b.example.com"}}))
print("x" * 5000)
""",
    )
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))
    monkeypatch.setattr("app.workers.scanner_runner._MAX_STDOUT_BYTES", 1024)

    outcome = run_stage("dns_enum", "example.com")

    assert outcome["results"] == [
        {"host": "a.example.com"},
        {"host": "b.example.com"},
    ]
    assert outcome["counts"]["stdout_truncated"] is True
    assert outcome["counts"]["truncated_lines"] == 1


def test_run_stage_python_timeout_exceeds_agent_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_ssrf_check: None
) -> None:
    """B1: the Python wait is the agent timeout PLUS the grace — the
    agent's internal timeout fires first. Proved by the payload the
    agent receives (its own timeout) vs the wait the runner applies:
    an agent that exits just after its own timeout must NOT be killed
    by Python first."""
    agent = _write_fake_agent(
        tmp_path,
        """
import json, sys, time
payload = json.load(sys.stdin)
# Sleep past the agent's own timeout but inside the Python grace.
time.sleep(payload["timeout_seconds"] + 1)
print(json.dumps({"type": "result", "stage": "dns_enum", "data": {}}))
""",
    )
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))
    monkeypatch.setattr("app.workers.scanner_runner.TIMEOUT_GRACE_SECONDS", 5)

    started = time.monotonic()
    outcome = run_stage("dns_enum", "example.com", timeout_seconds=1)
    elapsed = time.monotonic() - started

    assert outcome["counts"]["results"] == 1
    assert elapsed >= 2  # Python waited out the agent's own timeout + grace
