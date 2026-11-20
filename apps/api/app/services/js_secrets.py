"""JS secret scanner (Week 2 recon, ``js_secret_scan`` stage).

Pure functions over supplied JS content — this module performs NO network
I/O and never fetches anything (the SSRF guard in ``app.core.ssrf`` governs
fetching; the caller — workstream B's crawl stage — supplies the content).

Detection is regex + Shannon entropy (threshold 4.5, per the Week 2 plan)
+ context scoring. Every finding carries only REDACTED evidence: the
returned dicts contain at most the first 4 and last 4 characters of a
matched value (see :func:`redact_value`), and the full secret value never
appears in any return value, log, or stored finding. There is no logging
in this module at all, by design.

Fixtures in the tests use synthetic fake secrets only (constructed
programmatically so no real-looking secret literal sits in source).
"""

from __future__ import annotations

import math
import re
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from typing import cast

MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MiB input cap (Week 2 plan §2)
MAX_FINDINGS = 200  # cap per file
ENTROPY_THRESHOLD = 4.5  # Shannon entropy gate for generic patterns

# Values that mark a match as an obvious placeholder / test value rather
# than a live secret. Generic (assignment) patterns are suppressed outright
# on these; format-specific patterns still fire but are downgraded to low
# confidence (e.g. the AWS-documented example key AKIAIOSFODNN7EXAMPLE
# must still fire — it is the documented synthetic fixture style — just
# at low confidence, so a reviewer is not misled into treating it as live).
_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "example",
    "test",
    "xxx",
    "xxxx",
    "your-api-key",
    "your_api_key",
    "changeme",
    "change-me",
    "todo",
    "placeholder",
    "dummy",
    "fake",
    "sample",
    "123456",
    "insert",
    "replace",
)

# Service keywords in the surrounding line that raise a generic pattern's
# confidence from medium to high. Deliberately excludes the pattern's own
# words (secret / token / api_key / password / auth) — those are the match
# itself, not extra context.
_SERVICE_KEYWORDS: tuple[str, ...] = (
    "aws",
    "stripe",
    "github",
    "slack",
    "google",
    "firebase",
    "sendgrid",
    "twilio",
    "openai",
    "database",
    "mongodb",
    "postgres",
    "mysql",
    "redis",
    "authorization",
    "bearer",
)


def shannon_entropy(value: str) -> float:
    """Shannon entropy of ``value`` in bits per character (0.0 when empty)."""
    if not value:
        return 0.0
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in Counter(value).values())


def redact_value(value: str) -> str:
    """Redact a secret value: first 4 + ``...`` + last 4 characters.

    Values of 8 characters or fewer reveal the whole value that way, so
    they redact to ``[redacted]`` instead. At most 8 characters of the
    secret ever survive redaction.
    """
    if len(value) <= 8:
        return "[redacted]"
    return f"{value[:4]}...{value[-4:]}"


def _is_placeholder(value: str) -> bool:
    """True when ``value`` looks like an obvious placeholder / test value."""
    if not value:
        return True
    if len(set(value)) == 1:  # e.g. "aaaaaaaaaaaaaaaa" — never a real secret
        return True
    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _downgrade_severity(severity: str) -> str:
    """One step down the severity ladder (placeholder-marked findings)."""
    return {"high": "medium", "medium": "low", "low": "info"}.get(severity, severity)


@dataclass(frozen=True)
class _Pattern:
    """One secret pattern.

    ``value_group`` is the regex group holding the secret value (0 = the
    whole match); ``name_group`` is the group holding the variable/key
    name, when the pattern is an assignment (used only for the redacted
    snippet's context — never echoed raw beyond the name itself).
    ``entropy_gated`` requires Shannon entropy > 4.5 on the value;
    ``placeholder_suppress`` drops the finding entirely on placeholder
    values (generic patterns), while format-specific patterns downgrade
    instead (see module docstring). ``placeholder_group`` overrides
    which regex group the placeholder check reads (the database_url
    pattern checks the password portion only — the host in a URL such
    as ``db.example.com`` legitimately contains "example").
    """

    name: str
    regex: re.Pattern[str]
    value_group: int
    name_group: int | None
    entropy_gated: bool
    severity: str
    base_confidence: str
    placeholder_suppress: bool
    placeholder_group: int | None = None


_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        name="aws_access_key",
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
        value_group=0,
        name_group=None,
        entropy_gated=False,
        severity="high",
        base_confidence="high",
        placeholder_suppress=False,
    ),
    _Pattern(
        name="aws_secret_key",
        regex=re.compile(
            r"(?<![A-Za-z0-9_])"
            r"(aws[_-]?secret(?:[_-]?access)?[_-]?key)"
            r"[\"'\s:=]+[\"']?([A-Za-z0-9/+=]{40})[\"']?",
            re.IGNORECASE,
        ),
        value_group=2,
        name_group=1,
        entropy_gated=True,
        severity="high",
        base_confidence="high",
        placeholder_suppress=False,
    ),
    _Pattern(
        name="generic_api_key",
        regex=re.compile(
            r"(?<![A-Za-z0-9_])"
            r"(api[_-]?key|apikey|api[_-]?token|access[_-]?key"
            r"|secret[_-]?key|client[_-]?secret)"
            r"[\"'\s:=]+[\"']?([A-Za-z0-9_\-./+=]{16,})[\"']?",
            re.IGNORECASE,
        ),
        value_group=2,
        name_group=1,
        entropy_gated=True,
        severity="medium",
        base_confidence="medium",
        placeholder_suppress=True,
    ),
    _Pattern(
        name="bearer_token",
        # JWTs after "Bearer" are reported by the jwt pattern, not here.
        regex=re.compile(r"Bearer\s+(?!eyJ)([A-Za-z0-9\-_=.]{20,})", re.IGNORECASE),
        value_group=1,
        name_group=None,
        entropy_gated=True,
        severity="medium",
        base_confidence="medium",
        placeholder_suppress=True,
    ),
    _Pattern(
        name="github_token",
        regex=re.compile(
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"
            r"|github_pat_[A-Za-z0-9_]{22,}"
        ),
        value_group=0,
        name_group=None,
        entropy_gated=False,
        severity="high",
        base_confidence="high",
        placeholder_suppress=False,
    ),
    _Pattern(
        name="slack_token",
        regex=re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        value_group=0,
        name_group=None,
        entropy_gated=False,
        severity="high",
        base_confidence="high",
        placeholder_suppress=False,
    ),
    _Pattern(
        name="stripe_live_key",
        regex=re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}"),
        value_group=0,
        name_group=None,
        entropy_gated=False,
        severity="high",
        base_confidence="high",
        placeholder_suppress=False,
    ),
    _Pattern(
        name="private_key",
        regex=re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
        value_group=0,
        name_group=None,
        entropy_gated=False,
        severity="high",
        base_confidence="high",
        placeholder_suppress=False,
    ),
    _Pattern(
        name="jwt",
        regex=re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
        value_group=0,
        name_group=None,
        entropy_gated=False,
        severity="medium",
        base_confidence="medium",
        placeholder_suppress=False,
    ),
    _Pattern(
        name="google_api_key",
        regex=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        value_group=0,
        name_group=None,
        entropy_gated=False,
        severity="high",
        base_confidence="high",
        placeholder_suppress=False,
    ),
    _Pattern(
        name="database_url",
        regex=re.compile(
            r"(?i)(postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis)://"
            r"[^\s\"'<>]+:([^\s\"'@<>]+)@[^\s\"'<>]+"
        ),
        value_group=0,
        name_group=None,
        entropy_gated=False,
        severity="high",
        base_confidence="high",
        placeholder_suppress=False,
        placeholder_group=2,
    ),
    _Pattern(
        name="generic_password",
        regex=re.compile(
            r"(?<![A-Za-z0-9_])"
            r"(password|passwd|pwd)"
            r"[\"'\s:=]+[\"']?([^\s\"'<>;,]{8,})[\"']?",
            re.IGNORECASE,
        ),
        value_group=2,
        name_group=1,
        entropy_gated=True,
        severity="medium",
        base_confidence="medium",
        placeholder_suppress=True,
    ),
)


def _snippet(pattern: _Pattern, match: re.Match[str], value: str) -> str:
    """Redacted evidence snippet for a match.

    Never contains the full secret value: at most the first/last 4
    characters of it (via :func:`redact_value`), or no secret characters
    at all for the private-key header and database-URL patterns, where
    the surrounding context alone identifies the finding.
    """
    if pattern.name == "private_key":
        return "-----BEGIN ... PRIVATE KEY-----"
    if pattern.name == "database_url":
        scheme = match.group(1).lower()
        return f"{scheme}://[redacted]"
    redacted = redact_value(value)
    if pattern.name_group is not None:
        name = match.group(pattern.name_group)
        return f'{name} = "{redacted}"'
    if pattern.name == "bearer_token":
        return f"Bearer {redacted}"
    return f"{pattern.name}: {redacted}"


def _line_offsets(content: str) -> list[int]:
    """Start offset of every line in ``content`` (line 1 starts at 0).

    Precomputed once per :func:`scan_js` call so line numbers stay O(1)
    per match instead of re-counting ``"\\n"`` from the start of the
    file for every match (M10 review fix — the old per-match
    ``content.count("\\n", 0, offset)`` was quadratic on large files).
    """
    offsets = [0]
    for index, char in enumerate(content):
        if char == "\n":
            offsets.append(index + 1)
    return offsets


def _line_number(content: str, offset: int, offsets: list[int] | None = None) -> int:
    """1-based line number of ``offset`` in ``content``.

    Pass the precomputed ``offsets`` from :func:`_line_offsets` when
    calling in a loop; without them the offsets are computed for this
    one call (same result, just slower).
    """
    if offsets is None:
        offsets = _line_offsets(content)
    return bisect_right(offsets, offset)


def scan_js(content: str, url: str) -> list[dict[str, object]]:
    """Scan JS ``content`` from ``url`` for leaked secrets.

    Returns a list of finding dicts with exactly these keys:
    ``pattern_name``, ``url``, ``line`` (1-based), ``redacted_snippet``,
    ``entropy`` (Shannon entropy of the matched value), ``confidence``
    (``high`` | ``medium`` | ``low``) and ``severity``
    (``high`` | ``medium`` | ``low`` | ``info``).

    Raises ValueError when ``content`` exceeds the 2 MiB input cap.
    Findings are capped at 200 per file and deduplicated on
    (pattern_name, line). No secret value is ever returned, logged, or
    stored — see :func:`redact_value`.
    """
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError(
            f"JS content exceeds {MAX_CONTENT_BYTES} bytes ({len(content.encode('utf-8'))} bytes)"
        )
    findings: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()
    # Precomputed once per call (M10): line-start offsets for O(1) line
    # numbers, and the split lines for context scoring — neither is
    # recomputed per match.
    offsets = _line_offsets(content)
    lines = content.splitlines()
    for pattern in _PATTERNS:
        for match in pattern.regex.finditer(content):
            if len(findings) >= MAX_FINDINGS:
                return findings
            value = match.group(pattern.value_group)
            line = _line_number(content, match.start(), offsets)
            key = (pattern.name, line)
            if key in seen:
                continue
            entropy = shannon_entropy(value)
            if pattern.entropy_gated and entropy <= ENTROPY_THRESHOLD:
                continue
            placeholder_value = (
                match.group(pattern.placeholder_group)
                if pattern.placeholder_group is not None
                else value
            )
            placeholder = _is_placeholder(placeholder_value)
            if placeholder and pattern.placeholder_suppress:
                continue
            confidence = pattern.base_confidence
            severity = pattern.severity
            if placeholder:
                # Format-specific pattern on an obvious placeholder
                # (e.g. the AWS-documented example key): still flag it,
                # but at low confidence and one severity step down.
                confidence = "low"
                severity = _downgrade_severity(severity)
            elif pattern.base_confidence == "medium":
                line_text = lines[line - 1].lower() if 0 < line <= len(lines) else ""
                if any(keyword in line_text for keyword in _SERVICE_KEYWORDS):
                    confidence = "high"
            seen.add(key)
            findings.append(
                {
                    "pattern_name": pattern.name,
                    "url": url,
                    "line": line,
                    "redacted_snippet": _snippet(pattern, match, value),
                    "entropy": entropy,
                    "confidence": confidence,
                    "severity": severity,
                }
            )
    findings.sort(key=lambda f: (cast(int, f["line"]), cast(str, f["pattern_name"])))
    return findings
