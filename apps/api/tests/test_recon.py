"""Week 2 recon task tests: verification-gate refusal, stage behaviour,
idempotency, snapshot hashing, and redaction of JS secrets.

Everything runs in Celery eager mode (no broker) against the real
``InMemoryStore``. The agent runner is a fake (never the network); the
JS fetches are faked the same way. Fixtures use synthetic fake secrets
only — the AWS example key ``AKIAIOSFODNN7EXAMPLE`` is the documented
example value, never a real credential.
"""

from __future__ import annotations

import hashlib
import json
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest

from app.core.ssrf import UnsafeUrlError
from app.db.memory import InMemoryStore
from app.services.techprint import fingerprint
from app.services.verification import hash_token
from app.workers import celery_app
from app.workers.dispatch import dispatch_scan
from app.workers.scanner_runner import ScannerAgentError
from app.workers.tasks import (
    _extract_live_hosts,
    compute_attack_surface_hash,
    crawl,
    dns_enum,
    http_probe,
    idempotency_key,
    js_secret_scan,
    port_scan,
    subdomain_enum,
    tech_fingerprint,
)

RECON_TASKS = [
    dns_enum,
    subdomain_enum,
    port_scan,
    http_probe,
    tech_fingerprint,
    crawl,
    js_secret_scan,
]

# Synthetic fake secret material (documented example values only).
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_API_KEY = "xK9mQ2vZ8wLp4RtY7sDfGhJkN3bVcX"
FAKE_JS = (
    f"const awsKey = '{FAKE_AWS_KEY}';\n"
    f'const apiKey = "{FAKE_API_KEY}";\n'
    "const placeholder = 'YOUR_API_KEY';\n"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _eager_celery() -> Any:
    old_eager = celery_app.conf.task_always_eager
    old_store = celery_app.conf.task_store_eager_result
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_store_eager_result = False
    yield
    celery_app.conf.task_always_eager = old_eager
    celery_app.conf.task_store_eager_result = old_store


@pytest.fixture(autouse=True)
def _no_live_pinned_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default pinned_get stub: an empty robots.txt, no network.

    B2 chaining means most stages now reach ``crawl`` (robots fetch)
    or ``js_secret_scan`` (JS fetch) in eager mode; without this, those
    tests would do a real DNS resolution for the robots fetch. Tests
    that need specific fetch behaviour set their own mock, which
    overrides this fixture.
    """
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda url, timeout=10.0, max_bytes=65536: httpx.Response(200, content=b""),
    )


@pytest.fixture()
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture()
def _patched_store(store: InMemoryStore, monkeypatch: pytest.MonkeyPatch) -> InMemoryStore:
    monkeypatch.setattr("app.workers.tasks._load_store", lambda: store)
    monkeypatch.setattr("app.workers.dispatch._load_store", lambda: store)
    return store


def _make_scan(
    store: InMemoryStore, domain: str = "example.com", *, verified: bool = True
) -> tuple[str, str, UUID]:
    user_id = uuid.uuid4()
    target = store.create_target(user_id, domain, hash_token("tok-123"))
    if verified:
        store.update_target_verification(
            user_id,
            target.id,
            status="verified",
            method="file",
            verified_at=datetime.now(timezone.utc),
        )
    scan = store.create_scan(user_id, target.id, {"depth": "quick"})
    return str(scan.id), str(user_id), target.id


def _runner_outcome(stage: str, results: list[Any]) -> dict[str, Any]:
    return {
        "stage": stage,
        "domain": "example.com",
        "results": results,
        "logs": [],
        "counts": {
            "results": len(results),
            "logs": 0,
            "errors": 0,
            "malformed_lines": 0,
        },
    }


def _job_log(store: InMemoryStore, user_id: str, scan_id: str, stage: str) -> dict[str, Any]:
    job = store.get_scan_job_by_key(UUID(user_id), idempotency_key(scan_id, stage, "example.com"))
    assert job is not None and job.status == "done"
    assert isinstance(job.log, str)
    parsed = json.loads(job.log)
    assert isinstance(parsed, dict)
    return parsed


def _seed_stage_log(
    store: InMemoryStore, user_id: str, scan_id: str, stage: str, result: dict[str, Any]
) -> None:
    user_uuid = UUID(user_id)
    scan_uuid = UUID(scan_id)
    key = idempotency_key(scan_id, stage, "example.com")
    job = store.create_scan_job(user_uuid, scan_uuid, stage, key)
    store.update_scan_job(user_uuid, job.id, status="done", log=json.dumps(result))


# ---------------------------------------------------------------------------
# Verification gate: every recon stage refuses an unverified target
# with ZERO outbound requests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("task", RECON_TASKS, ids=[t.name for t in RECON_TASKS])
def test_recon_stage_refuses_unverified_target(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
    task: Any,
) -> None:
    scan_id, user_id, _ = _make_scan(store, verified=False)

    def _must_not_run(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("runner must not be called for an unverified target")

    monkeypatch.setattr("app.workers.tasks.run_stage", _must_not_run)
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("pinned_get must not be called for an unverified target")
        ),
    )

    result = task.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "refused"
    assert result["error"] == "TARGET_NOT_VERIFIED"
    assert result["domain"] == "example.com"
    reloaded = store.get_scan(UUID(user_id), UUID(scan_id))
    assert reloaded is not None and reloaded.status == "failed"
    assert reloaded.error == "TARGET_NOT_VERIFIED"
    entries = list(store._audit.values())
    assert len(entries) == 1
    assert entries[0].action == "scan_refused_unverified_target"
    assert entries[0].metadata["stage"] == task.stage
    assert entries[0].metadata["scan_id_hash"] == hashlib.sha256(scan_id.encode()).hexdigest()
    assert "scan_id" not in entries[0].metadata


# ---------------------------------------------------------------------------
# dns_enum / subdomain_enum
# ---------------------------------------------------------------------------


def test_dns_enum_stores_sorted_deduped_subdomains(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(
            stage,
            [{"subdomains": ["b.example.com", "a.example.com", "b.example.com"]}],
        ),
    )

    result = dns_enum.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["subdomains"] == ["a.example.com", "b.example.com"]
    assert result["count"] == 2
    assert _job_log(store, user_id, scan_id, "dns_enum")["subdomains"] == [
        "a.example.com",
        "b.example.com",
    ]


def test_subdomain_enum_accepts_bare_host_records(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(
            stage, [{"host": "z.example.com"}, {"hostname": "a.example.com"}]
        ),
    )

    result = subdomain_enum.apply_async(args=[scan_id, user_id]).get()

    assert result["subdomains"] == ["a.example.com", "z.example.com"]


def test_dns_enum_rerun_returns_cached_result(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    calls: list[str] = []

    def _counting_runner(stage: str, domain: str, **kw: Any) -> dict[str, Any]:
        calls.append(stage)
        return _runner_outcome(stage, [{"subdomains": ["a.example.com"]}])

    monkeypatch.setattr("app.workers.tasks.run_stage", _counting_runner)

    first = dns_enum.apply_async(args=[scan_id, user_id]).get()
    second = dns_enum.apply_async(args=[scan_id, user_id]).get()

    assert first["subdomains"] == ["a.example.com"]
    assert second.get("cached") is True
    assert second["subdomains"] == ["a.example.com"]
    # B2 chaining: the fresh first run drove the whole chain (each
    # stage called the runner once); the cached second run called it
    # zero additional times.
    assert calls == ["dns_enum", "subdomain_enum", "port_scan", "http_probe", "crawl"]


# ---------------------------------------------------------------------------
# port_scan
# ---------------------------------------------------------------------------


def test_port_scan_creates_findings_only_for_non_standard_ports(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, target_id = _make_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(
            stage,
            [{"host": "example.com", "open_ports": [80, 443, 8080, 22]}],
        ),
    )

    result = port_scan.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["open_ports"] == [
        {"host": "example.com", "port": 22},
        {"host": "example.com", "port": 80},
        {"host": "example.com", "port": 443},
        {"host": "example.com", "port": 8080},
    ]
    assert result["findings_created"] == 2
    findings, _ = store.list_findings(UUID(user_id), UUID(scan_id), None, 10)
    assert len(findings) == 2
    assert {f.template_id for f in findings} == {"recon-open-port"}
    assert {f.severity for f in findings} == {"info"}
    assert {f.title for f in findings} == {
        "Open port 8080 on example.com",
        "Open port 22 on example.com",
    }
    # Evidence is host + port ONLY — no banner content.
    for finding in findings:
        assert finding.evidence in (
            "host=example.com port=8080",
            "host=example.com port=22",
        )


# ---------------------------------------------------------------------------
# http_probe
# ---------------------------------------------------------------------------


def test_http_probe_stores_live_hosts_and_screenshot_marker(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    outcome = _runner_outcome(
        "http_probe",
        [
            {
                "host": "example.com",
                "status": 200,
                "title": "Example",
                "ip": "93.184.216.34",
                "tls": {"issuer": "Example CA", "valid": True},
                "screenshot_unavailable": True,
            }
        ],
    )
    monkeypatch.setattr("app.workers.tasks.run_stage", lambda stage, domain, **kw: outcome)

    result = http_probe.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["count"] == 1
    assert result["screenshot_unavailable"] is True
    assert result["hosts"][0]["host"] == "example.com"
    assert result["hosts"][0]["status"] == 200
    assert result["hosts"][0]["title"] == "Example"
    assert result["hosts"][0]["ip"] == "93.184.216.34"
    assert result["hosts"][0]["tls"] == {"issuer": "Example CA", "valid": True}


# ---------------------------------------------------------------------------
# tech_fingerprint + snapshot hash
# ---------------------------------------------------------------------------


def test_tech_fingerprint_hashes_full_snapshot(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    _seed_stage_log(
        store,
        user_id,
        scan_id,
        "http_probe",
        {
            "status": "done",
            "hosts": [
                {
                    "host": "example.com",
                    "status": 200,
                    "title": "Example",
                    "ip": "93.184.216.34",
                    "tls": {"issuer": "Example CA"},
                    "headers": {"server": "nginx/1.25"},
                }
            ],
        },
    )
    _seed_stage_log(
        store,
        user_id,
        scan_id,
        "subdomain_enum",
        {"status": "done", "subdomains": ["b.example.com", "a.example.com"]},
    )
    _seed_stage_log(
        store,
        user_id,
        scan_id,
        "port_scan",
        {
            "status": "done",
            "open_ports": [
                {"host": "example.com", "port": 443},
                {"host": "example.com", "port": 80},
            ],
        },
    )
    # The runner must NOT be called for the fingerprint itself — but
    # the B2 chain runs crawl afterwards, so the runner mock returns an
    # empty outcome for the chained stage and robots.txt is empty.
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(stage, []),
    )
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda url, timeout=10.0, max_bytes=65536: httpx.Response(200, content=b""),
    )

    result = tech_fingerprint.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["snapshot_partial"] is False
    assert result["missing_stages"] == []
    assert result["snapshot_counts"] == {
        "subdomains": 2,
        "open_ports": 2,
        "technologies": 1,
        "hosts": 1,
    }
    assert len(result["attack_surface_hash"]) == 64
    # The expected snapshot is built from the real fingerprint output
    # (tls_summary normalises the raw TLS dict), not a hand-written copy.
    from app.services.techprint import fingerprint as _real_fingerprint

    expected_tls = _real_fingerprint(
        {
            "host": "example.com",
            "status": 200,
            "title": "Example",
            "ip": "93.184.216.34",
            "tls": {"issuer": "Example CA"},
            "headers": {"server": "nginx/1.25"},
        }
    )["tls"]
    expected = compute_attack_surface_hash(
        {
            "subdomains": ["a.example.com", "b.example.com"],
            "open_ports": [
                {"host": "example.com", "port": 80},
                {"host": "example.com", "port": 443},
            ],
            "technologies": ["Nginx"],
            "tls": {"example.com": expected_tls},
            # M3: partial + missing_stages live INSIDE the hashed snapshot.
            "partial": False,
            "missing_stages": [],
        }
    )
    assert result["attack_surface_hash"] == expected
    assert result["hosts"][0]["technologies"] == ["Nginx"]


def test_tech_fingerprint_partial_snapshot_when_prior_logs_missing(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    # Fingerprinting itself makes no runner call; the B2 chain runs
    # crawl afterwards, so the runner mock returns an empty outcome for
    # the chained stage and robots.txt is empty.
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(stage, []),
    )
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda url, timeout=10.0, max_bytes=65536: httpx.Response(200, content=b""),
    )

    result = tech_fingerprint.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"  # never fails for missing priors
    assert result["snapshot_partial"] is True
    assert result["missing_stages"] == ["http_probe", "subdomain_enum", "port_scan"]
    assert len(result["attack_surface_hash"]) == 64
    assert result["snapshot_counts"] == {
        "subdomains": 0,
        "open_ports": 0,
        "technologies": 0,
        "hosts": 0,
    }


def test_compute_attack_surface_hash_is_order_independent() -> None:
    snapshot_a = {"subdomains": ["a", "b"], "open_ports": [{"host": "h", "port": 80}]}
    snapshot_b = {"open_ports": [{"port": 80, "host": "h"}], "subdomains": ["a", "b"]}
    assert compute_attack_surface_hash(snapshot_a) == compute_attack_surface_hash(snapshot_b)
    assert compute_attack_surface_hash({**snapshot_a, "subdomains": ["a", "c"]}) != (
        compute_attack_surface_hash(snapshot_a)
    )


# ---------------------------------------------------------------------------
# crawl
# ---------------------------------------------------------------------------


def test_crawl_stores_urls_and_js_files(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(
            stage,
            [
                {
                    "urls": ["https://example.com/", "https://example.com/app.js"],
                    "js_files": ["https://example.com/app.js"],
                }
            ],
        ),
    )

    result = crawl.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["urls"] == ["https://example.com/", "https://example.com/app.js"]
    assert result["js_files"] == ["https://example.com/app.js"]
    assert result["url_count"] == 2
    assert result["js_count"] == 1


# ---------------------------------------------------------------------------
# js_secret_scan (real app.services.js_secrets, landed by workstream C)
# ---------------------------------------------------------------------------


def test_js_secret_scan_creates_redacted_findings(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    _seed_stage_log(
        store,
        user_id,
        scan_id,
        "crawl",
        {
            "status": "done",
            "urls": ["https://example.com/app.js"],
            "js_files": ["https://example.com/app.js"],
        },
    )
    fetches: list[str] = []

    def _fake_fetch(url: str, timeout: float = 10.0, max_bytes: int = 65536) -> httpx.Response:
        fetches.append(url)
        return httpx.Response(200, content=FAKE_JS.encode())

    monkeypatch.setattr("app.workers.tasks.pinned_get", _fake_fetch)
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("no runner call")),
    )

    result = js_secret_scan.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["files_scanned"] == 1
    assert result["files_failed"] == 0
    assert result["secrets_found"] == 2
    assert fetches == ["https://example.com/app.js"]
    findings, _ = store.list_findings(UUID(user_id), UUID(scan_id), None, 10)
    assert len(findings) == 2
    assert {f.template_id for f in findings} == {
        "js-secret-aws_access_key",
        "js-secret-generic_api_key",
    }
    for finding in findings:
        assert finding.url == "https://example.com/app.js"
        assert finding.evidence is not None
        # The secret value must appear NOWHERE in the stored evidence.
        assert FAKE_AWS_KEY not in finding.evidence
        assert FAKE_API_KEY not in finding.evidence
        assert "snippet=" in finding.evidence
    # …and nowhere in the stored job log either.
    job_log = _job_log(store, user_id, scan_id, "js_secret_scan")
    assert FAKE_AWS_KEY not in json.dumps(job_log)
    assert FAKE_API_KEY not in json.dumps(job_log)


def test_js_secret_scan_skips_failed_fetch(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    _seed_stage_log(
        store,
        user_id,
        scan_id,
        "crawl",
        {
            "status": "done",
            "urls": [],
            "js_files": ["https://example.com/broken.js", "https://example.com/app.js"],
        },
    )

    def _fake_fetch(url: str, timeout: float = 10.0, max_bytes: int = 65536) -> httpx.Response:
        if "broken" in url:
            raise httpx.ConnectError("refused", request=httpx.Request("GET", url))
        return httpx.Response(200, content=b"const x = 1;\n")

    monkeypatch.setattr("app.workers.tasks.pinned_get", _fake_fetch)

    result = js_secret_scan.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["files_scanned"] == 1
    assert result["files_failed"] == 1
    assert result["secrets_found"] == 0


def test_js_secret_scan_with_no_crawl_log_scans_nothing(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id, user_id, _ = _make_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("no fetch without JS URLs")),
    )

    result = js_secret_scan.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["files_scanned"] == 0
    assert result["secrets_found"] == 0


# ---------------------------------------------------------------------------
# B2 review fix: end-to-end chaining through dispatch_scan (fake agent)
# ---------------------------------------------------------------------------

_E2E_AGENT = """
import json, sys, pathlib
payload = json.load(sys.stdin)
pathlib.Path("__PAYLOADS__").open("a").write(json.dumps(payload) + "\\n")
stage = payload["stage"]
hosts = payload.get("hosts") or [payload["domain"]]

def result(data):
    print(json.dumps({"type": "result", "stage": stage, "data": data}))

if stage == "dns_enum":
    result({"subdomains": ["ns.example.com"]})
elif stage == "subdomain_enum":
    result({"subdomains": ["www.example.com", "api.example.com", "example.com"]})
elif stage == "port_scan":
    for h in hosts:
        ports = [80, 443, 8080] if h == "www.example.com" else [80, 443]
        result({"host": h, "open_ports": ports})
elif stage == "http_probe":
    for h in hosts:
        result({
            "host": h, "url": "https://" + h, "status": 200, "status_code": 200,
            "title": "Title " + h, "technologies": ["Nginx"],
            "ip": "93.184.216.34",
            "tls": {"tls_version": "tls13", "issuer_cn": "Test CA",
                    "subject_cn": h, "not_after": "2030-01-01T00:00:00Z"},
            "headers": {}, "webserver": "nginx", "content_type": "text/html",
        })
elif stage == "crawl":
    result({"urls": ["https://example.com/", "https://example.com/app.js",
                     "https://example.com/private/secret"],
            "js_files": ["https://example.com/app.js"]})
else:
    result({})
"""


def _write_e2e_agent(tmp_path: Path, payloads_file: Path) -> Path:
    script = tmp_path / "scanner-agent"
    script.write_text(
        "#!/usr/bin/env python3\n" + _E2E_AGENT.replace("__PAYLOADS__", str(payloads_file))
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def test_dispatch_scan_chains_end_to_end_to_js_secret_scan(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B2: dispatching a scan runs verify_target → … → js_secret_scan,
    discovered non-apex hosts flow into port_scan/http_probe/crawl,
    and findings are stored."""
    scan_id, user_id, _ = _make_scan(store)
    payloads_file = tmp_path / "payloads.jsonl"
    agent = _write_e2e_agent(tmp_path, payloads_file)
    monkeypatch.setenv("SCANNER_AGENT_BIN", str(agent))
    monkeypatch.setattr("app.core.ssrf.assert_url_safe", lambda url: None)
    monkeypatch.setattr("app.workers.tasks._recheck_verification", lambda *a: True)
    monkeypatch.setattr("app.workers.tasks._assert_verification_url_safe", lambda domain: None)

    def _fake_fetch(url: str, timeout: float = 10.0, max_bytes: int = 65536) -> httpx.Response:
        if url.endswith("/robots.txt"):
            return httpx.Response(200, content=b"User-agent: *\nDisallow: /private/\n")
        return httpx.Response(200, content=FAKE_JS.encode())

    monkeypatch.setattr("app.workers.tasks.pinned_get", _fake_fetch)

    summary = dispatch_scan(scan_id, user_id)
    assert summary["enqueued"] is True

    # Every stage ran to done.
    for stage in (
        "verify_target",
        "dns_enum",
        "subdomain_enum",
        "port_scan",
        "http_probe",
        "tech_fingerprint",
        "crawl",
        "js_secret_scan",
    ):
        job = store.get_scan_job_by_key(
            UUID(user_id), idempotency_key(scan_id, stage, "example.com")
        )
        assert job is not None and job.status == "done", stage

    payloads = [json.loads(line) for line in payloads_file.read_text().splitlines() if line.strip()]
    by_stage: dict[str, list[dict[str, Any]]] = {}
    for payload in payloads:
        by_stage.setdefault(payload["stage"], []).append(payload)
    assert sorted(by_stage) == [
        "crawl",
        "dns_enum",
        "http_probe",
        "port_scan",
        "subdomain_enum",
    ]
    # Discovered non-apex hosts flow into the host-taking stages,
    # apex first, sorted — and only the apex is probed for dns_enum
    # (it takes no hosts= at all). The union covers subdomain_enum
    # AND dns_enum, so ns.example.com is in it too.
    expected_hosts = [
        "example.com",
        "api.example.com",
        "ns.example.com",
        "www.example.com",
    ]
    for stage in ("port_scan", "http_probe", "crawl"):
        assert len(by_stage[stage]) == 1
        assert by_stage[stage][0]["hosts"] == expected_hosts, stage
    assert "hosts" not in by_stage["dns_enum"][0]
    assert "hosts" not in by_stage["subdomain_enum"][0]

    tech_log = _job_log(store, user_id, scan_id, "tech_fingerprint")
    assert tech_log["snapshot_partial"] is False
    assert len(tech_log["attack_surface_hash"]) == 64
    assert tech_log["hosts"][0]["technologies"] == ["Nginx"]

    crawl_log = _job_log(store, user_id, scan_id, "crawl")
    assert crawl_log["robots_disallowed_filtered"] == 1
    assert "https://example.com/private/secret" not in crawl_log["urls"]

    js_log = _job_log(store, user_id, scan_id, "js_secret_scan")
    assert js_log["files_scanned"] == 1
    assert js_log["secrets_found"] == 2

    findings, _ = store.list_findings(UUID(user_id), UUID(scan_id), None, 10)
    assert {f.template_id for f in findings} == {
        "recon-open-port",
        "js-secret-aws_access_key",
        "js-secret-generic_api_key",
    }
    reloaded = store.get_scan(UUID(user_id), UUID(scan_id))
    assert reloaded is not None and reloaded.status == "recon"

    # Idempotency: re-running a stage returns the cached result and
    # does NOT re-enqueue the next stage.
    port_payloads_before = len(by_stage["port_scan"])
    rerun = subdomain_enum.apply_async(args=[scan_id, user_id]).get()
    assert rerun.get("cached") is True
    payloads_after = [
        json.loads(line) for line in payloads_file.read_text().splitlines() if line.strip()
    ]
    assert len([p for p in payloads_after if p["stage"] == "port_scan"]) == (port_payloads_before)


# ---------------------------------------------------------------------------
# B3 review fix: real agent-shaped httpx output survives extraction +
# fingerprinting (Netlify detected, TLS version/issuer survive)
# ---------------------------------------------------------------------------


def test_extract_live_hosts_real_agent_shape_detects_netlify() -> None:
    """B3: agent-shaped records built from the REAL httpx capture
    (packages/scanner-agent/testdata/httpx.real.jsonl) flow through
    _extract_live_hosts into fingerprint() with Netlify detected and
    the TLS version + issuer intact."""
    testdata = (
        Path(__file__).resolve().parents[3]
        / "packages"
        / "scanner-agent"
        / "testdata"
        / "httpx.real.jsonl"
    )
    entries = [json.loads(line) for line in testdata.read_text().splitlines() if line.strip()]
    assert len(entries) == 2
    # The agent's per-host record, exactly as agent.go emits it:
    # "technologies" (from httpx "tech"), the tls sub-object verbatim
    # (issuer_cn / subject_cn / tls_version), plus webserver and
    # content_type carried from the httpx line.
    results: list[dict[str, Any]] = []
    for entry in entries:
        results.append(
            {
                "host": entry["host"],
                "url": entry["url"],
                "status": entry["status_code"],
                "status_code": entry["status_code"],
                "title": entry.get("title"),
                "technologies": entry.get("tech", []),
                "ip": (entry.get("a") or [None])[0],
                "tls": entry.get("tls", {}),
                "headers": {},
                "webserver": entry.get("webserver"),
                "content_type": entry.get("content_type"),
            }
        )
    hosts, _screenshot = _extract_live_hosts(results, [])
    assert [h["host"] for h in hosts] == ["potatomuzik.me", "www.potatomuzik.me"]
    for host in hosts:
        # The extractor must not drop the agent's fields.
        assert host["technologies"] == ["HSTS", "Netlify"]
        assert host["webserver"] == "Netlify"
        assert host["content_type"] in ("text/html", "text/plain")
        printed = fingerprint(host)
        assert "Netlify" in printed["technologies"]
        assert printed["webserver"] == "Netlify"
        assert printed["tls"]["version"] == "TLS 1.3"
        assert printed["tls"]["issuer"] == "YE2"
        assert printed["status_code"] in (200, 301)


def test_fingerprint_accepts_both_tech_key_spellings() -> None:
    """B3: fingerprint() prefers "technologies" but still reads "tech"."""
    assert fingerprint({"technologies": ["Netlify"], "tech": ["Apache"]})["technologies"] == [
        "Netlify"
    ]
    assert fingerprint({"tech": ["Apache"]})["technologies"] == ["Apache"]
    summary = fingerprint(
        {"tls": {"tls_version": "tls13", "issuer_cn": "ACME", "subject_cn": "ACME"}}
    )["tls"]
    assert summary["version"] == "TLS 1.3"
    assert summary["issuer"] == "ACME"
    assert summary["self_signed"] is True


# ---------------------------------------------------------------------------
# M2 review fix: deterministic failures refuse without retry
# ---------------------------------------------------------------------------


def test_ssrf_refusal_returns_without_retry(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M2: an SSRF refusal is a clean refusal, not 3 retries."""
    scan_id, user_id, _ = _make_scan(store)
    calls: list[str] = []

    def _raising_runner(stage: str, domain: str, **kw: Any) -> dict[str, Any]:
        calls.append(stage)
        raise UnsafeUrlError("Blocked hostname: localhost")

    monkeypatch.setattr("app.workers.tasks.run_stage", _raising_runner)

    result = dns_enum.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "refused"
    assert result["error"] == "SSRF_REFUSED"
    assert calls == ["dns_enum"]  # exactly once — no autoretry burn
    reloaded = store.get_scan(UUID(user_id), UUID(scan_id))
    assert reloaded is not None and reloaded.status == "failed"
    assert reloaded.error == "SSRF_REFUSED"
    # The refusal is stored: a redelivery returns it cached, still once.
    second = dns_enum.apply_async(args=[scan_id, user_id]).get()
    assert second.get("cached") is True
    assert second["status"] == "refused"
    assert calls == ["dns_enum"]


def test_agent_stage_failure_returns_without_retry(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M2: an agent stage failure (non-transient cause) refuses cleanly."""
    scan_id, user_id, _ = _make_scan(store)
    calls: list[str] = []

    def _raising_runner(stage: str, domain: str, **kw: Any) -> dict[str, Any]:
        calls.append(stage)
        raise ScannerAgentError("subfinder: exit status 1")

    monkeypatch.setattr("app.workers.tasks.run_stage", _raising_runner)

    result = subdomain_enum.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "refused"
    assert result["error"] == "AGENT_STAGE_FAILED"
    assert calls == ["subdomain_enum"]
    reloaded = store.get_scan(UUID(user_id), UUID(scan_id))
    assert reloaded is not None and reloaded.status == "failed"
    assert reloaded.error == "AGENT_STAGE_FAILED"


# ---------------------------------------------------------------------------
# M3 review fix: partial snapshot hashes differently from a complete
# empty surface
# ---------------------------------------------------------------------------


def test_partial_snapshot_hash_differs_from_complete_empty_snapshot(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M3: a partial empty snapshot and a complete empty snapshot must
    not hash identically."""
    empty_complete = {
        "subdomains": [],
        "open_ports": [],
        "technologies": [],
        "tls": {},
        "partial": False,
        "missing_stages": [],
    }
    empty_partial = {
        **empty_complete,
        "partial": True,
        "missing_stages": ["http_probe", "port_scan", "subdomain_enum"],
    }
    assert compute_attack_surface_hash(empty_partial) != (
        compute_attack_surface_hash(empty_complete)
    )

    # And the task's partial hash is the partial snapshot's hash.
    scan_id, user_id, _ = _make_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(stage, []),
    )
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda url, timeout=10.0, max_bytes=65536: httpx.Response(200, content=b""),
    )
    result = tech_fingerprint.apply_async(args=[scan_id, user_id]).get()
    assert result["snapshot_partial"] is True
    assert result["attack_surface_hash"] == compute_attack_surface_hash(empty_partial)


# ---------------------------------------------------------------------------
# M4 review fix: stored-list caps (5,000) + per-stage host cap (100)
# ---------------------------------------------------------------------------


def test_subdomain_enum_caps_stored_list_at_5000(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M4: 5,002 subdomains store the first 5,000 (sorted) with
    truncated=true + total_count; the next stage gets at most 100
    hosts, apex first."""
    scan_id, user_id, _ = _make_scan(store)
    all_subdomains = ["example.com"] + [f"h{i:05d}.example.com" for i in range(5001)]
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(stage, [{"subdomains": all_subdomains}]),
    )
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda url, timeout=10.0, max_bytes=65536: httpx.Response(200, content=b""),
    )

    result = subdomain_enum.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["count"] == 5000
    assert result["total_count"] == 5002
    assert result["truncated"] is True
    assert result["subdomains"][0] == "example.com"
    assert "h05000.example.com" not in result["subdomains"]
    assert result["subdomains"] == sorted(result["subdomains"])
    # The chained port_scan got at most 100 hosts, apex first.
    port_log = _job_log(store, user_id, scan_id, "port_scan")
    assert len(port_log["hosts"]) == 100
    assert port_log["hosts"][0] == "example.com"
    assert port_log["hosts_fallback_apex"] is False


def test_crawl_caps_stored_url_lists_at_5000(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M4: 5,001 crawl URLs / JS files store the first 5,000 each."""
    scan_id, user_id, _ = _make_scan(store)
    urls = [f"https://example.com/p{i:05d}" for i in range(5001)]
    js_files = [f"https://example.com/x{i:05d}.js" for i in range(5001)]
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(stage, [{"urls": urls, "js_files": js_files}]),
    )
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda url, timeout=10.0, max_bytes=65536: httpx.Response(200, content=b""),
    )
    monkeypatch.setattr("app.workers.tasks._JS_FETCH_DELAY_SECONDS", 0)

    result = crawl.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["url_count"] == 5000
    assert result["js_count"] == 5000
    assert result["total_url_count"] == 5001
    assert result["total_js_count"] == 5001
    assert result["truncated"] is True
    assert result["hosts_fallback_apex"] is True  # no prior subdomain log
    assert result["hosts"] == ["example.com"]


# ---------------------------------------------------------------------------
# M6 review fix: js_secret_scan fetches same-domain JS only
# ---------------------------------------------------------------------------


def test_js_secret_scan_skips_off_domain_js(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M6: CDN / lookalike-domain JS is skipped and counted, never
    fetched — only the target domain and its subdomains are scanned."""
    scan_id, user_id, _ = _make_scan(store)
    _seed_stage_log(
        store,
        user_id,
        scan_id,
        "crawl",
        {
            "status": "done",
            "urls": [],
            "js_files": [
                "https://example.com/app.js",
                "https://cdn.example.net/lib.js",
                "https://evil-example.com/x.js",
                "https://sub.example.com/widget.js",
            ],
        },
    )
    fetches: list[str] = []

    def _fake_fetch(url: str, timeout: float = 10.0, max_bytes: int = 65536) -> httpx.Response:
        fetches.append(url)
        return httpx.Response(200, content=FAKE_JS.encode())

    monkeypatch.setattr("app.workers.tasks.pinned_get", _fake_fetch)

    result = js_secret_scan.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["files_scanned"] == 2
    assert result["files_skipped_off_domain"] == 2
    assert fetches == [
        "https://example.com/app.js",
        "https://sub.example.com/widget.js",
    ]
    # Two secrets per on-domain file, none from the skipped files.
    assert result["secrets_found"] == 4


# ---------------------------------------------------------------------------
# M7 review fix: robots.txt respected by the crawl stage
# ---------------------------------------------------------------------------


def test_crawl_filters_robots_disallowed_urls(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M7: User-agent: * Disallow rules filter katana's URLs (prefix
    match on path) before storing; other user-agents' rules do not."""
    scan_id, user_id, _ = _make_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(
            stage,
            [
                {
                    "urls": [
                        "https://example.com/",
                        "https://example.com/public",
                        "https://example.com/public/app.js",
                        "https://example.com/private/secret",
                        "https://example.com/private/app.js",
                    ],
                    "js_files": ["https://example.com/private/app.js"],
                }
            ],
        ),
    )

    def _fake_fetch(url: str, timeout: float = 10.0, max_bytes: int = 65536) -> httpx.Response:
        assert url == "https://example.com/robots.txt"
        return httpx.Response(
            200,
            content=(
                b"User-agent: *\nDisallow: /private/\n\nUser-agent: Googlebot\nDisallow: /public/\n"
            ),
        )

    monkeypatch.setattr("app.workers.tasks.pinned_get", _fake_fetch)

    result = crawl.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["robots_fetch_failed"] is False
    assert result["robots_disallowed_filtered"] == 3
    assert result["urls"] == [
        "https://example.com/",
        "https://example.com/public",
        "https://example.com/public/app.js",
    ]
    assert result["js_files"] == []


def test_crawl_proceeds_when_robots_fetch_fails(
    _patched_store: InMemoryStore,
    store: InMemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M7: a failed robots.txt fetch is best-effort — the crawl
    proceeds unfiltered and records robots_fetch_failed."""
    scan_id, user_id, _ = _make_scan(store)
    monkeypatch.setattr(
        "app.workers.tasks.run_stage",
        lambda stage, domain, **kw: _runner_outcome(
            stage,
            [{"urls": ["https://example.com/private/secret"], "js_files": []}],
        ),
    )
    monkeypatch.setattr(
        "app.workers.tasks.pinned_get",
        lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("refused")),
    )

    result = crawl.apply_async(args=[scan_id, user_id]).get()

    assert result["status"] == "done"
    assert result["robots_fetch_failed"] is True
    assert result["robots_disallowed_filtered"] == 0
    assert result["urls"] == ["https://example.com/private/secret"]
