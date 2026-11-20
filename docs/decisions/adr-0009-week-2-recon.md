# ADR-0009: Week 2 Recon — Go scanner-agent + Python worker stages (16 Nov 2026)

**Status:** Accepted (build complete on branch `week-2-recon`, 16 Nov 2026;
independent security review verdict recorded in §8; live smoke test still
open — see §7). Pushed to GitHub 16 Nov 2026 (commit `d2aa9c21`,
owner-approved) on branch `week-2-recon`.

## Context

Week 2 (ENGINEERING-PLAN.md §3, `docs/week-2-plan.md`) is the recon
phase: subfinder / crt.sh, httpx, naabu, JS secret scraper, tech
fingerprint / TLS / screenshots, first live scan on the owner's own
domain only. The Week 1 pipeline registered the seven recon stages with
`implemented=False`; this ADR records them landing as real code.

## Decision

1. **Real Go scanner-agent, stdlib only.** `packages/scanner-agent/`
   (module `websurfacehq/scanner-agent`, Go 1.27, zero external deps):
   `cmd/scanner-agent/main.go` reads ONE JSON object on stdin
   (`stage`, `domain`, `hosts?`, `timeout_seconds`, `rate_limit`,
   `max_ports`) and emits JSONL on stdout (`result` / `log` / `error`
   lines); exit 0 = success, non-zero = stage failure. `internal/runner/`
   is the exec wrapper (context timeout, whole-process-group kill on
   expiry, 2-concurrent semaphore, 32 MiB output cap, argv only — no
   shell anywhere). `internal/parsers/` parses subfinder / crt.sh / httpx /
   naabu / katana JSONL (malformed lines skipped + counted, never fatal).
   `internal/ssrf/` ports the Python guard (below). `internal/dnsenum/`
   does `dns_enum` via the crt.sh API + Go stdlib DNS. `internal/agent/`
   dispatches stages with curated flags only. The agent was NOT faked in
   Python — Go 1.27.4 is installed on this VM and the binary is built at
   `packages/scanner-agent/scanner-agent` (gitignored build artifact).
2. **SSRF guard enforced twice, same rules.** Python
   `app/core/ssrf.py` stays the source of truth for the API/worker; the
   Go agent re-checks at the point of execution (blocklist `10/8`,
   `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `0/8`, `localhost`,
   `*.local`, `*.internal`, `metadata.google.internal`, IPv6 `fc00::/7`,
   `fe80::/10`, `::1`, `::`, IPv4-mapped IPv6 unwrapped; resolve twice,
   reject if either resolution introduces a non-global IP; fail closed
   on unresolvable hosts). The Python runner SSRF pre-checks the domain
   before invoking the binary, so both layers fail closed consistently
   (proven by the VM sink-DNS incident in §7: both refused).
3. **Connect scan is the naabu default.** Evidence
   (`packages/scanner-agent/docs/naabu-scan-modes.md`): a SYN scan
   requested unprivileged silently falls back to CONNECT (naabu logs
   "Running CONNECT scan with non root privileges") — even as uid 0 in
   this cell, which drops capabilities — so a true SYN scan could not be
   demonstrated here at all, and on Render Free a SYN request would
   silently become CONNECT anyway. The agent therefore uses
   `-scan-type connect` by default. This is a REPORTED FINDING, not a
   failure to fix by renting a VPS: the Oracle Always Free first /
   Hetzner fallback decision is the owner's and needs his card answer.
   Two flag corrections from live `naabu -h`: `-timeout` is a duration
   (`"120s"` — bare `120` means 120 ms) and `-top-ports` is a string;
   naabu also needs `-Pn` (host discovery hangs without it on
   known-live hosts).
4. **Python worker integration.** `app/workers/scanner_runner.py` invokes
   the agent (stdin JSON, timeout, JSONL parse, malformed lines counted,
   non-zero exit raises `ScannerAgentError` carrying ONLY the agent's
   error line truncated to 500 chars; missing binary raises loud
   `ScannerAgentUnavailable`). Seven real Celery tasks in
   `app/workers/tasks.py` (`websurfacehq.recon.<stage>`, `SCAN_PIPELINE`
   flipped to `implemented=True` for all seven): `dns_enum`,
   `subdomain_enum`, `port_scan`, `http_probe`, `tech_fingerprint`,
   `crawl`, `js_secret_scan`. Every task re-checks
   `target.verification_status == "verified"` before ANY outbound
   request and refuses cleanly (`TARGET_NOT_VERIFIED`, scan failed,
   audit log) with zero outbound calls in that path. Findings go through
   `Store.create_finding`; recon summaries go in the stage job's `log`
   JSON (Week 1 pattern).
5. **Pinned-IP transport closes the TOCTOU race for JS fetches only.**
   `app/workers/pinned_http.py` (`pinned_get`): resolve once, check
   every address, connect the socket to the checked IP while sending the
   hostname as `Host` and TLS SNI/cert name (stdlib `socket`+`ssl` +
   hand-rolled HTTP/1.1 reader — httpx cannot pin, its transports derive
   connect address and SNI from the URL host). 64 KiB cap, no redirects.
   NOT closed by this work: the agent binary's own fetches (httpx/katana
   inside Go) and the verification re-check fetches (`safe_get`,
   check-then-connect window as documented in `ssrf.py`). Do not claim
   the race is closed for those paths.
6. **JS secret scraper: redacted by construction.**
   `app/services/js_secrets.py` (pure functions, no network): 12 regex
   patterns (AWS access/secret, generic API key, Bearer, GitHub, Slack,
   Stripe live, private key, JWT, Google API key, database URL,
   generic password); Shannon entropy > 4.5 gates the generic patterns;
   context scoring raises confidence on named-service context and
   suppresses placeholders/test values. `redact_value()` keeps first 4 +
   `...` + last 4 chars (≤ 8 chars of any secret); DB-URL snippets are
   scheme-only; private-key snippets are the header only. Tests assert
   no fixture secret appears anywhere in any returned dict. Findings use
   template ids `js-secret-<pattern_name>` (snake_case) with severity
   from the scraper; evidence is pattern + file + line + redacted
   snippet only. `app/services/techprint.py`: `fingerprint()` (httpx
   `tech` list + header/cookie/body heuristics, never invents a
   technology), `tls_summary()` (version/issuer/expiry/self-signed +
   `grade_hint` of `ok`/`weak`/`expired`/`unknown`), `summarize_http_probe()`.
7. **Attack-surface snapshot hash.** `compute_attack_surface_hash()` in
   `tasks.py`: SHA-256 of canonical JSON over sorted subdomains + sorted
   open ports + sorted tech stack + TLS summary. `tech_fingerprint`
   computes it from the prior stages' job logs and stores
   `attack_surface_hash` + `snapshot_counts` in its job log; missing
   prior logs give `snapshot_partial: true` + `missing_stages` instead
   of failing the stage. Week 4's diff compares hashes/snapshots across
   scans of the same target.

## Live-scan blocker (environment, not code — needs parent decision)

**This VM's cell resolver answers every hostname with a synthetic
`198.18.166.x` address** (verified by the coordinator 16 Nov 2026:
`potatomuzik.me` → `198.18.166.126`, `nonexistent.invalid` →
`198.18.166.128`). Consequences, all verified live: the agent's SSRF
check correctly refuses every live domain here (198.18/15 is not
globally routable — fail closed, working as designed); the Python
pre-check refuses identically before the binary is invoked; crt.sh
returns a proxy 502; katana fails the TLS handshake; naabu rejects the
sink IP outright ("no valid ipv4 or ipv6 targets"). **An end-to-end live
smoke test through the agent binary cannot run on this VM.** It needs
real DNS (Render worker) or a non-sink resolver. No DNS was faked
(e.g. `/etc/hosts`) to force it — that would have made the SSRF check
pass on a spoofed answer. Closest verifiable evidence on this VM: unit /
CLI tests with fake resolver + tools, direct real-tool runs with
identical flags, real-capture parser tests, and B-extractor checks
against exact payloads. The live smoke test on `potatomuzik.me` (plan
§8 item 4, `docs/week-2-live-scan-2026-11-16.md`) is therefore NOT done
in this run; it is the parent's next step, on real DNS.

## Consequences / open items

- **Task-name/queue mismatch (decision for the parent):** tasks are
  named `websurfacehq.recon.<stage>`, but `celery_app` routes
  `*.crawl.*` → `crawl` queue, so `crawl` and `js_secret_scan` land on
  the `recon` queue despite `SCAN_PIPELINE` listing them under `crawl`.
  Renaming to `websurfacehq.crawl.<stage>` is a one-line change when
  dispatch starts enqueuing recon stages.
- **Pinned fetches go direct (no proxy).** On this VM direct egress is
  blocked, so a live `pinned_get` to `potatomuzik.me` fails here; on
  Render (direct egress) it should work. A VM smoke test would record
  `files_failed` for every JS file — environmental, not a code failure.
- **Screenshots:** httpx `-screenshot` attempted; the renderer
  downloads Chromium (~150 MB, `~/.cache/rod` now 533 MB) and the first
  screenshot pass may exceed its cap — the agent honestly reports
  `screenshot_unavailable` instead of fabricating an image, and
  screenshot bytes are excluded (`-esb`); screenshots are never stored,
  only the marker.
- **Parsers verified against real tool output** (frozen in
  `packages/scanner-agent/testdata/*.real.jsonl`): httpx (200
  PotatoMuzik + 301 www — parser corrected: IPs live in `"a"`, TLS
  version in `"tls_version"`); subfinder v2.17.0 (0 subdomains, no
  provider keys — legitimate empty result); naabu v2.7.0 (real JSON has
  no `"host"` field — parser falls back to IP); katana (real output was
  a TLS-handshake error line — parser now skips error entries). crt.sh
  stays synthetic (proxy 502 on this VM).
- **Contract mismatches found and fixed on the Go side** (B's tolerant
  extractors vs A's first payloads): `port_scan` now emits one result
  per host + summary; `http_probe` per-host records carry `"status"` as
  well as `"status_code"`; `crawl` `"urls"` are strings (full detail
  under `"crawled"`). Verified by importing B's real `_extract_*`
  functions against A's exact payloads. `DisallowUnknownFields` dropped
  in `main.go` so B's `extra` fields cannot break a stage.
- **One test-isolation fix by the coordinator** (disclosed, not a
  behaviour change): `test_resolve_agent_binary_raises_when_nothing_found`
  assumed the checked-out binary did not exist; once A built it
  (gitignored artifact), resolution correctly succeeded and the test
  failed. Fixed by hiding the binary from resolution inside that test
  only (patch `Path.is_file` for `scanner-agent`); the asserted behaviour
  (loud failure when no binary resolves) is unchanged. No other test was
  edited. B's one disclosed edit stands: the Week 1 pipeline assertion
  became the Week 2 assertion (seven recon stages implemented).
- **No new dependencies.** Go: stdlib only. Python: none added
  (httpx/dnspython already pinned). No Week 3 scope (agent rejects
  `nuclei` etc. with an error) and no Week 4 scope. `dispatch.py`
  untouched — recon stages are not auto-enqueued yet.

## Gates (16 Nov 2026, coordinator re-run — full CI command set)

Saved in `docs/week-2-gate-outputs/`
(`python-gates-2026-11-16.txt`, `go-gates-2026-11-16.txt`,
`scanner-agent-gates-2026-11-16.txt` from workstream A).

- Python (`apps/api`): `ruff check .` — All checks passed;
  `ruff format --check .` — 63 files already formatted;
  `mypy .` — Success: no issues found in 61 source files;
  `pytest -q` — **282 passed, 1 warning** (pre-existing Starlette /
  httpx `TestClient` deprecation, not from Week 2 code).
- Go (`packages/scanner-agent`): `gofmt -l .` — empty; `go vet ./...`
  — exit 0; `go test -count=1 ./...` — **6 packages ok, 57 `--- PASS`
  lines** (incl. subtests; workstream A reported 45 top-level tests).

## 8. Independent security review

**NOT APPROVED (16 Nov 2026, reviewer 05:05 UTC)** — see the entry below
for the fix pass and re-review.

First review (gates matched the coordinator's: pytest 282, ruff/mypy
clean, `go vet` clean, `go test` 6 packages ok). Blocking findings:
**B1** — Python-side timeout kills only the agent binary; tool children
orphaned and keep scanning (proven empirically with a fake agent +
own-session `sleep 30` child surviving `ScannerAgentTimeout`); **B2** —
pipeline not wired: dispatch enqueues only `verify_target`, stages scan
the apex only, no chaining, discovered subdomains never probed; **B3** —
B↔A contract break: `technologies` / `issuer_cn` / `subject_cn` /
`webserver` never reach `fingerprint`, so the snapshot hash is blind to
tech (proven by feeding real agent-shaped output through
`_extract_live_hosts` → `fingerprint`: `technologies: []`).
Non-blocking: M1 screenshots to shared cwd + misleading marker; M2 retry
storm on deterministic failures; M3 partial snapshots hash identically
to empty surfaces; M4 unbounded stored lists, no request-budget
enforcement; M5 politeness caps process-local; M6 JS fetched from any
public host; M7 `robots.txt` not respected; M8 Go SSRF parity gaps
(incl. `::127.0.0.1` passing BOTH guards — a hole in the Week 1 Python
source of truth); M9 hostname charset; M10 `scan_js` quadratic line
numbers; M11 hosts unchecked Python-side, uncapped stdout, `extra=`
override; M12 refusal messages name resolved IPs; M13 uncapped stdin,
screenshot pass doubles requests; M14 target titles stored raw (Week 4
must HTML-escape); M15 `dns_enum` can emit private IPs on a rebinding
flip. Held under attack: verification gate (all 7 stages), SSRF guard,
argv-only exec, secret redaction.

**Fix pass (16 Nov 2026):** Python-side fixer (B1 Python half, B2, B3
Python half, M2, M3, M4, M6, M7, M10, M11, M14) and Go-side fixer (M1,
M8, M9, M13, M15, B1 Go verification, M5 docs); coordinator ported the
M8 IPv6 ranges to Python `ssrf.py` (`::/96`, `2001:db8::/32`,
`2001:2::/48`, `2001:10::/28`, `100::/64`) closing the `::127.0.0.1`
hole in the Week 1 source of truth, with tests.

**RE-REVIEW: APPROVED (16 Nov 2026, reviewer 05:49 UTC).** The re-reviewer
re-ran the first review's empirical proofs itself: B1 orphan kill
verified (fake-agent child dead after `ScannerAgentTimeout`); B2 eager-mode
end-to-end test re-run (dispatch → all 8 stages `done`, non-apex hosts in
recorded stdin payloads, findings stored, cached re-run does not
re-enqueue); B3 verified with real agent output (Netlify detected, TLS
1.3, issuer YE2, hash covers tech). All M1–M15 verified fixed. Gates
re-run by the re-reviewer matched: pytest 299, ruff/mypy clean, `go vet`
clean, `go test` 62 PASS. No test was weakened to pass.

Residuals (Low, non-blocking) and their disposition:
- **R1 — `setsid` escape (accepted risk):** a tool child that calls
  `setsid()` itself survives the process-group kill (re-reviewer proved
  it). Accepted: the curated tools never re-session; escaping requires a
  malicious/replaced tool binary, which already implies worker
  compromise. Same residual exists on the Go side.
- **R2 — `open_ports` uncapped: FIXED by the coordinator after the
  re-review** (cap 5,000 via `_MAX_STORED_URLS`, `open_ports_total` /
  `open_ports_truncated` recorded; per-port findings capped with the
  list). Gates re-run after the fix: pytest 299, Go 62 PASS — the
  re-reviewer did not re-verify this one-liner; it is a mechanical cap
  in the already-reviewed pattern.
- **R3 — Teredo `2001::/32`: FIXED by the coordinator after the
  re-review** (added to Go `blockedPrefixes` + Python `_BLOCKED_NETWORKS`
  for symmetry, with tests both sides). The re-reviewer corrected the
  premise: Python's `is_global` is already False for Teredo; only Go's
  `IsGlobalUnicast` passed it, and the production path was protected by
  the Python pre-check. Same one-liner caveat as R2.
- **R4 — refusal log line named the resolved IP: FIXED by the
  coordinator after the re-review** (`_refuse_stage_error` now logs only
  the error code + exception class). Same one-liner caveat as R2.

Open items carried forward (not code defects, do not block sign-off):
live end-to-end smoke test on `potatomuzik.me` still impossible on this
VM (sink DNS — fail-closed verified; needs real DNS / Render worker);
Celery against a real broker (Week 1 open item); Supabase-backed store
for the new stages (tests use `InMemoryStore`; store contract unchanged).
Week 4 notes: HTML-escape stored titles on render (M14); render refusal
codes as human-readable messages.
