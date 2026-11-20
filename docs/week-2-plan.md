# Week 2 — Recon plan (Mon 16 – Sun 22 Nov 2026)

**Status:** PLAN (16 Nov 2026, kickoff run). Implementation follows the repo working
loop: plan → review → implement in small steps on a branch → lint + typecheck +
tests → review the diff → independent security review before reporting done.

**Scope (ENGINEERING-PLAN.md §3, Week 2):** subfinder / crt.sh, httpx, naabu, JS
secret scraper (Katana-collected JS, regex + entropy > 4.5 + context scoring,
redacted flags), tech fingerprint / TLS / screenshots, first live scan on the
owner's own domain ONLY. Exit gate: end-to-end recon scan on the owner's domain
with findings stored and diff hashing working.

## 1. Architecture (already decided — ADR-0002, scanner-agent README)

- Go `scanner-agent` binary (`packages/scanner-agent/`) wraps ProjectDiscovery
  tools **via exec** and emits structured JSONL on stdout. It does NOT reimplement
  port scanning or crawling. Python orchestrates; Go executes the hot path.
- Python Celery worker (`apps/api/app/workers/tasks.py`) gains real tasks for the
  Week 2 stages and calls the agent binary through a small runner module
  (`apps/api/app/workers/scanner_runner.py`, new). The runner passes one stage's
  input as JSON on stdin, enforces a timeout, and parses JSONL lines.
- Results land in the existing store: recon summary JSON in the stage's
  `scan_jobs.log` (the Week 1 pattern), and real findings via
  `Store.create_finding` (severity per finding type, evidence redacted).
- The verification gate stays: NO recon stage runs for an unverified target
  (`verify_target` refuses first; every recon task re-checks
  `target.verification_status == "verified"` before any outbound request).

## 2. Stages and ownership

| Stage (pipeline name) | Tool(s) | Output |
|---|---|---|
| `dns_enum` | crt.sh API (JSON) + Go stdlib DNS | subdomains from Certificate Transparency |
| `subdomain_enum` | subfinder (exec) | deduped subdomain list |
| `port_scan` | naabu (exec, **connect scan** — see §4) | open ports per host |
| `http_probe` | httpx (exec) | live hosts, status, title, tech, TLS, IP |
| `tech_fingerprint` | httpx tech-detect + header heuristics (Python) | tech stack per host |
| `crawl` | katana (exec) | URLs + JS file list |
| `js_secret_scan` | Python regex + Shannon entropy > 4.5 + context scoring on Katana JS | redacted secret findings, never the secret value |

Screenshots: httpx `-screenshot` — attempt it; if the renderer's headless
browser is unavailable in the worker environment, record the gap honestly and
store a `screenshot_unavailable` marker instead of faking an image. Do NOT
fabricate a screenshot.

## 3. Safety rules (non-negotiable, from AGENTS.md §2/§3)

- **Authorized scanning only.** First live scan target is `potatomuzik.me`
  (owner's own domain; `websurfacehq.com` is unregistered). No other live
  target in this run.
- **SSRF blocklist + DNS-rebinding check** apply to everything the agent and
  the worker fetch: `10/8, 172.16/12, 192.168/16, 127/8, 169.254/16`,
  `localhost`, `*.local`, `*.internal`, IPv6 `fc00::/7`, `fe80::/10`, `::1`.
  The Go agent enforces the same blocklist before exec (shared logic, ported
  from `apps/api/app/core/ssrf.py` — the Python side stays the source of truth
  for the API/worker; the agent re-checks at the point of execution).
- **Pinned-IP transport (Week 1 TOCTOU note, `ssrf.py` docstring):** Week 2
  closes the check-then-connect race for the worker's httpx fetches where
  feasible (resolve once, connect to the checked IP with Host/SNI set).
  If it cannot be closed cleanly for a given fetch path, say so in the report
  instead of claiming it.
- **Politeness:** 5 req/s per domain, 2 concurrent, respect `robots.txt` +
  `Retry-After`, per-target timeouts on every tool (naabu/httpx/katana/subfinder
  each get an explicit timeout; agent kills the child on expiry).
- **Secrets:** found secrets are flagged REDACTED and NEVER used, logged, or
  stored in full. Evidence stores only the pattern name, file, line number,
  and a redacted snippet (first/last 4 chars max, or none). No secret value in
  logs, findings, scan_jobs.log, or test fixtures — fixtures use synthetic
  fake secrets only.
- **Safe payloads only.** Recon is passive/active-read-only: DNS, TCP connect,
  HTTP GET/HEAD. No exploit payloads (that is Week 3 Nuclei scope, and even
  there only safe templates).

## 4. Render / raw-socket decision point

naabu's SYN scan needs raw sockets (root / CAP_NET_RAW). Render Free almost
certainly does not grant them. Week 2 MUST answer this with evidence:

1. Run naabu locally in this VM in both modes; record which works unprivileged.
2. Design the agent to use **connect scan** (`-scan-type connect` / `-s connect`)
   as the default so it works on Render Free without privileges.
3. If evidence shows Render cannot do raw sockets, that is a REPORTED FINDING,
   not a failure to fix by renting a VPS. The Oracle Always Free first /
   Hetzner fallback decision is the owner's and needs his card answer — do NOT
   rent anything in this run.

## 5. Diff hashing (exit-gate requirement)

Each recon scan computes a deterministic snapshot hash over the sorted
subdomain list + open ports + tech stack + TLS summary and stores it in the
scan's job log (`attack_surface_hash`, plus the snapshot counts). Week 4's
diff compares hashes/snapshots across scans of the same target. The hash
covers structure, not finding verdicts.

## 6. Testing (test-first, per repo rules)

- Go: unit tests for every parser against recorded fixtures in
  `packages/scanner-agent/testdata/` (real tool output captured once, then
  frozen); SSRF-blocklist tests; runner timeout/kill tests.
- Python: unit tests for the JS secret scraper (entropy + context scoring,
  redaction — assert no secret value appears in the finding), runner
  (timeout, malformed JSONL, non-zero exit), and each new Celery task
  (verification-gate refusal, idempotency re-run returns cached result,
  unverified target makes zero outbound requests — mock the runner).
- Full gates before reporting done: `ruff check`, `ruff format --check`,
  `mypy .`, full `pytest` in `apps/api`; `go vet` + `go test ./...` in
  `packages/scanner-agent`; web untouched unless a dashboard change is needed
  (none planned — recon results surface in Week 4 report UI; do not build UI
  in this run).

## 7. What is NOT in this run

- Week 3 scope (Nuclei, dalfox, LLM triage, KEV/EPSS, safe PoC, attack paths).
- Week 4 scope (PDF report, diff UI, payments, email provider).
- No push to GitHub in this run — pushes go through the GitHub connector with
  the owner's approval taps; the owner is not present in this detached run.
  Work lands on a local branch (`week-2-recon`) and is verified locally.
- No VPS, no paid service, no new dependency without the reason recorded
  (AGENTS.md rule 5). New Python deps must be pinned in `requirements.txt`
  with a DEPENDENCIES.md entry; new Go deps in `go.mod` with a reason.

## 8. Deliverables of this run

1. Go scanner-agent: `go.mod`, `cmd/scanner-agent/main.go`,
   `internal/{runner,parsers,ssrf}/`, fixtures + tests, updated README.
2. Python: `app/workers/scanner_runner.py`, recon tasks in
   `app/workers/tasks.py` (stages flipped to `implemented=True` as they land),
   `app/services/js_secrets.py` (scraper), `app/services/techprint.py`
   (fingerprint/TLS summary) — or equivalent modules with reasons recorded.
3. Tests for all of the above + full gate outputs.
4. Live smoke: agent binary run end-to-end against `potatomuzik.me` only,
   with the findings/snapshot recorded in `docs/week-2-live-scan-2026-11-16.md`
   (redacted evidence log, same pattern as the Week 1 live-proof docs).
5. `docs/decisions/adr-0009-week-2-recon.md` + AGENTS.md decision entry.
6. Independent security review sign-off (separate reviewer agent) before the
   run reports Week 2 done; if the review does not approve, the run reports
   exactly what remains.
