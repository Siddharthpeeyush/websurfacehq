# scanner-agent (Go) — PLACEHOLDER

**Status:** Phase 0 — this package contains **no code**. This README is a placeholder
only, describing what will be built here and what is blocking it. Do not treat this
directory as a working component.

## What the Go scanner-agent binary will be

A tiny Go binary shipped to the Celery workers. It does the hot-path work that Python
orchestrates but should not do itself: fast, concurrent port scanning and crawling.
It will:

- Wrap ProjectDiscovery tools **via exec** — `naabu` (port scan), `httpx` (live-host
  probe, tech fingerprint, TLS, screenshots), `katana` (crawl, JS file discovery),
  `nuclei` (vulnerability templates) — and parse their JSONL output.
- Accept one stage's input (target domain, scope, limits) on stdin or argv, run the
  tool with the safe flags (curated template set, rate limits, timeouts), and emit
  structured JSONL results on stdout for the Python worker to store.
- Enforce the scanner-safety rules at the point of execution: the worker-side SSRF
  blocklist (`10/8, 172.16/12, 192.168/16, 127/8, 169.254.169.254`, `localhost`,
  `*.local`, `*.internal`, plus the DNS-rebinding check) applies to everything the
  agent fetches, and no intrusive stage runs for an unverified target.
- Stay small and boring: exec + JSONL parsing + safe defaults. No custom port scanner,
  no custom crawler, no Nuclei replacement (blueprint §3.8 forbids rebuilding them).

## Why Go

Go's concurrency model fits the hot path (probing thousands of subdomains, scanning the
top ports) and the tools being wrapped are themselves Go-native and designed to pipe
JSONL to each other (`subfinder | httpx | katana | nuclei`). Python orchestrates the
pipeline; Go does the fast, concurrent execution.

## Toolchain — resolved in Phase 0

**Go 1.27.4 is installed on this VM.** Installed 11 Nov 2026: official tarball from
go.dev, SHA256-verified, user-local at `~/go` (no sudo). Verified: `go version
go1.27.4 linux/amd64`. The Go scanner-agent phase is **unblocked** — the toolchain
gap from the plan is closed. This package is still a placeholder in Phase 0: no Go
code has been written yet; the first Go file lands in the scanner-agent phase.

**Do NOT fake the agent in Python.** A Python reimplementation of the scanner-agent
presented as the Go binary would be a false deliverable: it would hide the missing
toolchain, perform worse on the hot path, and break the architecture decision recorded
in `docs/decisions/adr-0002-nextjs-fastapi-go-stack.md`. If Go cannot be installed,
report the blocker — do not substitute Python and call it done.

## Planned layout (when built)

```
packages/scanner-agent/
├── README.md          # this file (updated when the agent lands)
├── go.mod
├── cmd/scanner-agent/main.go
├── internal/
│   ├── runner/        # exec wrapper: timeouts, safe flags, output streaming
│   ├── parsers/       # JSONL parsers for naabu / httpx / katana / nuclei
│   └── ssrf/          # blocklist + DNS-rebinding check (shared with the worker)
└── testdata/          # recorded tool outputs as parser fixtures
```
