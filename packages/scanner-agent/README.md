# scanner-agent (Go)

**Status:** Week 2 Recon — IMPLEMENTED (16 Nov 2026, branch `week-2-recon`).
Real Go, stdlib only, no external dependencies. `go vet ./...` and
`go test ./...` green; `gofmt -l .` empty.

A tiny Go binary shipped to the Celery workers. It does the hot-path work
that Python orchestrates but should not do itself: fast, concurrent port
scanning and crawling. It wraps ProjectDiscovery tools **via exec** and
emits structured JSONL on stdout for the Python worker to store. It does
NOT reimplement port scanning or crawling.

## CLI contract (used by the Python runner — workstream B)

Input: ONE JSON object on stdin (capped at 1 MiB — larger input is
rejected with an error, so a caller cannot force unbounded buffering):

```json
{"stage": "dns_enum"|"subdomain_enum"|"port_scan"|"http_probe"|"crawl",
 "domain": "example.com",
 "hosts": ["example.com"],          // optional, for port_scan/http_probe/crawl
 "timeout_seconds": 120,            // default 120, max 1800
 "rate_limit": 5,                   // default 5, clamped to 5 (politeness cap)
 "max_ports": "top-100",            // default; also "top-1000" or "all"
 "wordlist": "wordlist.txt"}        // optional; accepted, currently unused
```

Output: JSONL on stdout, one object per line — nothing else is ever
printed to stdout (tool stderr goes to our stderr):

```json
{"type":"result","stage":"subdomain_enum","data":{"domain":"example.com","subdomains":[...],"count":4}}
{"type":"log","level":"info","message":"subdomain_enum found 4 subdomains for example.com"}
{"type":"error","message":"SSRF refusal for domain ..."}
```

Exit 0 on success (even if a stage finds nothing); non-zero only on stage
failure (bad input, SSRF refusal, tool missing, timeout).

```sh
echo '{"stage":"subdomain_enum","domain":"example.com"}' | ./scanner-agent
```

## Stages and tools (curated flags only — no shell, no user flags)

| Stage | Tool | Flags |
|---|---|---|
| `dns_enum` | crt.sh API (stdlib `net/http`) + Go DNS | `https://crt.sh/?q=%.domain&output=json`, Proxy: nil (trust_env=False equivalent), no redirect following, 10 MiB body cap |
| `subdomain_enum` | subfinder v2.17.0 | `-d <domain> -silent -json -timeout <t> -rate-limit 5` (`-timeout` is integer seconds) |
| `port_scan` | naabu v2.7.0 | `-host <hosts> -top-ports 100 -scan-type connect -Pn -silent -json -rate 5 -timeout <t>s` |
| `http_probe` | httpx | `-json -silent -status-code -title -tech-detect -tls-probe -ip -timeout <t> -rate-limit 5 -threads 2`, targets on stdin; `-screenshot` attempted as a separate best-effort pass (see below) |
| `crawl` | katana | `-u <hosts> -jsonl -silent -depth 3 -rate-limit 5 -timeout <t> -js-crawl` |

`-timeout` is integer **seconds** on subfinder, httpx and katana
(verified against the real `--help` output). **naabu is the exception:
its `-timeout` is a duration** — the agent passes `"120s"` (a bare
number would be milliseconds). naabu's `-top-ports` takes a string
(`100`/`1000`/`full`); full range is `-top-ports full`, not `-p -`.

**CONNECT scan is the naabu default** (`-scan-type connect`). SYN needs
raw sockets (root / CAP_NET_RAW), which Render Free does not grant; see
`docs/naabu-scan-modes.md` for the unprivileged evidence run. In this
VM a requested SYN scan silently falls back to CONNECT (logged by
naabu) — the explicit default states what actually happens.

**`-Pn` (skip host discovery) is required on naabu.** Without it,
naabu's host discovery hangs in sandboxed environments (this VM: the
agent's literal flag set hit the 45 s timeout with no output). Hosts
reaching `port_scan` are already-known-live, so discovery adds nothing.
This is a deviation from the plan's literal flag list, made on evidence
— see `docs/naabu-scan-modes.md`.

## Result shapes (read by workstream B's Python runner)

One stage emits one summary `result` line, plus — for `port_scan` and
`http_probe` — one `result` per host, because B's extractors read
per-host records (`{"host", "open_ports"}`, `{"host", "status", ...}`).
`http_probe` per-host records carry both `status` and `status_code`,
plus `webserver` and `content_type` passed through from httpx.
`crawl` emits `"urls"` as plain strings (a list of objects would be
dropped by B's extractor); full per-URL detail is under `"crawled"`.

**Screenshots:** httpx `-screenshot` is attempted as a second, best-effort
pass with a short timeout (10–30 s) so a missing headless renderer can
never lose the probe results. The pass runs in a per-run temp dir
(`os.MkdirTemp`, deleted on every exit path — including error and
timeout), so screenshot files can never accumulate in the shared worker
cwd. **The agent never stores or returns screenshot images**, so the
result always carries `"screenshot_unavailable": true` with
`"screenshot_reason": "screenshot_not_persisted"` — even when the pass
runs clean. `"renderer_available"` (true/false) separately records
whether the `-screenshot` pass ran without a renderer error: a probe of
renderer health, not a promise of an image. No image is ever fabricated.
The pass adds `-esb` (exclude screenshot bytes from JSON) because the
agent never stores images. Note: on first use in a fresh environment
httpx's renderer downloads a Chromium build (~150 MB, `~/.cache/rod`,
533 MB total observed here) — the first screenshot pass may exceed its
short timeout and honestly report the renderer unavailable; later passes
reuse the cached browser. On Render, that download happens per cold
worker unless the image pre-bakes it — a deployment note for workstream
B, not a code change.

**`max_ports`:** `top-100` → `-top-ports 100`, `top-1000` → `-top-ports
1000`, `all` → `-p -`. Anything else is a stage error.

## Safety

- **SSRF blocklist + DNS-rebinding check** (`internal/ssrf`, ported from
  `apps/api/app/core/ssrf.py` — Python stays the source of truth, Go
  re-checks at the execution point): `10/8, 172.16/12, 192.168/16, 127/8,
  169.254/16, 0/8`, `localhost` / `*.localhost` / `*.local` / `*.internal` /
  `metadata.google.internal`, IPv6 `fc00::/7, fe80::/10, ::1, ::, ::/96
  (IPv4-compatible — covers ::127.0.0.1), 2001:db8::/32 (documentation),
  2001:2::/48 (benchmarking), 2001:10::/28 (ORCHID), 100::/64
  (discard-only)`, IPv4-mapped IPv6, plus CGNAT/benchmarking/documentation/
  multicast/reserved ranges (Python `is_global` semantics). The hostname
  is resolved TWICE; either resolution introducing a non-global IP is
  rejected. Fail closed on unresolvable hosts. Enforced on the domain and
  every host BEFORE any exec. TOCTOU honesty note: the check-then-connect
  window is narrowed, not closed — see `internal/ssrf/ssrf.go`. The
  explicit prefix list is the ONLY layer for IPv4 privates and the IPv6
  special ranges above: `netip.IsGlobalUnicast` returns true for
  `10.0.0.1`, `100.64.0.1`, `198.18.0.1`, `::127.0.0.1`, `2001:db8::1`
  and the rest (verified 16 Nov 2026), so it must never be relied on
  alone. `dns_enum` also filters its own DNS answers through the same
  check: a private IP that appears after the check is dropped from the
  result and recorded in `dropped_private_ips`.
- **Politeness (honest bound):** 5 req/s and 2 concurrent runs max PER
  AGENT PROCESS (the per-tool rate flags and the runner semaphore). That
  is NOT a per-target bound: with N worker processes probing the same
  target, the per-target rate multiplies by N. The per-target rate is
  therefore only bounded by deployment (one worker per scan in the Week
  2 design), not by this code.
- **Timeout ordering:** the agent's own timeout (`timeout_seconds`,
  applied as the context deadline) fires FIRST and group-kills the tool
  and any children it spawned (process-group kill — a hung tool cannot
  outlive the stage or orphan children); the Python runner's longer
  timeout (timeout + 30 s grace) is only a backstop for a wedged agent
  process. The `dns_enum` HTTP fetch and the screenshot pass run under
  the same stage context, so every path gets the kill — no tool or fetch
  runs outside the timeout.
- **Secrets:** found secrets are flagged REDACTED and never used, logged,
  or stored. Fixtures use synthetic fake data only (`example.com`).
- **Output cap:** tool stdout capped at 32 MiB (OOM guard).

## Layout

```
packages/scanner-agent/
├── README.md                  # this file
├── go.mod                     # module websurfacehq/scanner-agent, go 1.27, stdlib only
├── cmd/scanner-agent/main.go  # stdin JSON → agent.Run → exit code
├── internal/
│   ├── agent/     # stage dispatch, CLI contract, curated flags, JSONL emission
│   ├── dnsenum/   # dns_enum: crt.sh fetch + stdlib DNS lookup
│   ├── parsers/   # JSONL parsers: subfinder, crt.sh, naabu, httpx, katana
│   ├── runner/    # exec wrapper: timeout, process-group kill, 2-concurrent cap
│   └── ssrf/      # blocklist + DNS-rebinding check (ported from ssrf.py)
├── testdata/      # parser fixtures (SYNTHETIC — see testdata/README.md)
└── docs/
    └── naabu-scan-modes.md    # connect-vs-SYN evidence (unprivileged)
```

## Build, gates, tests

```sh
export PATH="$HOME/go/bin:$PATH" GOPATH="$HOME/gopath"
go build ./...        # or: go build -o scanner-agent ./cmd/scanner-agent
go vet ./...
go test ./...         # parsers (fixture-driven), SSRF blocklist + rebinding,
                      # runner timeout/kill (sleep must die on expiry),
                      # CLI end-to-end with fake tools on PATH
gofmt -l .            # must be empty
```

## Known VM-environment limits (16 Nov 2026 — NOT code defects)

This VM's cell resolver answers **every** hostname with a synthetic
`198.18.166.x` address (even `nonexistent.invalid` resolves), and direct
egress is proxy-only. Consequences, all verified live:

1. The agent's SSRF check **correctly refuses every live domain on this
   VM** (198.18/15 is not globally routable — fail closed, working as
   designed). A live end-to-end smoke test through the agent binary needs
   real DNS (Render worker), not this VM.
2. `crt.sh` via the egress proxy returns **502 Bad Gateway**, so `dns_enum`
   cannot be verified live from this VM either.
3. `subfinder` v2.17.0 against `potatomuzik.me` returns **0 subdomains in
   ~12 ms** (no provider keys configured; free sources produced nothing
   here) — a legitimate empty result, exit 0, not a parser failure.
4. `katana` cannot fetch `potatomuzik.me` from this VM: its only output
   line is an error (`tls: first record does not look like a TLS
   handshake`) — katana appears to connect directly to the sink IP
   rather than via the egress proxy, unlike httpx which works. The
   parser skips error lines (proven by the real fixture); a real katana
   crawl needs real egress.
5. `naabu` cannot scan any live domain from this VM either: it rejects
   the sink-DNS answer outright (`Could not run enumeration: no valid
   ipv4 or ipv6 targets were found`). The real naabu fixture is
   therefore the 127.0.0.1 evidence capture.
6. `httpx -screenshot` works here only after downloading a Chromium
   build (see Screenshots above).

## What is NOT here (Week 3/4 scope)

No nuclei/dalfox/LLM/KEV/PoC (Week 3), no PDF report/diff UI/payments
(Week 4). The agent rejects unknown stages (e.g. `nuclei`) with an error.
