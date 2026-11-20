# naabu scan modes — evidence (16 Nov 2026)

Question (week-2-plan §4): does naabu's SYN scan work unprivileged, and
is the agent's CONNECT-scan default right? Answer: **CONNECT is the
default, and it is the only mode that behaves predictably without
privileges.** Evidence below; all runs in this VM, naabu v2.7.0.

## Test setup

- Listener: `python3 -m http.server 18080 --bind 127.0.0.1` (known-open
  port 18080 on loopback). Target for every evidence run: `127.0.0.1`
  only — the only loopback target the task authorizes for this test.
- Current user is uid 0 (`whoami` = root), but naabu itself reports
  "non root privileges" in every verbose run here: this cell drops
  capabilities despite uid 0. Unprivileged runs were also done as
  `nobody` via `setpriv --reuid=nobody --regid=nogroup --clear-groups`.

## Evidence

| # | Run (all `naabu -host 127.0.0.1 -p 18080 ... -rate 5 -timeout 10s`) | Result |
|---|---|---|
| 1 | `-scan-type connect`, no `-Pn` (uid 0) | HANG — `timeout 60` killed it (exit 124), no output |
| 2 | `-scan-type syn`, no `-Pn` (uid 0) | HANG — same, exit 124, no output |
| 3 | `-scan-type connect -Pn` (uid 0) | OK in ~2 s: `{"ip":"127.0.0.1",...,"port":18080,"protocol":"tcp","tls":false}` |
| 4 | `-scan-type connect -Pn`, agent's literal top-100 flags WITHOUT `-Pn` (uid 0) | HANG — `timeout 45` killed it (exit 124) |
| 5 | `-scan-type syn -Pn` (uid 0, verbose) | Returns the port, but logs **"Running CONNECT scan with non root privileges"** — silent fallback to CONNECT, not a SYN scan |
| 6 | `-scan-type connect -Pn` as `nobody` | OK: port found, exit 0 |
| 7 | `-scan-type syn -Pn` as `nobody` (verbose) | Returns the port, but logs **"Running CONNECT scan with non root privileges"** — silent fallback again |

## Conclusions

1. **Host discovery hangs in sandboxed environments.** Without `-Pn`,
   naabu's host discovery never completes here (runs 1, 2, 4) — the
   stage would hit the agent timeout and fail. The agent therefore
   passes `-Pn` (skip host discovery). This is safe: hosts reaching
   `port_scan` are already-known-live from earlier pipeline stages, so
   discovery adds nothing. This is a deviation from the plan's literal
   flag list, made on evidence — see agent.go.
2. **SYN silently becomes CONNECT without privileges.** Requesting
   `-scan-type syn` unprivileged does NOT error — naabu logs the
   fallback and runs a connect scan. On Render Free (unprivileged), a
   SYN request would silently be a CONNECT scan anyway. The agent's
   explicit `-scan-type connect` default states what actually happens.
3. **A true SYN scan could not be demonstrated in this VM at all** —
   even uid 0 lacks the capability here ("non root privileges" per
   naabu). Whether SYN works on Render Free is therefore unproven and
   irrelevant: the agent never requests it.
4. **naabu rejects the VM's sink DNS answers.** `naabu -host
   potatomuzik.me ...` fails fast: `Could not run enumeration: no valid
   ipv4 or ipv6 targets were found` — the cell resolver answers
   198.18.166.126, which naabu itself rejects as non-public. A real
   naabu-vs-domain capture needs real DNS (Render worker).

## Flag corrections found while verifying (naabu v2.7.0 `-h`)

- `-timeout` is a **duration** (`"120s"`); a bare number is
  **milliseconds** (`-timeout 120` = 120 ms — finds nothing).
- `-top-ports` takes a **string**: `100` / `1000` / `full`. Full range
  is `-top-ports full`, not `-p -`.
- `-scan-type` accepts `connect` and `syn` (default `"c"`).
- Real JSON output has **no `"host"` field**: `{"ip","timestamp",
  "port","protocol","tls"}`. The parser falls back to the IP as host.
