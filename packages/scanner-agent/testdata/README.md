# testdata — parser fixtures

**All fixtures in this directory are SYNTHETIC** (hand-written 16 Nov 2026 to
match each tool's documented real JSON schema — `example.com` only, no real
scan data, no real secrets). The background `go install` of the real
ProjectDiscovery binaries was still in progress when they were written.

A `//` header comment was deliberately NOT put inside the fixture files:
a comment line in a JSONL file would be counted as a skipped line, and in
`crtsh.json` it would break the whole-document parse. The SYNTHETIC label
lives here instead, plus in `parsers_test.go`.

When the real binaries are available, capture each tool once against
`potatomuzik.me` only (recon stages, 5 req/s), save the raw output here as
`*.real.jsonl`, and update the tests to parse the real fixtures. Do not
edit a fixture to make a test pass.

Captured so far (16 Nov 2026):
- `subfinder.real.jsonl` — subfinder v2.17.0, potatomuzik.me, 04:24 UTC:
  EMPTY (0 subdomains in ~12 ms; no provider keys configured here).
- `httpx.real.jsonl` — httpx, potatomuzik.me, 04:29 UTC: 2 lines
  (200 PotatoMuzik + 301 www redirect). This capture corrected the
  parser: real httpx puts IPs in `"a"`, not `"ip"`, and the TLS version
  field is `"tls_version"`.
- `naabu.real.jsonl` — naabu v2.7.0, 127.0.0.1:18080 CONNECT scan,
  04:42 UTC: 1 line (`{"ip","timestamp","port","protocol","tls"}` — no
  `"host"` field). naabu could NOT scan potatomuzik.me from this VM:
  it resolves via the cell's sink DNS to 198.18.166.126, which naabu
  itself rejects ("no valid ipv4 or ipv6 targets were found"). Real
  naabu-vs-domain capture needs real DNS (Render worker).
- `katana.real.jsonl` — katana, potatomuzik.me, 04:39 UTC: 1 ERROR line
  (TLS handshake failure — katana cannot fetch the site from this VM).
  The parser skips error lines; the fixture proves it.
