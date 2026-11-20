// Package agent implements the scanner-agent CLI contract (the contract the
// Python runner in workstream B uses — do not change it without coordinating
// with workstream B):
//
// Input: ONE JSON object on stdin:
//
//	{"stage": "dns_enum"|"subdomain_enum"|"port_scan"|"http_probe"|"crawl",
//	 "domain": string,
//	 "hosts": [string] (optional, for port_scan/http_probe/crawl),
//	 "timeout_seconds": int (default 120),
//	 "rate_limit": int (default 5),
//	 "max_ports": string (default "top-100"),
//	 "wordlist": string (optional)}
//
// Output: structured JSONL on stdout, one object per line:
//
//	{"type":"result","stage":...,"data":{...}}  — stage results
//	{"type":"log","level":"info","message":...} — progress
//	{"type":"error","message":...}              — failures (never echoes secrets)
//
// Exit 0 on success (even if a stage finds nothing); non-zero only on stage
// failure (bad input, SSRF refusal, tool missing, timeout). Nothing else is
// ever printed to stdout; tool stderr goes to our stderr, not stdout.
//
// Safety: the SSRF blocklist (internal/ssrf) is enforced on the domain and
// every host BEFORE any exec. Flags are curated per stage — no shell, no
// user-controlled flags.
//
// Politeness (honest bound, review fix M5): this agent enforces 5 req/s
// and 2 concurrent runs PER AGENT PROCESS (the per-tool rate flags and
// the runner semaphore). That is NOT a per-target bound: with N worker
// processes probing the same target, the per-target rate multiplies by N.
// The per-target rate is therefore only bounded by deployment (one
// worker per scan in the Week 2 design), not by this code.
//
// Timeout ordering (review fix B1): the agent's own timeout
// (timeout_seconds, applied as the context deadline in Run) fires FIRST
// and group-kills the tool and any children it spawned (runner.Run /
// RunInDir); the Python runner's longer timeout (timeout + 30s grace)
// is only a backstop for a wedged agent process. The dns_enum HTTP fetch
// is bound by the same context (NewRequestWithContext), so it too dies
// with the stage — there is no tool or fetch path outside the timeout.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"websurfacehq/scanner-agent/internal/dnsenum"
	"websurfacehq/scanner-agent/internal/parsers"
	"websurfacehq/scanner-agent/internal/runner"
	"websurfacehq/scanner-agent/internal/ssrf"
)

// Stages.
const (
	StageDNSEnum       = "dns_enum"
	StageSubdomainEnum = "subdomain_enum"
	StagePortScan      = "port_scan"
	StageHTTPProbe     = "http_probe"
	StageCrawl         = "crawl"
)

// Input is one stage request read from stdin.
type Input struct {
	Stage          string   `json:"stage"`
	Domain         string   `json:"domain"`
	Hosts          []string `json:"hosts"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	RateLimit      int      `json:"rate_limit"`
	MaxPorts       string   `json:"max_ports"`
	Wordlist       string   `json:"wordlist"`
}

// Defaults and limits.
const (
	DefaultTimeoutSeconds = 120
	MaxTimeoutSeconds     = 1800
	DefaultRateLimit      = 5
	MaxRateLimit          = 5 // politeness cap per agent process (see package comment: NOT a per-target bound)
	DefaultMaxPorts       = "top-100"
)

// emitter writes one JSON object per line to stdout.
type emitter struct {
	w   io.Writer
	enc *json.Encoder
}

func newEmitter(w io.Writer) *emitter {
	return &emitter{w: w, enc: json.NewEncoder(w)}
}

func (e *emitter) log(msg string) {
	_ = e.enc.Encode(map[string]any{"type": "log", "level": "info", "message": msg})
}

func (e *emitter) result(stage string, data any) {
	_ = e.enc.Encode(map[string]any{"type": "result", "stage": stage, "data": data})
}

func (e *emitter) error(msg string) {
	_ = e.enc.Encode(map[string]any{"type": "error", "message": msg})
}

// Agent runs one stage. Runner is injected so tests can use a fake tool
// runner; HTTPClient is injected so dns_enum tests can avoid the network;
// Resolver is injected so SSRF tests can avoid real DNS. New() wires the
// real implementations.
type Agent struct {
	Runner     runner.Runner
	HTTPClient dnsenum.HTTPClient
	Resolver   ssrf.Resolver
}

// New builds an Agent with the real exec runner.
func New() *Agent {
	return &Agent{Runner: runner.ExecRunner{}, Resolver: ssrf.DefaultResolver}
}

// normalize validates the input, applies defaults, and returns the
// effective timeout, rate limit and host list.
func normalize(in Input) (Input, error) {
	out := in
	switch out.Stage {
	case StageDNSEnum, StageSubdomainEnum, StagePortScan, StageHTTPProbe, StageCrawl:
	default:
		return out, fmt.Errorf("unknown stage: %q", in.Stage)
	}
	out.Domain = strings.ToLower(strings.TrimSpace(ssrf.StripScheme(in.Domain)))
	if out.Domain == "" {
		return out, fmt.Errorf("domain is required")
	}
	if err := ssrf.ValidateHostname(out.Domain); err != nil {
		return out, fmt.Errorf("invalid domain: %w", err)
	}
	if out.TimeoutSeconds == 0 {
		out.TimeoutSeconds = DefaultTimeoutSeconds
	}
	if out.TimeoutSeconds < 1 || out.TimeoutSeconds > MaxTimeoutSeconds {
		return out, fmt.Errorf("timeout_seconds must be 1..%d", MaxTimeoutSeconds)
	}
	if out.RateLimit == 0 {
		out.RateLimit = DefaultRateLimit
	}
	if out.RateLimit < 1 {
		return out, fmt.Errorf("rate_limit must be >= 1")
	}
	if out.RateLimit > MaxRateLimit {
		out.RateLimit = MaxRateLimit // clamped to the politeness cap
	}
	if out.MaxPorts == "" {
		out.MaxPorts = DefaultMaxPorts
	}
	// Hosts default to the domain itself.
	hosts := []string{}
	for _, h := range in.Hosts {
		h = strings.ToLower(strings.TrimSpace(ssrf.StripScheme(h)))
		if h == "" {
			continue
		}
		if err := ssrf.ValidateHostname(h); err != nil {
			return out, fmt.Errorf("invalid host %q: %w", h, err)
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		hosts = []string{out.Domain}
	}
	out.Hosts = hosts
	return out, nil
}

// checkHosts SSRF-checks the domain and every host before any exec.
func (a *Agent) checkHosts(ctx context.Context, in Input) error {
	r := a.Resolver
	if r == nil {
		r = ssrf.DefaultResolver
	}
	if err := ssrf.CheckHost(ctx, r, in.Domain); err != nil {
		return fmt.Errorf("SSRF refusal for domain %s: %w", in.Domain, err)
	}
	for _, h := range in.Hosts {
		if h == in.Domain {
			continue
		}
		if err := ssrf.CheckHost(ctx, r, h); err != nil {
			return fmt.Errorf("SSRF refusal for host %s: %w", h, err)
		}
	}
	return nil
}

// Run executes one stage and returns the process exit code (0 success,
// 1 stage failure). It never panics on tool output.
func (a *Agent) Run(ctx context.Context, in Input, out io.Writer) int {
	e := newEmitter(out)
	norm, err := normalize(in)
	if err != nil {
		e.error(err.Error())
		return 1
	}
	if norm.RateLimit != in.RateLimit && in.RateLimit != 0 {
		e.log(fmt.Sprintf("rate_limit clamped to %d req/s (politeness cap)", MaxRateLimit))
	}
	if norm.Wordlist != "" {
		e.log(fmt.Sprintf("wordlist %q is not used by stage %s; ignored", norm.Wordlist, norm.Stage))
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(norm.TimeoutSeconds)*time.Second)
	defer cancel()

	e.log(fmt.Sprintf("stage %s starting for domain %s (timeout %ds, rate %d/s)",
		norm.Stage, norm.Domain, norm.TimeoutSeconds, norm.RateLimit))

	if err := a.checkHosts(ctx, norm); err != nil {
		e.error(err.Error())
		return 1
	}

	switch norm.Stage {
	case StageDNSEnum:
		return a.runDNSEnum(ctx, norm, e)
	case StageSubdomainEnum:
		return a.runSubfinder(ctx, norm, e)
	case StagePortScan:
		return a.runNaabu(ctx, norm, e)
	case StageHTTPProbe:
		return a.runHttpx(ctx, norm, e)
	case StageCrawl:
		return a.runKatana(ctx, norm, e)
	}
	e.error(fmt.Sprintf("unknown stage: %q", norm.Stage))
	return 1
}

// requireTool fails the stage with a clear error when a binary is absent.
func (a *Agent) requireTool(e *emitter, name string) bool {
	if _, err := a.Runner.LookPath(name); err != nil {
		e.error(fmt.Sprintf("tool missing: %s is not installed on PATH", name))
		return false
	}
	return true
}

// runTool runs one curated tool invocation and returns its stdout, or
// fails the stage. Tool stderr is summarized in the error (truncated) —
// it goes to our stderr only via the caller, never to stdout.
func (a *Agent) runTool(ctx context.Context, e *emitter, name string, args []string, stdin []byte) ([]byte, bool) {
	res, err := a.Runner.Run(ctx, name, args, stdin)
	if err != nil {
		e.error(fmt.Sprintf("%s failed: %v", name, err))
		return nil, false
	}
	if len(res.Stderr) > 0 {
		e.log(fmt.Sprintf("%s stderr: %s", name, truncateString(string(res.Stderr), 300)))
	}
	return res.Stdout, true
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(s[:n]) + "…"
}

// ---- dns_enum ----

func (a *Agent) runDNSEnum(ctx context.Context, in Input, e *emitter) int {
	res, err := dnsenum.Run(ctx, a.HTTPClient, a.Resolver, in.Domain)
	if err != nil {
		e.error(fmt.Sprintf("dns_enum failed: %v", err))
		return 1
	}
	e.log(fmt.Sprintf("dns_enum found %d subdomains for %s", res.Count, in.Domain))
	e.result(StageDNSEnum, res)
	return 0
}

// ---- subdomain_enum (subfinder) ----
//
// Flags (curated): subfinder -d <domain> -silent -json -timeout <t> -rate-limit 5
// -timeout is seconds (integer). -silent keeps stdout pure JSONL.
func (a *Agent) runSubfinder(ctx context.Context, in Input, e *emitter) int {
	if !a.requireTool(e, "subfinder") {
		return 1
	}
	args := []string{
		"-d", in.Domain,
		"-silent", "-json",
		"-timeout", strconv.Itoa(in.TimeoutSeconds),
		"-rate-limit", strconv.Itoa(in.RateLimit),
	}
	stdout, ok := a.runTool(ctx, e, "subfinder", args, nil)
	if !ok {
		return 1
	}
	subs, skipped, err := parsers.ParseSubfinder(stdout)
	if err != nil {
		e.error(fmt.Sprintf("subfinder output unparsable: %v", err))
		return 1
	}
	if skipped > 0 {
		e.log(fmt.Sprintf("subfinder: skipped %d malformed output line(s)", skipped))
	}
	hosts := make([]string, 0, len(subs))
	for _, s := range subs {
		hosts = append(hosts, s.Host)
	}
	e.log(fmt.Sprintf("subdomain_enum found %d subdomains for %s", len(hosts), in.Domain))
	e.result(StageSubdomainEnum, map[string]any{
		"domain": in.Domain, "subdomains": hosts, "count": len(hosts),
	})
	return 0
}

// ---- port_scan (naabu) ----
//
// Flags (curated): naabu -host <hosts> -top-ports 100 -scan-type connect
// -Pn -silent -json -rate 5 -timeout <t>s
// CONNECT scan is the default: SYN needs raw sockets (root / CAP_NET_RAW),
// which Render Free does not grant. See docs/naabu-scan-modes.md.
// Flag corrections vs the Week 2 plan's shorthand (verified against
// naabu v2.7.0 -h, 16 Nov 2026):
//   - -timeout is a DURATION ("120s"), not bare seconds — a bare number
//     is milliseconds, so -timeout 120 would mean 120ms and find nothing.
//   - -top-ports takes "100"/"1000"/"full" (a string); full range is
//     "-top-ports full", not "-p -".
//   - -Pn (skip host discovery) is REQUIRED: without it naabu's host
//     discovery hangs in sandboxed environments (this VM: both runs hit
//     the 60s timeout with no output). Hosts reaching port_scan are
//     already-known-live from earlier stages, so discovery adds nothing.
func (a *Agent) runNaabu(ctx context.Context, in Input, e *emitter) int {
	if !a.requireTool(e, "naabu") {
		return 1
	}
	topPorts, err := parseMaxPorts(in.MaxPorts)
	if err != nil {
		e.error(err.Error())
		return 1
	}
	args := []string{
		"-host", strings.Join(in.Hosts, ","),
		"-top-ports", topPorts,
		"-scan-type", "connect",
		"-Pn",
		"-silent", "-json",
		"-rate", strconv.Itoa(in.RateLimit),
		"-timeout", fmt.Sprintf("%ds", in.TimeoutSeconds),
	}
	stdout, ok := a.runTool(ctx, e, "naabu", args, nil)
	if !ok {
		return 1
	}
	ports, skipped, err := parsers.ParseNaabu(stdout)
	if err != nil {
		e.error(fmt.Sprintf("naabu output unparsable: %v", err))
		return 1
	}
	if skipped > 0 {
		e.log(fmt.Sprintf("naabu: skipped %d malformed output line(s)", skipped))
	}
	e.log(fmt.Sprintf("port_scan found %d open port(s) on %s", len(ports), strings.Join(in.Hosts, ",")))
	// One result per host (the Python runner's extractor reads per-host
	// {"host", "open_ports"} records), plus a stage summary line.
	byHost := map[string][]parsers.OpenPort{}
	for _, p := range ports {
		byHost[p.Host] = append(byHost[p.Host], p)
	}
	for _, h := range in.Hosts {
		hostPorts := byHost[h]
		if hostPorts == nil {
			hostPorts = []parsers.OpenPort{}
		}
		e.result(StagePortScan, map[string]any{
			"host": h, "open_ports": hostPorts, "count": len(hostPorts),
		})
	}
	e.result(StagePortScan, map[string]any{
		"hosts": in.Hosts, "open_ports": ports, "count": len(ports),
	})
	return 0
}

// parseMaxPorts maps the max_ports contract value to naabu's -top-ports
// string ("100" / "1000" / "full").
func parseMaxPorts(v string) (string, error) {
	switch v {
	case "top-100":
		return "100", nil
	case "top-1000":
		return "1000", nil
	case "all":
		return "full", nil
	default:
		return "", fmt.Errorf("unsupported max_ports: %q (want top-100, top-1000 or all)", v)
	}
}

// ---- http_probe (httpx) ----
//
// Flags (curated): httpx -json -silent -status-code -title -tech-detect
// -tls-probe -ip -timeout <t> -rate-limit 5 -threads 2, targets on stdin.
// Screenshots: attempted as a SEPARATE best-effort pass (see
// attemptScreenshots) so a missing headless renderer can never lose the
// probe results. The agent NEVER stores or returns screenshot images:
// "screenshot_unavailable" is therefore always true (reason
// "screenshot_not_persisted") and "renderer_available" separately records
// whether the -screenshot pass ran clean — a renderer probe, not a
// promise of an image.
func (a *Agent) runHttpx(ctx context.Context, in Input, e *emitter) int {
	if !a.requireTool(e, "httpx") {
		return 1
	}
	targets := make([]string, 0, len(in.Hosts))
	for _, h := range in.Hosts {
		targets = append(targets, "https://"+h)
	}
	stdin := []byte(strings.Join(targets, "\n") + "\n")
	args := []string{
		"-json", "-silent",
		"-status-code", "-title", "-tech-detect", "-tls-probe", "-ip",
		"-timeout", strconv.Itoa(in.TimeoutSeconds),
		"-rate-limit", strconv.Itoa(in.RateLimit),
		"-threads", "2",
	}
	stdout, ok := a.runTool(ctx, e, "httpx", args, stdin)
	if !ok {
		return 1
	}
	results, skipped, err := parsers.ParseHttpx(stdout)
	if err != nil {
		e.error(fmt.Sprintf("httpx output unparsable: %v", err))
		return 1
	}
	if skipped > 0 {
		e.log(fmt.Sprintf("httpx: skipped %d malformed output line(s)", skipped))
	}
	screenshotAvailable, rendererAvailable, shotErr := a.attemptScreenshots(ctx, e, in, stdin)
	if shotErr != nil {
		e.log(fmt.Sprintf("screenshot pass error: %v", shotErr))
	}
	// "screenshot_unavailable" is always true in this design: the agent
	// never persists a screenshot, so no image is ever available to a
	// caller — regardless of whether the renderer ran. See
	// attemptScreenshots.
	screenshotUnavailable := !screenshotAvailable
	e.log(fmt.Sprintf("http_probe found %d live host(s) for %s", len(results), in.Domain))
	// One result per probed host (the Python runner's extractor reads
	// per-host records: host/url/status/title/ip/tls/headers), plus a
	// stage summary line. "status" duplicates "status_code" because the
	// runner reads "status". "webserver" and "content_type" are passed
	// through from httpx (the runner reads them for tech fingerprinting).
	for _, r := range results {
		e.result(StageHTTPProbe, map[string]any{
			"host": r.Host, "url": r.URL,
			"status": r.StatusCode, "status_code": r.StatusCode,
			"title": r.Title, "technologies": r.Technologies,
			"ip": r.IP, "tls": r.TLS, "headers": map[string]any{},
			"webserver": r.Webserver, "content_type": r.ContentType,
			"screenshot_unavailable": screenshotUnavailable,
			"renderer_available":     rendererAvailable,
			"screenshot_reason":      "screenshot_not_persisted",
		})
	}
	e.result(StageHTTPProbe, map[string]any{
		"hosts": in.Hosts, "results": results, "count": len(results),
		"screenshot_unavailable": screenshotUnavailable,
		"renderer_available":     rendererAvailable,
		"screenshot_reason":      "screenshot_not_persisted",
	})
	return 0
}

// attemptScreenshots runs httpx -screenshot as a best-effort second pass
// with a short timeout, in a per-run temp dir that is deleted on every
// exit path (deferred os.RemoveAll — including error and timeout).
//
// It returns (available, rendererAvailable, err):
//   - available is true only if a screenshot file exists in a location
//     the caller persists. This agent never stores or returns images, so
//     available is ALWAYS false here; callers must report
//     screenshot_unavailable=true with reason "screenshot_not_persisted".
//     The old semantics (available=false only when the renderer failed)
//     misstated availability and are corrected by this change.
//   - rendererAvailable records whether the -screenshot pass itself ran
//     without a renderer error — a probe of renderer health, kept
//     separate from availability so a working renderer is never read as
//     "a screenshot exists".
//   - err is non-nil only when the temp dir could not be created; a
//     failed or timed-out screenshot pass is NOT an error (it just means
//     rendererAvailable=false) and never fails the stage.
//
// The pass runs under a child context of the stage timeout, through the
// runner, so a stage timeout group-kills httpx and any Chromium it
// spawned — same as every other tool path.
func (a *Agent) attemptScreenshots(ctx context.Context, e *emitter, in Input, stdin []byte) (available bool, rendererAvailable bool, err error) {
	shotDir, err := os.MkdirTemp("", "websurfacehq-screenshots-*")
	if err != nil {
		return false, false, fmt.Errorf("screenshot temp dir: %w", err)
	}
	defer os.RemoveAll(shotDir) // delete even on error/timeout
	shotTimeout := in.TimeoutSeconds / 4
	if shotTimeout < 10 {
		shotTimeout = 10
	}
	if shotTimeout > 30 {
		shotTimeout = 30
	}
	shotCtx, cancel := context.WithTimeout(ctx, time.Duration(shotTimeout)*time.Second)
	defer cancel()
	// -esb excludes screenshot bytes from the JSON output: the agent
	// never stores images, so the bytes would only bloat stdout (and
	// risk tripping the runner's 32 MiB output cap on media-heavy pages).
	args := []string{
		"-json", "-silent", "-screenshot", "-esb",
		"-timeout", strconv.Itoa(shotTimeout),
		"-rate-limit", strconv.Itoa(in.RateLimit),
		"-threads", "2",
	}
	res, err := a.Runner.RunInDir(shotCtx, "httpx", args, stdin, shotDir)
	if err != nil {
		e.log(fmt.Sprintf("httpx -screenshot unavailable (%v); recording screenshot_unavailable=true", err))
		return false, false, nil
	}
	stderr := strings.ToLower(string(res.Stderr))
	if strings.Contains(stderr, "screenshot") &&
		(strings.Contains(stderr, "browser") || strings.Contains(stderr, "chromium") ||
			strings.Contains(stderr, "rod") || strings.Contains(stderr, "failed") ||
			strings.Contains(stderr, "error")) {
		e.log("httpx -screenshot reported a renderer error; recording screenshot_unavailable=true")
		return false, false, nil
	}
	// The pass ran clean, so the renderer is available — but any
	// screenshot files httpx wrote went into shotDir, which is deleted
	// by the deferred RemoveAll above. Nothing is persisted, so
	// available stays false: no image exists for any caller to read.
	e.log("httpx -screenshot pass ran; renderer available, but screenshots are not stored by the agent (screenshot_not_persisted)")
	return false, true, nil
}

// ---- crawl (katana) ----
//
// Flags (curated): katana -u <hosts> -jsonl -silent -depth 3 -rate-limit 5
// -timeout <t> -js-crawl
func (a *Agent) runKatana(ctx context.Context, in Input, e *emitter) int {
	if !a.requireTool(e, "katana") {
		return 1
	}
	targets := make([]string, 0, len(in.Hosts))
	for _, h := range in.Hosts {
		targets = append(targets, "https://"+h)
	}
	args := []string{
		"-u", strings.Join(targets, ","),
		"-jsonl", "-silent",
		"-depth", "3",
		"-rate-limit", strconv.Itoa(in.RateLimit),
		"-timeout", strconv.Itoa(in.TimeoutSeconds),
		"-js-crawl",
	}
	stdout, ok := a.runTool(ctx, e, "katana", args, nil)
	if !ok {
		return 1
	}
	urls, skipped, err := parsers.ParseKatana(stdout)
	if err != nil {
		e.error(fmt.Sprintf("katana output unparsable: %v", err))
		return 1
	}
	if skipped > 0 {
		e.log(fmt.Sprintf("katana: skipped %d malformed output line(s)", skipped))
	}
	jsFiles := parsers.JSFiles(urls)
	e.log(fmt.Sprintf("crawl found %d URL(s) (%d JS file(s)) for %s", len(urls), len(jsFiles), in.Domain))
	// "urls" is a plain string list: the Python runner's extractor reads
	// string URLs from it (a list of objects would be dropped). Full
	// per-URL detail stays available under "crawled".
	urlStrings := make([]string, 0, len(urls))
	for _, u := range urls {
		urlStrings = append(urlStrings, u.URL)
	}
	e.result(StageCrawl, map[string]any{
		"hosts": in.Hosts, "urls": urlStrings, "crawled": urls, "js_files": jsFiles,
		"count": len(urls), "js_count": len(jsFiles),
	})
	return 0
}
