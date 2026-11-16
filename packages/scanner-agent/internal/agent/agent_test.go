package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websurfacehq/scanner-agent/internal/runner"
)

// fakeResolver always resolves to a public IP.
type fakeResolver struct{}

func (fakeResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

// fakeRunner returns canned tool output and records invocations.
type fakeRunner struct {
	outputs map[string][]byte // tool name -> stdout
	calls   []call
	lookErr error
}

type call struct {
	name  string
	args  []string
	stdin []byte
	dir   string // non-empty when the call ran via RunInDir (temp dir)
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, stdin []byte) (*runner.Result, error) {
	f.calls = append(f.calls, call{name, args, stdin, ""})
	out, ok := f.outputs[name]
	if !ok {
		return nil, fmt.Errorf("fake tool %s has no canned output", name)
	}
	return &runner.Result{Stdout: out, Stderr: nil, ExitCode: 0}, nil
}

// RunInDir records the dir (the screenshot pass must run in a temp dir,
// never the shared worker cwd) and otherwise behaves like Run.
func (f *fakeRunner) RunInDir(_ context.Context, name string, args []string, stdin []byte, dir string) (*runner.Result, error) {
	f.calls = append(f.calls, call{name, args, stdin, dir})
	out, ok := f.outputs[name]
	if !ok {
		return nil, fmt.Errorf("fake tool %s has no canned output", name)
	}
	return &runner.Result{Stdout: out, Stderr: nil, ExitCode: 0}, nil
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if f.lookErr != nil {
		return "", f.lookErr
	}
	if _, ok := f.outputs[name]; !ok {
		return "", fmt.Errorf("not found: %s", name)
	}
	return "/fake/bin/" + name, nil
}

// fakeHTTPClient returns a canned crt.sh body.
type fakeHTTPClient struct {
	body   string
	status int
}

func (f *fakeHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func runStage(t *testing.T, r *fakeRunner, in Input) (int, []map[string]any) {
	t.Helper()
	ag := &Agent{Runner: r, Resolver: fakeResolver{}}
	var buf bytes.Buffer
	code := ag.Run(context.Background(), in, &buf)
	lines := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("output line is not JSON: %q: %v", line, err)
		}
		lines = append(lines, obj)
	}
	return code, lines
}

func findResult(t *testing.T, lines []map[string]any) map[string]any {
	t.Helper()
	for _, l := range lines {
		if l["type"] == "result" {
			return l
		}
	}
	t.Fatal("no result line in output")
	return nil
}

func TestSubdomainEnum_FakeTool(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"subfinder": readFixture(t, "subfinder.jsonl")}}
	code, lines := runStage(t, r, Input{Stage: StageSubdomainEnum, Domain: "example.com"})
	if code != 0 {
		t.Fatalf("exit code %d, lines: %v", code, lines)
	}
	res := findResult(t, lines)
	data := res["data"].(map[string]any)
	if int(data["count"].(float64)) != 4 {
		t.Errorf("count = %v, want 4", data["count"])
	}
	// The curated flag set must contain exactly the safe flags — no shell,
	// no user-controlled flags — and the domain as a separate arg.
	if len(r.calls) != 1 || r.calls[0].name != "subfinder" {
		t.Fatalf("calls = %+v", r.calls)
	}
	args := r.calls[0].args
	for _, want := range []string{"-d", "example.com", "-silent", "-json", "-rate-limit", "5"} {
		found := false
		for _, a := range args {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("subfinder args %v missing %q", args, want)
		}
	}
}

func TestPortScan_FakeTool(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"naabu": readFixture(t, "naabu.jsonl")}}
	code, lines := runStage(t, r, Input{Stage: StagePortScan, Domain: "example.com", Hosts: []string{"example.com"}})
	if code != 0 {
		t.Fatalf("exit code %d, lines: %v", code, lines)
	}
	// One per-host result + one stage summary. The per-host record is
	// what the Python runner's extractor reads.
	var perHost, summary map[string]any
	nResults := 0
	for _, l := range lines {
		if l["type"] != "result" {
			continue
		}
		nResults++
		data := l["data"].(map[string]any)
		if _, ok := data["host"]; ok {
			perHost = data
		} else {
			summary = data
		}
	}
	if nResults != 2 {
		t.Fatalf("result lines = %d, want 2 (per-host + summary)", nResults)
	}
	if perHost["host"] != "example.com" || int(perHost["count"].(float64)) != 2 {
		t.Errorf("per-host result = %v", perHost)
	}
	if int(summary["count"].(float64)) != 2 {
		t.Errorf("summary count = %v, want 2", summary["count"])
	}
	args := r.calls[0].args
	for _, want := range []string{"-scan-type", "connect", "-top-ports", "100", "-rate", "5", "-Pn", "-timeout", "120s"} {
		found := false
		for _, a := range args {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("naabu args %v missing %q (connect scan must be the default)", args, want)
		}
	}
	for _, a := range args {
		if a == "syn" {
			t.Errorf("naabu args must never request a SYN scan: %v", args)
		}
	}
}

func TestPortScan_MaxPortsAll(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"naabu": readFixture(t, "naabu.jsonl")}}
	code, _ := runStage(t, r, Input{Stage: StagePortScan, Domain: "example.com", MaxPorts: "all"})
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	args := r.calls[0].args
	hasFull := false
	for i, a := range args {
		if a == "-top-ports" && i+1 < len(args) && args[i+1] == "full" {
			hasFull = true
		}
		if a == "-p" {
			t.Errorf("max_ports=all must not use -p (naabu full range is -top-ports full): %v", args)
		}
	}
	if !hasFull {
		t.Errorf("max_ports=all must pass -top-ports full, got %v", args)
	}
}

func TestPortScan_BadMaxPorts(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"naabu": readFixture(t, "naabu.jsonl")}}
	code, lines := runStage(t, r, Input{Stage: StagePortScan, Domain: "example.com", MaxPorts: "top-999"})
	if code == 0 {
		t.Fatalf("bad max_ports must fail, lines: %v", lines)
	}
}

func TestHTTPProbe_FakeTool(t *testing.T) {
	// httpx is invoked twice: the probe pass and the best-effort
	// -screenshot pass. Both return the canned output here.
	r := &fakeRunner{outputs: map[string][]byte{"httpx": readFixture(t, "httpx.jsonl")}}
	code, lines := runStage(t, r, Input{Stage: StageHTTPProbe, Domain: "example.com"})
	if code != 0 {
		t.Fatalf("exit code %d, lines: %v", code, lines)
	}
	// 3 per-host results (one per probed URL) + 1 stage summary.
	var perHost []map[string]any
	var summary map[string]any
	for _, l := range lines {
		if l["type"] != "result" {
			continue
		}
		data := l["data"].(map[string]any)
		if _, ok := data["host"]; ok {
			perHost = append(perHost, data)
		} else {
			summary = data
		}
	}
	if len(perHost) != 3 {
		t.Fatalf("per-host results = %d, want 3", len(perHost))
	}
	if summary == nil || int(summary["count"].(float64)) != 3 {
		t.Fatalf("summary = %v, want count 3", summary)
	}
	// Semantics (review fix M1): the agent never stores a screenshot, so
	// screenshot_unavailable is ALWAYS true — even when the screenshot
	// pass runs clean. renderer_available separately records that the
	// pass ran (the renderer works); screenshot_reason names why no
	// image is available.
	if summary["screenshot_unavailable"] != true {
		t.Errorf("screenshot_unavailable = %v, want true (screenshots are never persisted)", summary["screenshot_unavailable"])
	}
	if summary["renderer_available"] != true {
		t.Errorf("renderer_available = %v, want true when the screenshot pass runs clean", summary["renderer_available"])
	}
	if summary["screenshot_reason"] != "screenshot_not_persisted" {
		t.Errorf("screenshot_reason = %v, want screenshot_not_persisted", summary["screenshot_reason"])
	}
	if perHost[0]["screenshot_unavailable"] != true || perHost[0]["renderer_available"] != true {
		t.Errorf("per-host screenshot markers wrong: %v", perHost[0])
	}
	// The Python runner reads "status" (not "status_code") per host.
	if int(perHost[0]["status"].(float64)) != 200 || perHost[0]["title"] != "Example Domain" {
		t.Errorf("first per-host result wrong: %v", perHost[0])
	}
	if perHost[0]["ip"] != "93.184.216.34" {
		t.Errorf("first per-host IP = %v, want the \"a\" array value", perHost[0]["ip"])
	}
	if len(r.calls) != 2 {
		t.Fatalf("expected 2 httpx calls (probe + screenshot), got %d", len(r.calls))
	}
	// The probe pass must NOT carry -screenshot (screenshots are a
	// separate best-effort pass); the second call must.
	for _, a := range r.calls[0].args {
		if a == "-screenshot" {
			t.Error("probe pass must not include -screenshot")
		}
	}
	hasShot := false
	for _, a := range r.calls[1].args {
		if a == "-screenshot" {
			hasShot = true
		}
	}
	if !hasShot {
		t.Error("second httpx call must be the -screenshot pass")
	}
	// The screenshot pass must run in a temp dir (dir != ""), never the
	// shared worker cwd; the probe pass runs in the cwd (dir == "").
	if r.calls[0].dir != "" {
		t.Errorf("probe pass must run in the worker cwd, got dir %q", r.calls[0].dir)
	}
	if r.calls[1].dir == "" {
		t.Error("screenshot pass must run in a temp dir, got empty dir")
	}
	// Targets go on stdin, one https URL per line.
	if !strings.Contains(string(r.calls[0].stdin), "https://example.com\n") {
		t.Errorf("probe stdin wrong: %q", r.calls[0].stdin)
	}
}

func TestHTTPProbe_ScreenshotUnavailable(t *testing.T) {
	// The screenshot pass fails (no renderer) while the probe succeeds:
	// the stage must still succeed with screenshot_unavailable=true.
	shotFail := &screenshotFailRunner{probe: readFixture(t, "httpx.jsonl")}
	ag := &Agent{Runner: shotFail, Resolver: fakeResolver{}}
	var buf bytes.Buffer
	code := ag.Run(context.Background(), Input{Stage: StageHTTPProbe, Domain: "example.com"}, &buf)
	if code != 0 {
		t.Fatalf("exit code %d, output: %s", code, buf.String())
	}
	var res map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var obj map[string]any
		_ = json.Unmarshal([]byte(line), &obj)
		if obj["type"] == "result" {
			res = obj
		}
	}
	if res == nil {
		t.Fatal("no result line")
	}
	data := res["data"].(map[string]any)
	if data["screenshot_unavailable"] != true {
		t.Errorf("screenshot_unavailable = %v, want true", data["screenshot_unavailable"])
	}
	if data["renderer_available"] != false {
		t.Errorf("renderer_available = %v, want false when the screenshot pass fails", data["renderer_available"])
	}
	if int(data["count"].(float64)) != 3 {
		t.Errorf("probe results must survive a failed screenshot pass, count = %v", data["count"])
	}
}

// screenshotWriterRunner simulates a real httpx -screenshot pass: it
// writes a screenshot file into the dir it is given, like the real tool
// writes into the cwd. The test proves the agent deletes that dir.
type screenshotWriterRunner struct {
	probe []byte
	dir   string // dir the screenshot pass was given
}

func (f *screenshotWriterRunner) Run(_ context.Context, name string, args []string, _ []byte) (*runner.Result, error) {
	return &runner.Result{Stdout: f.probe, Stderr: nil, ExitCode: 0}, nil
}

func (f *screenshotWriterRunner) RunInDir(_ context.Context, name string, args []string, _ []byte, dir string) (*runner.Result, error) {
	f.dir = dir
	if err := os.WriteFile(filepath.Join(dir, "https_example.com.png"), []byte("fake png"), 0o644); err != nil {
		return nil, err
	}
	return &runner.Result{Stdout: f.probe, Stderr: nil, ExitCode: 0}, nil
}

func (f *screenshotWriterRunner) LookPath(name string) (string, error) {
	return "/fake/bin/" + name, nil
}

func TestHTTPProbe_ScreenshotTempDirCleanedUp(t *testing.T) {
	// The screenshot pass writes files; they must live in a per-run
	// temp dir that the agent deletes, and must never leak into the
	// shared worker cwd.
	probe := readFixture(t, "httpx.jsonl") // read BEFORE chdir: the
	// fixture path is relative to the package dir.
	workdir := t.TempDir()
	t.Chdir(workdir)
	r := &screenshotWriterRunner{probe: probe}
	ag := &Agent{Runner: r, Resolver: fakeResolver{}}
	var buf bytes.Buffer
	code := ag.Run(context.Background(), Input{Stage: StageHTTPProbe, Domain: "example.com"}, &buf)
	if code != 0 {
		t.Fatalf("exit code %d, output: %s", code, buf.String())
	}
	if r.dir == "" {
		t.Fatal("screenshot pass was not given a temp dir")
	}
	if _, err := os.Stat(r.dir); !os.IsNotExist(err) {
		t.Errorf("screenshot temp dir %q still exists after the run (must be removed)", r.dir)
	}
	matches, _ := filepath.Glob(filepath.Join(workdir, "*.png"))
	if len(matches) != 0 {
		t.Errorf("screenshot files leaked into the worker cwd: %v", matches)
	}
	var summary map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var obj map[string]any
		_ = json.Unmarshal([]byte(line), &obj)
		if obj["type"] == "result" {
			summary = obj["data"].(map[string]any)
		}
	}
	if summary["screenshot_unavailable"] != true {
		t.Errorf("screenshot_unavailable = %v, want true (never persisted)", summary["screenshot_unavailable"])
	}
	if summary["renderer_available"] != true {
		t.Errorf("renderer_available = %v, want true (the pass ran clean)", summary["renderer_available"])
	}
}

// screenshotFailRunner succeeds for the probe call and fails the
// -screenshot call, simulating a missing headless renderer.
type screenshotFailRunner struct {
	probe []byte
	calls int
}

func (f *screenshotFailRunner) Run(_ context.Context, name string, args []string, _ []byte) (*runner.Result, error) {
	f.calls++
	for _, a := range args {
		if a == "-screenshot" {
			return nil, fmt.Errorf("httpx: screenshot failed: browser not found")
		}
	}
	return &runner.Result{Stdout: f.probe, ExitCode: 0}, nil
}

func (f *screenshotFailRunner) RunInDir(ctx context.Context, name string, args []string, stdin []byte, _ string) (*runner.Result, error) {
	return f.Run(ctx, name, args, stdin)
}

func (f *screenshotFailRunner) LookPath(name string) (string, error) {
	return "/fake/bin/" + name, nil
}

func TestCrawl_FakeTool(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"katana": readFixture(t, "katana.jsonl")}}
	code, lines := runStage(t, r, Input{Stage: StageCrawl, Domain: "example.com"})
	if code != 0 {
		t.Fatalf("exit code %d, lines: %v", code, lines)
	}
	res := findResult(t, lines)
	data := res["data"].(map[string]any)
	if int(data["count"].(float64)) != 4 {
		t.Errorf("count = %v, want 4", data["count"])
	}
	if int(data["js_count"].(float64)) != 1 {
		t.Errorf("js_count = %v, want 1", data["js_count"])
	}
	// "urls" must be plain strings: the Python runner's extractor drops
	// non-string items, so a list of objects would lose every URL.
	urls, ok := data["urls"].([]any)
	if !ok || len(urls) != 4 {
		t.Fatalf("urls = %v, want 4 strings", data["urls"])
	}
	for _, u := range urls {
		if _, ok := u.(string); !ok {
			t.Errorf("urls entry %v is not a string", u)
		}
	}
	if _, ok := data["crawled"]; !ok {
		t.Error("crawled detail objects must be present under \"crawled\"")
	}
	args := r.calls[0].args
	for _, want := range []string{"-jsonl", "-depth", "3", "-js-crawl", "-rate-limit", "5"} {
		found := false
		for _, a := range args {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("katana args %v missing %q", args, want)
		}
	}
}

func TestDNSEnum_FakeHTTP(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{}}
	ag := &Agent{Runner: r, Resolver: fakeResolver{}, HTTPClient: &fakeHTTPClient{body: string(readFixture(t, "crtsh.json")), status: 200}}
	var buf bytes.Buffer
	code := ag.Run(context.Background(), Input{Stage: StageDNSEnum, Domain: "example.com"}, &buf)
	if code != 0 {
		t.Fatalf("exit code %d, output: %s", code, buf.String())
	}
	var res map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var obj map[string]any
		_ = json.Unmarshal([]byte(line), &obj)
		if obj["type"] == "result" {
			res = obj
		}
	}
	if res == nil {
		t.Fatal("no result line")
	}
	data := res["data"].(map[string]any)
	if int(data["count"].(float64)) != 3 {
		t.Errorf("count = %v, want 3", data["count"])
	}
}

func TestSSRFRefusal_BeforeExec(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"subfinder": readFixture(t, "subfinder.jsonl")}}
	// 127.0.0.1 resolves (fake resolver maps everything to public, so
	// use the hostname blocklist instead: localhost is refused before
	// any DNS lookup).
	code, lines := runStage(t, r, Input{Stage: StageSubdomainEnum, Domain: "localhost"})
	if code == 0 {
		t.Fatalf("localhost must be refused, lines: %v", lines)
	}
	if len(r.calls) != 0 {
		t.Errorf("no tool must run after an SSRF refusal, calls = %+v", r.calls)
	}
	foundErr := false
	for _, l := range lines {
		if l["type"] == "error" {
			foundErr = true
		}
		if l["type"] == "result" {
			t.Error("refused stage must not emit a result line")
		}
	}
	if !foundErr {
		t.Error("refused stage must emit an error line")
	}
}

func TestSSRFRefusal_PrivateIPLiteral(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"naabu": readFixture(t, "naabu.jsonl")}}
	code, _ := runStage(t, r, Input{Stage: StagePortScan, Domain: "192.168.1.1"})
	if code == 0 {
		t.Fatal("private IP literal must be refused")
	}
	if len(r.calls) != 0 {
		t.Error("no tool must run after an SSRF refusal")
	}
}

func TestUnknownStage(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{}}
	code, lines := runStage(t, r, Input{Stage: "nuclei", Domain: "example.com"})
	if code == 0 {
		t.Fatal("Week 3 stage nuclei must be rejected in Week 2")
	}
	foundErr := false
	for _, l := range lines {
		if l["type"] == "error" {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("unknown stage must emit an error line")
	}
}

func TestMissingDomain(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{}}
	code, _ := runStage(t, r, Input{Stage: StageSubdomainEnum, Domain: ""})
	if code == 0 {
		t.Fatal("missing domain must fail")
	}
	if len(r.calls) != 0 {
		t.Error("no tool must run with bad input")
	}
}

func TestMissingTool(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{}} // no subfinder output
	code, lines := runStage(t, r, Input{Stage: StageSubdomainEnum, Domain: "example.com"})
	if code == 0 {
		t.Fatalf("missing tool must fail, lines: %v", lines)
	}
}

func TestRateLimitClamped(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"subfinder": readFixture(t, "subfinder.jsonl")}}
	code, _ := runStage(t, r, Input{Stage: StageSubdomainEnum, Domain: "example.com", RateLimit: 50})
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	for _, a := range r.calls[0].args {
		if a == "50" {
			t.Error("rate_limit 50 must be clamped to the 5 req/s cap")
		}
	}
}

func TestOutputIsPureJSONL(t *testing.T) {
	// Every stdout line must be a JSON object with a "type" field — the
	// Python runner parses line-by-line and anything else breaks it.
	r := &fakeRunner{outputs: map[string][]byte{"subfinder": readFixture(t, "subfinder.jsonl")}}
	ag := &Agent{Runner: r, Resolver: fakeResolver{}}
	var buf bytes.Buffer
	code := ag.Run(context.Background(), Input{Stage: StageSubdomainEnum, Domain: "example.com"}, &buf)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("non-JSON stdout line: %q", line)
		}
		if _, ok := obj["type"]; !ok {
			t.Fatalf("line without type field: %q", line)
		}
	}
}
