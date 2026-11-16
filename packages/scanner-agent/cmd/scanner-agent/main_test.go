package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websurfacehq/scanner-agent/internal/agent"
	"websurfacehq/scanner-agent/internal/runner"
)

// fakeResolver always resolves to a public IP, so CLI end-to-end tests do
// not depend on this VM's sink DNS (see internal/dnsenum tests).
type fakeResolver struct{}

func (fakeResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

// installFakeTool writes an executable shell script named tool into dir
// that prints fixture verbatim on stdout. It records its argv to
// <tool>.argv in the same dir for flag assertions.
func installFakeTool(t *testing.T, dir, tool, fixture string) {
	t.Helper()
	script := "#!/bin/sh\n" +
		"echo \"$@\" > \"" + filepath.Join(dir, tool+".argv") + "\"\n" +
		"cat \"" + filepath.Join(dir, fixture) + "\"\n"
	path := filepath.Join(dir, tool)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", tool, err)
	}
}

func testAgent(t *testing.T, dir string) *agent.Agent {
	t.Helper()
	return &agent.Agent{Runner: runner.ExecRunner{}, Resolver: fakeResolver{}}
}

func TestCLI_SubdomainEnumEndToEnd(t *testing.T) {
	dir := t.TempDir()
	// Copy the synthetic subfinder fixture next to the fake tool.
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "subfinder.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "subfinder.out"), data, 0o644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}
	installFakeTool(t, dir, "subfinder", "subfinder.out")

	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	var out bytes.Buffer
	code := run(strings.NewReader(`{"stage":"subdomain_enum","domain":"example.com"}`), &out, testAgent(t, dir))
	if code != 0 {
		t.Fatalf("exit code %d, output: %s", code, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var result map[string]any
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("stdout line is not JSON: %q", line)
		}
		if obj["type"] == "result" {
			result = obj
		}
	}
	if result == nil {
		t.Fatal("no result line")
	}
	if result["stage"] != "subdomain_enum" {
		t.Errorf("stage = %v", result["stage"])
	}
	data2 := result["data"].(map[string]any)
	if int(data2["count"].(float64)) != 4 {
		t.Errorf("count = %v, want 4", data2["count"])
	}
	// The fake tool must have received the domain as its own argv token
	// (safe flag construction — no shell, no concatenation).
	argv, err := os.ReadFile(filepath.Join(dir, "subfinder.argv"))
	if err != nil {
		t.Fatalf("read argv record: %v", err)
	}
	if !strings.Contains(string(argv), "-d example.com") {
		t.Errorf("subfinder argv = %q, want -d example.com in it", argv)
	}
}

func TestCLI_BadJSON(t *testing.T) {
	var out bytes.Buffer
	code := run(strings.NewReader(`{not json`), &out, testAgent(t, t.TempDir()))
	if code == 0 {
		t.Fatal("bad JSON must exit non-zero")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &obj); err != nil {
		t.Fatalf("error output is not JSON: %q", out.String())
	}
	if obj["type"] != "error" {
		t.Errorf("type = %v, want error", obj["type"])
	}
}

func TestCLI_UnknownFieldIgnored(t *testing.T) {
	// Unknown input fields are IGNORED (forward-compat with the Python
	// runner's run_stage(extra=...)): the decode must not fail on them.
	// A missing domain is still an error — and the error must be about
	// the domain, proving the unknown field did not trip the decoder.
	var out bytes.Buffer
	code := run(strings.NewReader(`{"stage":"subdomain_enum","domain":"","surprise":1}`), &out, testAgent(t, t.TempDir()))
	if code == 0 {
		t.Fatal("missing domain must exit non-zero")
	}
	if !strings.Contains(out.String(), "domain is required") {
		t.Errorf("expected a domain error, got: %s", out.String())
	}
}

func TestCLI_TrailingDataRejected(t *testing.T) {
	var out bytes.Buffer
	code := run(strings.NewReader(`{"stage":"subdomain_enum","domain":"example.com"} {"stage":"crawl"}`), &out, testAgent(t, t.TempDir()))
	if code == 0 {
		t.Fatal("trailing JSON object must be rejected")
	}
}

func TestCLI_OversizeStdinRejected(t *testing.T) {
	// Stdin is capped at 1 MiB: a larger input must be rejected with a
	// clear size error, not buffered unboundedly.
	big := `{"stage":"subdomain_enum","domain":"example.com","wordlist":"` +
		strings.Repeat("x", (1<<20)+10) + `"}` // > 1 MiB
	var out bytes.Buffer
	code := run(strings.NewReader(big), &out, testAgent(t, t.TempDir()))
	if code == 0 {
		t.Fatal("oversize stdin must exit non-zero")
	}
	if !strings.Contains(out.String(), "exceeds") {
		t.Errorf("oversize stdin error must name the size cap, got: %s", out.String())
	}
}

func TestCLI_EmptyStdin(t *testing.T) {
	var out bytes.Buffer
	code := run(strings.NewReader(``), &out, testAgent(t, t.TempDir()))
	if code == 0 {
		t.Fatal("empty stdin must exit non-zero")
	}
}
