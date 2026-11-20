// Command scanner-agent is the WebSurfaceHQ Go scanner-agent binary
// (Week 2 Recon). It reads ONE JSON stage request on stdin and emits
// structured JSONL on stdout — see internal/agent for the contract.
//
// It prints nothing else to stdout. Tool stderr is forwarded to our stderr
// (never stdout) so the Python runner's JSONL parsing stays clean.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"websurfacehq/scanner-agent/internal/agent"
)

func main() {
	os.Exit(run(os.Stdin, os.Stdout, agent.New()))
}

// maxStdinBytes caps the stage request read from stdin (1 MiB). A stage
// request is a few hundred bytes; an unbounded read lets a caller force
// the agent to buffer an arbitrary amount of memory before parsing.
const maxStdinBytes = 1 << 20

// run is split from main so tests can inject an Agent with a fake
// resolver/runner; production main passes agent.New().
func run(stdin io.Reader, stdout io.Writer, ag *agent.Agent) int {
	// LimitReader(+1) so an oversize input is detected instead of
	// silently truncated: a truncated JSON object would fail the decode
	// with a confusing syntax error.
	raw, err := io.ReadAll(io.LimitReader(stdin, maxStdinBytes+1))
	if err != nil {
		emitError(stdout, fmt.Sprintf("failed to read stdin: %v", err))
		return 1
	}
	if len(raw) > maxStdinBytes {
		emitError(stdout, fmt.Sprintf("invalid stage input: stdin exceeds %d bytes", maxStdinBytes))
		return 1
	}
	var in agent.Input
	dec := json.NewDecoder(bytes.NewReader(raw))
	// No DisallowUnknownFields: the Python runner may pass forward-compat
	// "extra" fields (scanner_runner.run_stage(extra=...)). Unknown
	// fields are ignored; the known contract fields are validated below.
	if err := dec.Decode(&in); err != nil {
		emitError(stdout, fmt.Sprintf("invalid stage input JSON: %v", err))
		return 1
	}
	// Reject trailing data after the single JSON object (other than
	// whitespace): the contract is exactly one object on stdin.
	if dec.More() {
		emitError(stdout, "invalid stage input: expected exactly one JSON object on stdin")
		return 1
	}
	return ag.Run(context.Background(), in, stdout)
}

func emitError(w io.Writer, msg string) {
	b, _ := json.Marshal(map[string]any{"type": "error", "message": msg})
	_, _ = w.Write(append(b, '\n'))
}
