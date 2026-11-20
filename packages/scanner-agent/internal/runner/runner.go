// Package runner is the exec wrapper for the scanner-agent: it runs the
// ProjectDiscovery tools with a curated flag set only (no shell, no
// user-controlled flags), enforces a context timeout, and kills the whole
// child process group on expiry so a hung tool cannot outlive the stage.
//
// Timeout ordering (agent vs Python worker): the agent's own timeout
// (timeout_seconds, applied as the context deadline in agent.Run) fires
// FIRST and group-kills the tool and any children it spawned; the
// Python runner's longer timeout (timeout + 30s grace) is only a
// backstop for a wedged agent process. Every tool invocation in the
// agent — probe, screenshot pass, crawl — goes through this runner, so
// every path gets the group kill; no tool runs outside it.
//
// Politeness (week-2-plan §3): 5 req/s, 2 concurrent runs max — PER
// AGENT PROCESS, not per target (review fix M5: with N workers the
// per-target rate multiplies by N). The per-tool rate flags carry the
// 5 req/s; this package enforces the 2-concurrent cap with a semaphore
// and the per-stage timeout with the caller's context.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

// MaxConcurrency is the 2-concurrent cap from the Week 2 plan.
const MaxConcurrency = 2

// MaxOutputBytes caps captured tool stdout (32 MiB). A tool emitting more
// than this is treated as a failure rather than an OOM risk; the cap is far
// above any realistic recon stage (subfinder/httpx/katana JSONL for one
// domain is kilobytes to low megabytes).
const MaxOutputBytes = 32 << 20

var sem = make(chan struct{}, MaxConcurrency)

// ErrTimeout is returned when the context expires (or the tool is killed
// for exceeding its deadline).
var ErrTimeout = errors.New("tool timed out")

// Result is the outcome of one tool invocation.
type Result struct {
	Stdout   []byte // captured stdout (capped at MaxOutputBytes)
	Stderr   []byte // captured stderr (capped, for diagnostics only — never echoed to our stdout)
	ExitCode int    // -1 if the process never started or was killed
}

// Runner executes external tools. It is an interface so stages can be
// tested with a fake (see internal/agent tests).
type Runner interface {
	// Run executes name with args and optional stdin, under ctx. It returns
	// a non-nil error only when the tool could not be started, timed out,
	// or exited non-zero; Stdout/Stderr are still returned for diagnosis.
	Run(ctx context.Context, name string, args []string, stdin []byte) (*Result, error)
	// RunInDir is Run with the child's working directory set to dir
	// (empty dir = the agent's own cwd). Used by the httpx screenshot
	// pass so screenshot files land in a throwaway temp dir instead of
	// the shared worker cwd.
	RunInDir(ctx context.Context, name string, args []string, stdin []byte, dir string) (*Result, error)
	// LookPath reports whether a tool binary is available on PATH.
	LookPath(name string) (string, error)
}

// ExecRunner is the real Runner: exec.CommandContext with process-group
// kill on timeout and no shell anywhere in the path.
type ExecRunner struct{}

// LookPath delegates to exec.LookPath.
func (ExecRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// cappedWriter errors once more than limit bytes are written.
type cappedWriter struct {
	buf   *bytes.Buffer
	limit int
	err   error
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.buf.Len()+len(p) > w.limit {
		w.err = fmt.Errorf("tool output exceeded %d bytes", w.limit)
		return 0, w.err
	}
	return w.buf.Write(p)
}

// Run executes the tool in the agent's own working directory.
func (ExecRunner) Run(ctx context.Context, name string, args []string, stdin []byte) (*Result, error) {
	return runInDir(ctx, name, args, stdin, "")
}

// RunInDir executes the tool with its working directory set to dir.
// The child is started in its own process group so a timeout kills the
// tool AND any subprocess it spawned (subfinder/naabu can fork helpers);
// a plain cmd.Process.Kill would orphan them.
func (ExecRunner) RunInDir(ctx context.Context, name string, args []string, stdin []byte, dir string) (*Result, error) {
	return runInDir(ctx, name, args, stdin, dir)
}

// runInDir is the shared implementation behind Run and RunInDir.
func runInDir(ctx context.Context, name string, args []string, stdin []byte, dir string) (*Result, error) {
	// Concurrency cap: 2 runs at a time. Wait for a slot, but respect the
	// caller's deadline while waiting.
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: waiting for a runner slot: %v", ErrTimeout, ctx.Err())
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if dir != "" {
		cmd.Dir = dir
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var outBuf, errBuf bytes.Buffer
	outW := &cappedWriter{buf: &outBuf, limit: MaxOutputBytes}
	errW := &cappedWriter{buf: &errBuf, limit: MaxOutputBytes}
	cmd.Stdout = outW
	cmd.Stderr = errW

	if err := cmd.Start(); err != nil {
		return &Result{ExitCode: -1}, fmt.Errorf("failed to start %s: %w", name, err)
	}

	// Kill the whole process group if the context expires. CommandContext
	// kills only the direct child; the group kill covers its children.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				// Negative PID = process group (Setpgid above).
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		case <-done:
		}
	}()

	waitErr := cmd.Wait()
	close(done)

	res := &Result{
		Stdout:   outBuf.Bytes(),
		Stderr:   errBuf.Bytes(),
		ExitCode: -1,
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if outW.err != nil {
		return res, outW.err
	}
	if errW.err != nil {
		return res, errW.err
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return res, fmt.Errorf("%w: %s", ErrTimeout, name)
		}
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return res, fmt.Errorf("%s exited with status %d: %s", name, exitErr.ExitCode(), truncate(errBuf.Bytes(), 500))
		}
		return res, fmt.Errorf("%s failed: %w", name, waitErr)
	}
	return res, nil
}

// truncate returns at most n bytes of b, for error messages.
func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
