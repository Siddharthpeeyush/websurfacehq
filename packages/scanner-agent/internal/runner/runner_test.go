package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRun_Echo(t *testing.T) {
	r := ExecRunner{}
	ctx := context.Background()
	res, err := r.Run(ctx, "echo", []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("echo failed: %v", err)
	}
	if string(res.Stdout) != "hello\n" {
		t.Errorf("unexpected stdout: %q", res.Stdout)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", res.ExitCode)
	}
}

func TestRun_StdinPassedThrough(t *testing.T) {
	r := ExecRunner{}
	res, err := r.Run(context.Background(), "cat", nil, []byte("abc\n"))
	if err != nil {
		t.Fatalf("cat failed: %v", err)
	}
	if string(res.Stdout) != "abc\n" {
		t.Errorf("unexpected stdout: %q", res.Stdout)
	}
}

func TestRun_NonZeroExit(t *testing.T) {
	r := ExecRunner{}
	_, err := r.Run(context.Background(), "false", nil, nil)
	if err == nil {
		t.Fatal("expected error for non-zero exit")
	}
	if !strings.Contains(err.Error(), "exited with status 1") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRun_MissingBinary(t *testing.T) {
	r := ExecRunner{}
	_, err := r.Run(context.Background(), "websurfacehq-definitely-not-a-tool", nil, nil)
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestRun_TimeoutKillsSleep(t *testing.T) {
	r := ExecRunner{}
	// sleep 30 must be killed on expiry: the call must return well
	// before 30s, and the error must be a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Run(ctx, "sleep", []string{"30"}, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrTimeout, got %v", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("sleep was not killed promptly: took %v", elapsed)
	}
}

func TestRun_TimeoutKillsProcessGroup(t *testing.T) {
	r := ExecRunner{}
	// sh spawns a child sleep; the group kill must take the child too.
	// If only the shell were killed, the orphaned sleep would keep the
	// shell's stdout pipe open and Run would block until it finished.
	// (sleep 30 child would delay us 30s — the test fails by slowness.)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Run(ctx, "sh", []string{"-c", "sleep 30"}, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrTimeout, got %v", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("process group was not killed promptly: took %v", elapsed)
	}
}

func TestRunInDir_SetsWorkingDirectory(t *testing.T) {
	// The screenshot pass relies on RunInDir: the child must run with
	// its cwd set to the given temp dir, not the agent's cwd.
	r := ExecRunner{}
	dir := t.TempDir()
	res, err := r.RunInDir(context.Background(), "sh", []string{"-c", "pwd"}, nil, dir)
	if err != nil {
		t.Fatalf("RunInDir: %v", err)
	}
	if strings.TrimSpace(string(res.Stdout)) != dir {
		t.Errorf("child cwd = %q, want %q", strings.TrimSpace(string(res.Stdout)), dir)
	}
	// Run (no dir) still runs in the agent's own cwd.
	res, err = r.Run(context.Background(), "sh", []string{"-c", "pwd"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.TrimSpace(string(res.Stdout)) == dir {
		t.Errorf("Run without a dir must not run in %q", dir)
	}
}

func TestLookPath(t *testing.T) {
	r := ExecRunner{}
	if _, err := r.LookPath("echo"); err != nil {
		t.Errorf("echo should be on PATH: %v", err)
	}
	if _, err := r.LookPath("websurfacehq-definitely-not-a-tool"); err == nil {
		t.Error("missing tool should error")
	}
}
