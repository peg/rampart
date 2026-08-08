package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSuperviseMCPProcessTerminatesChildWhenProxyFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitCh := make(chan error, 1)
	proxyErrCh := make(chan error, 1)
	proxyErrCh <- errors.New("proxy stopped")
	terminated := false

	waitErr, proxyErr, contextErr := superviseMCPProcess(ctx, cancel, func() error {
		terminated = true
		waitCh <- errors.New("child killed")
		return nil
	}, waitCh, proxyErrCh)
	if !terminated {
		t.Fatal("proxy failure did not terminate child")
	}
	if proxyErr == nil || proxyErr.Error() != "proxy stopped" {
		t.Fatalf("proxy error = %v", proxyErr)
	}
	if waitErr == nil || waitErr.Error() != "child killed" {
		t.Fatalf("wait error = %v", waitErr)
	}
	if contextErr != nil {
		t.Fatalf("context error = %v", contextErr)
	}
}

func TestSuperviseMCPProcessCancelsProxyWhenChildExits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	waitCh := make(chan error, 1)
	proxyErrCh := make(chan error, 1)
	waitCh <- nil
	cancelled := false
	wrapperCancel := func() {
		cancelled = true
		cancel()
		proxyErrCh <- nil
	}

	waitErr, proxyErr, contextErr := superviseMCPProcess(ctx, wrapperCancel, nil, waitCh, proxyErrCh)
	if !cancelled {
		t.Fatal("child exit did not cancel proxy")
	}
	if waitErr != nil || proxyErr != nil || contextErr != nil {
		t.Fatalf("outcome = wait %v, proxy %v, context %v", waitErr, proxyErr, contextErr)
	}
}

func TestResolveMCPPolicyPath_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte("version: 1\n"), 0o644)

	got, cleanup, err := resolveMCPPolicyPath(p)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got != p {
		t.Errorf("got %q, want %q", got, p)
	}
}

func TestResolveMCPPolicyPath_Fallback(t *testing.T) {
	got, cleanup, err := resolveMCPPolicyPath("/nonexistent/rampart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got == "" {
		t.Fatal("expected temp file path")
	}
	data, _ := os.ReadFile(got)
	if len(data) == 0 {
		t.Fatal("expected non-empty policy")
	}
}

func TestResolveTestPolicyPath_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte("version: 1\n"), 0o644)

	got, cleanup, err := resolveTestPolicyPath(p)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got != p {
		t.Errorf("got %q, want %q", got, p)
	}
}

func TestResolveTestPolicyPath_Fallback(t *testing.T) {
	got, cleanup, err := resolveTestPolicyPath("/nonexistent/rampart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got == "" {
		t.Fatal("expected temp file path")
	}
}
