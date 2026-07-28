package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
)

func TestValidateWrapPlatform(t *testing.T) {
	for _, tt := range []struct {
		goos    string
		wantErr bool
	}{
		{goos: "linux"},
		{goos: "darwin"},
		{goos: "windows", wantErr: true},
		{goos: "freebsd", wantErr: true},
	} {
		t.Run(tt.goos, func(t *testing.T) {
			err := validateWrapPlatform(tt.goos)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateWrapPlatform(%q) error = %v, wantErr %v", tt.goos, err, tt.wantErr)
			}
		})
	}
}

func TestResolveWrapPolicyPath_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte("version: 1\n"), 0o644)

	got, cleanup, err := resolveWrapPolicyPath(p)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got != p {
		t.Errorf("got %q, want %q", got, p)
	}
}

func TestResolveWrapPolicyPath_FallbackEmbedded(t *testing.T) {
	got, cleanup, err := resolveWrapPolicyPath("/nonexistent/rampart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got == "" {
		t.Fatal("expected a temp file path")
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty policy file")
	}
}

func TestResolveWrapPolicyPath_Empty(t *testing.T) {
	// Empty path defaults to "rampart.yaml" which doesn't exist in cwd (probably)
	origDir, _ := os.Getwd()
	dir := t.TempDir()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	got, cleanup, err := resolveWrapPolicyPath("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got == "" {
		t.Fatal("expected fallback path")
	}
}

func TestResolveRealShell(t *testing.T) {
	// Should find bash on any CI/linux system
	shell, err := resolveRealShell(func(name string) (string, error) {
		if name == "/bin/bash" || name == "bash" {
			return "/bin/bash", nil
		}
		return "", &os.PathError{Op: "lookpath", Path: name, Err: os.ErrNotExist}
	})
	if err != nil {
		t.Fatal(err)
	}
	if shell != "/bin/bash" {
		t.Errorf("got %q", shell)
	}
}

func TestResolveRealShell_Fallback(t *testing.T) {
	t.Setenv("SHELL", "/nonexistent/shell")
	shell, err := resolveRealShell(func(name string) (string, error) {
		if name == "bash" {
			return "/usr/bin/bash", nil
		}
		return "", &os.PathError{Op: "lookpath", Path: name, Err: os.ErrNotExist}
	})
	if err != nil {
		t.Fatal(err)
	}
	if shell != "/usr/bin/bash" {
		t.Errorf("got %q", shell)
	}
}

func TestResolveRealShell_NoShell(t *testing.T) {
	t.Setenv("SHELL", "")
	_, err := resolveRealShell(func(name string) (string, error) {
		return "", &os.PathError{Op: "lookpath", Path: name, Err: os.ErrNotExist}
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateShellShim(t *testing.T) {
	skipOnWindows(t, "Unix shell shims")
	path, err := createShellShim("http://localhost:9090", "tok123", "enforce", "/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	defer os.Remove(path + ".tok")

	data, _ := os.ReadFile(path)
	script := string(data)
	if !strings.Contains(script, "/bin/bash") {
		t.Error("shim missing real shell")
	}
	if !strings.Contains(script, "http://localhost:9090") {
		t.Error("shim missing proxy URL")
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm()&0o111 == 0 {
		t.Error("shim not executable")
	}

	// Check token file
	tokData, _ := os.ReadFile(path + ".tok")
	if string(tokData) != "tok123" {
		t.Errorf("token file = %q", string(tokData))
	}
}

func TestShellShimFailsClosedWithoutCurlInEnforceMode(t *testing.T) {
	skipOnWindows(t, "Unix shell shims")
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	realShell := filepath.Join(dir, "real-shell")
	if err := os.WriteFile(realShell, []byte("#!/bin/sh\nprintf ran > \"$MARKER\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		mode        string
		wantCode    int
		wantExecute bool
	}{
		{mode: "enforce", wantCode: 126},
		{mode: "monitor", wantExecute: true},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			_ = os.Remove(marker)
			path, err := createShellShim("http://127.0.0.1:1", "token", tt.mode, realShell)
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(path)
			defer os.Remove(path + ".tok")

			var stderr bytes.Buffer
			cmd := exec.Command("/bin/bash", path, "-c", "echo should-not-run")
			cmd.Env = []string{"PATH=" + dir, "MARKER=" + marker}
			cmd.Stderr = &stderr
			err = cmd.Run()
			if tt.wantCode != 0 {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != tt.wantCode {
					t.Fatalf("exit error = %v, want code %d", err, tt.wantCode)
				}
				if !strings.Contains(stderr.String(), "policy cannot be evaluated") {
					t.Fatalf("stderr missing fail-closed reason: %q", stderr.String())
				}
			} else if err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(marker)
			if got := statErr == nil; got != tt.wantExecute {
				t.Fatalf("wrapped command executed = %v, want %v", got, tt.wantExecute)
			}
		})
	}
}

func TestShellShimFailsClosedWhenPreflightIsUnavailable(t *testing.T) {
	skipOnWindows(t, "Unix shell shims")
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"base64", "cat", "tr"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s is required for shell-shim test", name)
		}
		if err := os.Symlink(path, filepath.Join(binDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(binDir, "curl"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(dir, "executed")
	realShell := filepath.Join(dir, "real-shell")
	if err := os.WriteFile(realShell, []byte("#!/bin/sh\nprintf ran > \"$MARKER\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	shim, err := createShellShim("http://127.0.0.1:1", "token", "enforce", realShell)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(shim)
	defer os.Remove(shim + ".tok")

	var stderr bytes.Buffer
	cmd := exec.Command("/bin/bash", shim, "-c", "echo should-not-run")
	cmd.Env = []string{"PATH=" + binDir, "MARKER=" + marker}
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 126 {
		t.Fatalf("exit error = %v, want code 126", err)
	}
	if !strings.Contains(stderr.String(), "preflight unavailable; policy cannot be evaluated") {
		t.Fatalf("stderr missing fail-closed reason: %q", stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("wrapped command unexpectedly executed; marker stat error = %v", err)
	}
}

func TestShellShimFailsClosedWithoutBase64InEnforceMode(t *testing.T) {
	skipOnWindows(t, "Unix shell shims")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/bin/sh\nprintf '{\"allowed\":true}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "executed")
	realShell := filepath.Join(dir, "real-shell")
	if err := os.WriteFile(realShell, []byte("#!/bin/sh\nprintf ran > \"$MARKER\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	shim, err := createShellShim("http://127.0.0.1:1", "token", "enforce", realShell)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(shim)
	defer os.Remove(shim + ".tok")

	var stderr bytes.Buffer
	cmd := exec.Command("/bin/bash", shim, "-c", "echo should-not-run")
	cmd.Env = []string{"PATH=" + dir, "MARKER=" + marker}
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 126 {
		t.Fatalf("exit error = %v, want code 126", err)
	}
	if !strings.Contains(stderr.String(), "base64 is unavailable; command cannot be evaluated safely") {
		t.Fatalf("stderr missing fail-closed reason: %q", stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("wrapped command unexpectedly executed; marker stat error = %v", err)
	}
}

func TestCreateShellWrappers(t *testing.T) {
	dir, err := createShellWrappers("http://localhost:9090", "/tmp/tok", "enforce")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Should have at least bash wrapper if /bin/bash exists
	if _, err := os.Stat("/bin/bash"); err == nil {
		wrapper := filepath.Join(dir, "bash")
		data, err := os.ReadFile(wrapper)
		if err != nil {
			t.Fatal("missing bash wrapper")
		}
		if !strings.Contains(string(data), "RAMPART_ACTIVE") {
			t.Error("wrapper missing RAMPART_ACTIVE check")
		}
		if strings.Contains(string(data), "preflight unavailable, allowing") {
			t.Error("wrapper contains fail-open preflight path")
		}
		for _, want := range []string{"curl is unavailable; policy cannot be evaluated", "base64 is unavailable; command cannot be evaluated safely", "preflight unavailable; policy cannot be evaluated"} {
			if !strings.Contains(string(data), want) {
				t.Errorf("wrapper missing enforce failure %q", want)
			}
		}
	}
}

func TestExitCodeError(t *testing.T) {
	e := exitCodeError{code: 42}
	if e.ExitCode() != 42 {
		t.Errorf("ExitCode() = %d", e.ExitCode())
	}
	if e.Error() != "exit status 42" {
		t.Errorf("Error() = %q", e.Error())
	}

	e0 := exitCodeError{code: 0}
	if e0.ExitCode() != 1 {
		t.Errorf("ExitCode() for 0 = %d, want 1", e0.ExitCode())
	}

	eNeg := exitCodeError{code: -1}
	if eNeg.ExitCode() != 1 {
		t.Errorf("ExitCode() for -1 = %d, want 1", eNeg.ExitCode())
	}
}

type mockAuditSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *mockAuditSink) Write(e audit.Event) error {
	m.mu.Lock()
	m.events = append(m.events, e)
	m.mu.Unlock()
	return nil
}
func (m *mockAuditSink) Flush() error { return nil }
func (m *mockAuditSink) Close() error { return nil }

type failingCounterAuditSink struct{}

func (*failingCounterAuditSink) Write(audit.Event) error { return errors.New("disk unavailable") }
func (*failingCounterAuditSink) Flush() error            { return nil }
func (*failingCounterAuditSink) Close() error            { return nil }

func TestDecisionCounterSink(t *testing.T) {
	mock := &mockAuditSink{}
	sink := &decisionCounterSink{sink: mock, logger: testLogger()}

	sink.Write(audit.Event{Decision: audit.EventDecision{Action: "allow"}})
	sink.Write(audit.Event{Decision: audit.EventDecision{Action: "deny"}})
	sink.Write(audit.Event{Decision: audit.EventDecision{Action: "deny"}})
	sink.Write(audit.Event{Decision: audit.EventDecision{Action: "log"}})

	eval, denied, logged := sink.Counts()
	if eval != 4 {
		t.Errorf("evaluated = %d, want 4", eval)
	}
	if denied != 2 {
		t.Errorf("denied = %d, want 2", denied)
	}
	if logged != 1 {
		t.Errorf("logged = %d, want 1", logged)
	}

	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDecisionCounterSink_DoesNotCountFailedPersistence(t *testing.T) {
	sink := &decisionCounterSink{sink: &failingCounterAuditSink{}, logger: testLogger()}

	if err := sink.Write(audit.Event{Decision: audit.EventDecision{Action: "allow"}}); err == nil {
		t.Fatal("expected audit persistence failure")
	}
	evaluated, denied, logged := sink.Counts()
	if evaluated != 0 || denied != 0 || logged != 0 {
		t.Fatalf("failed audit changed counters: evaluated=%d denied=%d logged=%d", evaluated, denied, logged)
	}
}

func TestDecisionCounterSink_WithNotify(t *testing.T) {
	mock := &mockAuditSink{}
	sink := &decisionCounterSink{
		sink:         mock,
		notifyConfig: &engine.NotifyConfig{URL: "http://localhost:1234/webhook", On: []string{"deny"}},
		logger:       testLogger(),
	}

	// Just verify it doesn't panic with notify config set
	sink.Write(audit.Event{
		Tool:     "exec",
		Decision: audit.EventDecision{Action: "deny", Message: "blocked"},
	})

	eval, denied, _ := sink.Counts()
	if eval != 1 || denied != 1 {
		t.Errorf("counts wrong: eval=%d denied=%d", eval, denied)
	}
}
