package cli

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
)

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
