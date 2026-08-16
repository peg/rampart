package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/policies"
	"github.com/stretchr/testify/require"
)

func TestNotifyRequiresSignedApprovalLinks(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  *engine.NotifyConfig
		want bool
	}{
		{name: "none"},
		{name: "empty url", cfg: &engine.NotifyConfig{On: []string{"ask"}}},
		{name: "default includes ask", cfg: &engine.NotifyConfig{URL: "https://example.invalid/hook"}, want: true},
		{name: "ask", cfg: &engine.NotifyConfig{URL: "https://example.invalid/hook", On: []string{"ask"}}, want: true},
		{name: "legacy approval", cfg: &engine.NotifyConfig{URL: "https://example.invalid/hook", On: []string{" REQUIRE_APPROVAL "}}, want: true},
		{name: "deny only", cfg: &engine.NotifyConfig{URL: "https://example.invalid/hook", On: []string{"deny"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := notifyRequiresSignedApprovalLinks(test.cfg); got != test.want {
				t.Fatalf("notifyRequiresSignedApprovalLinks() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestServeFailsClosedWhenApprovalSigningKeyIsUnavailable(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	configPath := filepath.Join(home, "rampart.yaml")
	config := `version: "1"
default_action: deny
notify:
  url: https://example.invalid/hook
  platform: webhook
  on: [ask]
policies: []
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	loaderCalled := false
	deps := &serveDeps{
		loadSigningKey: func(string) ([]byte, error) {
			loaderCalled = true
			return nil, fmt.Errorf("simulated signing-key failure")
		},
	}
	cmd := newServeCmd(&rootOptions{configPath: configPath}, deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--port", "19091", "--audit-dir", filepath.Join(home, "audit")})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "approval resolve URL signing unavailable") {
		t.Fatalf("serve error = %v, want signing failure", err)
	}
	if !loaderCalled {
		t.Fatal("serve did not attempt to load the approval signing key")
	}
}

func TestServeRejectsSecondApprovalStateOwner(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	configPath := filepath.Join(home, "rampart.yaml")
	content, err := policies.FS.ReadFile("standard.yaml")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, content, 0o600))

	freePort := func() int {
		listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, listenErr)
		port := listener.Addr().(*net.TCPAddr).Port
		require.NoError(t, listener.Close())
		return port
	}
	firstPort, secondPort := freePort(), freePort()
	for secondPort == firstPort {
		secondPort = freePort()
	}

	signalCh := make(chan os.Signal, 1)
	deps := &serveDeps{
		notifyContext: func(parent context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			go func() {
				select {
				case <-ctx.Done():
				case <-signalCh:
					cancel()
				}
			}()
			return ctx, cancel
		},
	}

	first := newServeCmd(&rootOptions{configPath: configPath}, deps)
	first.SetOut(&bytes.Buffer{})
	first.SetErr(&bytes.Buffer{})
	first.SetContext(context.Background())
	first.SetArgs([]string{"--addr", "127.0.0.1", "--port", fmt.Sprintf("%d", firstPort), "--audit-dir", filepath.Join(home, "audit")})
	firstErr := make(chan error, 1)
	go func() { firstErr <- first.Execute() }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", firstPort), 50*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		select {
		case serveErr := <-firstErr:
			t.Fatalf("first serve exited before readiness: %v", serveErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("first serve did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}

	second := newServeCmd(&rootOptions{configPath: configPath}, nil)
	second.SetOut(&bytes.Buffer{})
	second.SetErr(&bytes.Buffer{})
	second.SetArgs([]string{"--addr", "127.0.0.1", "--port", fmt.Sprintf("%d", secondPort), "--audit-dir", filepath.Join(home, "audit")})
	secondErr := second.Execute()
	require.ErrorContains(t, secondErr, "another Rampart serve process already owns approval state")

	signalCh <- os.Interrupt
	select {
	case serveErr := <-firstErr:
		require.NoError(t, serveErr)
	case <-time.After(3 * time.Second):
		t.Fatal("first serve did not shut down")
	}
}

func TestServeTokenOutputRedactsWhenNonInteractive(t *testing.T) {
	const token = "secret-token-value"
	var buf bytes.Buffer
	printServeToken(&buf, token, false)
	got := buf.String()
	if strings.Contains(got, token) {
		t.Fatalf("non-interactive output leaked full token: %q", got)
	}
	if !strings.Contains(got, "saved to ~/.rampart/token") {
		t.Fatalf("non-interactive output should point to token file, got: %q", got)
	}
}

func TestServeTokenOutputPrintsForInteractiveTerminal(t *testing.T) {
	const token = "secret-token-value"
	var buf bytes.Buffer
	printServeToken(&buf, token, true)
	got := buf.String()
	if !strings.Contains(got, token) {
		t.Fatalf("interactive output should include full token, got: %q", got)
	}
}

func TestIsWriteEvent(t *testing.T) {
	tests := []struct {
		name string
		op   fsnotify.Op
		want bool
	}{
		{"write", fsnotify.Write, true},
		{"create", fsnotify.Create, false},
		{"remove", fsnotify.Remove, false},
		{"rename", fsnotify.Rename, false},
		{"chmod", fsnotify.Chmod, false},
		{"write+create", fsnotify.Write | fsnotify.Create, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := fsnotify.Event{Name: "test.yaml", Op: tt.op}
			if got := isWriteEvent(e); got != tt.want {
				t.Errorf("isWriteEvent(%v) = %v, want %v", tt.op, got, tt.want)
			}
		})
	}
}

func TestIsPolicyDirEvent(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator), "tmp", "rampart", "policies")
	tests := []struct {
		name  string
		event fsnotify.Event
		want  bool
	}{
		{name: "yaml write", event: fsnotify.Event{Name: filepath.Join(dir, "guard.yaml"), Op: fsnotify.Write}, want: true},
		{name: "yml create", event: fsnotify.Event{Name: filepath.Join(dir, "custom.yml"), Op: fsnotify.Create}, want: true},
		{name: "yaml remove", event: fsnotify.Event{Name: filepath.Join(dir, "old.yaml"), Op: fsnotify.Remove}, want: true},
		{name: "yaml rename", event: fsnotify.Event{Name: filepath.Join(dir, "old.yaml"), Op: fsnotify.Rename}, want: true},
		{name: "unrelated extension", event: fsnotify.Event{Name: filepath.Join(dir, "notes.txt"), Op: fsnotify.Write}},
		{name: "nested directory", event: fsnotify.Event{Name: filepath.Join(dir, "nested", "guard.yaml"), Op: fsnotify.Write}},
		{name: "different directory", event: fsnotify.Event{Name: filepath.Join(filepath.Dir(dir), "guard.yaml"), Op: fsnotify.Write}},
		{name: "chmod only", event: fsnotify.Event{Name: filepath.Join(dir, "guard.yaml"), Op: fsnotify.Chmod}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPolicyDirEvent(tt.event, dir); got != tt.want {
				t.Fatalf("isPolicyDirEvent(%v, %q) = %v, want %v", tt.event, dir, got, tt.want)
			}
		})
	}
	if runtime.GOOS == "windows" {
		event := fsnotify.Event{Name: filepath.Join(strings.ToUpper(dir), "guard.yaml"), Op: fsnotify.Write}
		if !isPolicyDirEvent(event, dir) {
			t.Fatal("isPolicyDirEvent must compare Windows directory paths case-insensitively")
		}
	}
}

func TestStopBackgroundServeAllowsMissingPID(t *testing.T) {
	testSetHome(t, t.TempDir())
	if err := stopBackgroundServe(&bytes.Buffer{}, true); err != nil {
		t.Fatalf("stopBackgroundServe(missingOK=true): %v", err)
	}
}

func TestPrepareBackgroundServePIDRefusesToClobberRunningServer(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "serve.pid")
	if err := os.WriteFile(pidPath, []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalInspect := inspectBackgroundServeProcess
	inspectBackgroundServeProcess = func(pid int) (bool, string, error) {
		if pid != 4242 {
			t.Fatalf("inspected pid = %d, want 4242", pid)
		}
		return true, "rampart serve", nil
	}
	t.Cleanup(func() { inspectBackgroundServeProcess = originalInspect })

	if err := prepareBackgroundServePID(pidPath); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("prepareBackgroundServePID error = %v", err)
	}
	if _, err := os.Stat(pidPath); err != nil {
		t.Fatalf("active PID file was removed: %v", err)
	}
}

func TestPrepareBackgroundServePIDRemovesAuthenticatedStaleFile(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "serve.pid")
	if err := os.WriteFile(pidPath, []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalInspect := inspectBackgroundServeProcess
	inspectBackgroundServeProcess = func(int) (bool, string, error) {
		return false, "process is no longer running", nil
	}
	t.Cleanup(func() { inspectBackgroundServeProcess = originalInspect })

	if err := prepareBackgroundServePID(pidPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("stale PID file remains: %v", err)
	}
}

func TestReadServePIDFileRejectsSymlinkAndOversizedInput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "serve.pid")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := readServePIDFile(link); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("symlink error = %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte(strings.Repeat("9", maxServePIDFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readServePIDFile(link); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestBackgroundReadyMarkerRequiresExactChildPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".serve-ready-test")
	if err := os.WriteFile(path, []byte("wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(path, []byte("4242\n"), 0o600)
	}()
	if err := waitForBackgroundReady(path, 4242, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeBackgroundReadyPathStaysInsideRampartDir(t *testing.T) {
	rampartDir := t.TempDir()
	valid := filepath.Join(rampartDir, ".serve-ready-valid")
	t.Setenv(backgroundReadyFileEnv, valid)
	got, err := consumeBackgroundReadyPath(rampartDir)
	if err != nil || got != valid {
		t.Fatalf("consumeBackgroundReadyPath() = %q, %v", got, err)
	}
	if os.Getenv(backgroundReadyFileEnv) != "" {
		t.Fatal("readiness environment variable was not consumed")
	}

	t.Setenv(backgroundReadyFileEnv, filepath.Join(t.TempDir(), ".serve-ready-outside"))
	if _, err := consumeBackgroundReadyPath(rampartDir); err == nil {
		t.Fatal("outside readiness path was accepted")
	}
}

func TestIsRampartServeCommand(t *testing.T) {
	tests := []struct {
		name string
		comm string
		args string
		want bool
	}{
		{name: "serve", comm: "/usr/local/bin/rampart", args: "/usr/local/bin/rampart serve --port 9090", want: true},
		{name: "serve with global flag", comm: "rampart", args: "rampart --config /tmp/policy.yaml serve", want: true},
		{name: "quoted Windows executable", comm: "rampart.exe", args: `"C:\Program Files\Rampart\rampart.exe" serve --port 9090`, want: true},
		{name: "different rampart command", comm: "rampart", args: "rampart doctor"},
		{name: "serve as unrelated argument", comm: "rampart", args: "rampart doctor --output serve"},
		{name: "serve after terminating version flag", comm: "rampart", args: "rampart --version serve"},
		{name: "different executable", comm: "/usr/bin/sleep", args: "sleep 60"},
		{name: "name substring", comm: "/tmp/not-rampart", args: "/tmp/not-rampart serve"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRampartServeCommand(tt.comm, tt.args); got != tt.want {
				t.Fatalf("isRampartServeCommand(%q, %q) = %v, want %v", tt.comm, tt.args, got, tt.want)
			}
		})
	}
}

func TestIsRampartServeCommandAuthenticatesPublishedExecutable(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "rampart-openclaw-candidate")
	args := executable + " serve --port 19090"
	if !isRampartServeCommandForExecutable("rampart-o", args, executable) {
		t.Fatal("published executable identity did not authenticate a renamed Rampart server")
	}
	if isRampartServeCommandForExecutable("rampart-o", args, filepath.Join(t.TempDir(), "rampart-openclaw-candidate")) {
		t.Fatal("mismatched executable identity authenticated")
	}
	if isRampartServeCommand("rampart-o", args) {
		t.Fatal("renamed binary authenticated without published executable identity")
	}
}

func TestServeStatePublishesPrivateExecutableIdentity(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	dir := filepath.Join(home, ".rampart")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const pid = 4242
	if err := writeServeState(dir, 19090, pid, false); err != nil {
		t.Fatal(err)
	}
	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err = filepath.Abs(want)
	if err != nil {
		t.Fatal(err)
	}
	if got := serveExecutableForPID(pid); !samePath(got, want) {
		t.Fatalf("serveExecutableForPID() = %q, want %q", got, want)
	}
	if got := serveExecutableForPID(pid + 1); got != "" {
		t.Fatalf("mismatched PID returned executable %q", got)
	}
}

func TestSamePath(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"/foo/bar", "/foo/bar", true},
		{"/foo/bar/", "/foo/bar", true},
		{"/foo//bar", "/foo/bar", true},
		{"/foo/bar", "/foo/baz", false},
		{" /foo/bar ", "/foo/bar", true},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			if got := samePath(tt.a, tt.b); got != tt.want {
				t.Errorf("samePath(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
	if runtime.GOOS == "windows" {
		if !samePath(`C:\Users\Example\.rampart\rampart.exe`, `c:\users\example\.RAMPART\RAMPART.EXE`) {
			t.Fatal("samePath must compare Windows paths case-insensitively")
		}
	}
}

func TestActivePolicyMDWrite(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	configPath := filepath.Join(home, "rampart.yaml")
	content, err := policies.FS.ReadFile("standard.yaml")
	if err != nil {
		t.Fatalf("read embedded policy: %v", err)
	}
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	signalCh := make(chan os.Signal, 1)
	deps := &serveDeps{
		notifyContext: func(parent context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			go func() {
				select {
				case <-ctx.Done():
				case <-signalCh:
					cancel()
				}
			}()
			return ctx, cancel
		},
	}

	cmd := newServeCmd(&rootOptions{configPath: configPath}, deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"--addr", "127.0.0.1", "--port", fmt.Sprintf("%d", port)})

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	activePolicyPath := filepath.Join(home, ".rampart", "ACTIVE_POLICY.md")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(activePolicyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ACTIVE_POLICY.md was not created at %s", activePolicyPath)
		}
		time.Sleep(25 * time.Millisecond)
	}

	signalCh <- os.Interrupt

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve command failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve command did not shut down in time")
	}
}

func TestWriteActivePolicyMarkdownReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	rampartDir := filepath.Join(home, ".rampart")
	if err := os.MkdirAll(rampartDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(target, []byte("preserve-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(rampartDir, "ACTIVE_POLICY.md")
	if err := os.Symlink(target, active); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	store := engine.NewMemoryStore([]byte("version: \"1\"\npolicies: []\n"), "active-policy-test")
	eng, err := engine.New(store, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeActivePolicyMarkdown(eng); err != nil {
		t.Fatal(err)
	}

	targetData, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(targetData) != "preserve-me" {
		t.Fatalf("symlink target changed to %q", targetData)
	}
	info, err := os.Lstat(active)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("ACTIVE_POLICY.md remained a symlink")
	}
}
