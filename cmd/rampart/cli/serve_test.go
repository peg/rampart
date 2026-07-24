package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/peg/rampart/policies"
)

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
}

func TestStopBackgroundServeAllowsMissingPID(t *testing.T) {
	testSetHome(t, t.TempDir())
	if err := stopBackgroundServe(&bytes.Buffer{}, true); err != nil {
		t.Fatalf("stopBackgroundServe(missingOK=true): %v", err)
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
		{name: "different rampart command", comm: "rampart", args: "rampart doctor"},
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
