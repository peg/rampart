package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/peg/rampart/policies"
)

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
	t.Setenv("HOME", home)

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
