package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePreloadBaseURL_UsesServeURLAlias(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("RAMPART_URL", "")
	t.Setenv("RAMPART_SERVE_URL", "")

	if err := os.MkdirAll(filepath.Join(home, ".rampart"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".rampart", "config.yaml"), []byte("serve_url: http://compat-serve:9123\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := resolvePreloadBaseURL(9099)
	if err != nil {
		t.Fatalf("resolvePreloadBaseURL: %v", err)
	}
	if got != "http://compat-serve:9123" {
		t.Fatalf("got %q", got)
	}
}

func TestResolvePreloadBaseURL_RejectsInvalidConfig(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".rampart"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".rampart", "config.yaml"), []byte("serveUrl: http://typo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := resolvePreloadBaseURL(9099); err == nil {
		t.Fatal("expected config parse error")
	}
}
