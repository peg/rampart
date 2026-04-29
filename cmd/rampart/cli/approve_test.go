package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is..."},
		{"abc", 3, "abc"},
		{"abcd", 3, "..."},
	}
	for _, tt := range tests {
		got := truncate(tt.s, tt.max)
		if tt.max >= 3 && got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
		}
	}
}

func TestResolveToken(t *testing.T) {
	// Use temp dir as HOME to avoid picking up real ~/.rampart/token
	testSetHome(t, t.TempDir())
	t.Setenv("RAMPART_TOKEN", "env-tok")

	if got := resolveToken("explicit"); got != "explicit" {
		t.Errorf("resolveToken with explicit = %q", got)
	}
	if got := resolveToken(""); got != "env-tok" {
		t.Errorf("resolveToken with env = %q", got)
	}

	os.Unsetenv("RAMPART_TOKEN")
	if got := resolveToken(""); got != "" {
		t.Errorf("resolveToken with nothing = %q", got)
	}
}

func TestResolveAddr(t *testing.T) {
	defaultAddr := fmt.Sprintf("http://localhost:%d", defaultServePort)

	t.Run("empty addr falls back to default", func(t *testing.T) {
		os.Unsetenv("RAMPART_API")
		os.Unsetenv("RAMPART_URL")
		os.Unsetenv("RAMPART_SERVE_URL")
		if got := resolveAddr(""); got != defaultAddr {
			t.Errorf("got %q", got)
		}
	})

	t.Run("empty addr uses RAMPART_API override", func(t *testing.T) {
		t.Setenv("RAMPART_API", "http://custom:1234/")
		if got := resolveAddr(""); got != "http://custom:1234" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("empty addr uses serve url resolution chain", func(t *testing.T) {
		os.Unsetenv("RAMPART_API")
		t.Setenv("RAMPART_URL", "http://proxy:7777/")
		if got := resolveAddr(""); got != "http://proxy:7777" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("empty addr uses config API override", func(t *testing.T) {
		home := t.TempDir()
		testSetHome(t, home)
		os.Unsetenv("RAMPART_API")
		os.Unsetenv("RAMPART_URL")
		os.Unsetenv("RAMPART_SERVE_URL")
		if err := os.MkdirAll(filepath.Join(home, ".rampart"), 0o755); err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(home, ".rampart", "config.yaml")
		if err := os.WriteFile(cfgPath, []byte("api: http://config-api:8123\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := resolveAddr(""); got != "http://config-api:8123" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("explicit serve-url alias resolves when url unset", func(t *testing.T) {
		home := t.TempDir()
		testSetHome(t, home)
		os.Unsetenv("RAMPART_API")
		os.Unsetenv("RAMPART_URL")
		os.Unsetenv("RAMPART_SERVE_URL")
		if err := os.MkdirAll(filepath.Join(home, ".rampart"), 0o755); err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(home, ".rampart", "config.yaml")
		if err := os.WriteFile(cfgPath, []byte("serve_url: http://compat-serve:8124\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := resolveAddr(""); got != "http://compat-serve:8124" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("explicit addr wins", func(t *testing.T) {
		t.Setenv("RAMPART_API", "http://custom:1234")
		if got := resolveAddr("http://other:5678"); got != "http://other:5678" {
			t.Errorf("got %q", got)
		}
	})
}
