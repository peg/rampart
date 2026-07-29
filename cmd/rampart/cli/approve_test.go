package cli

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

func TestResolveTokenForEndpoint(t *testing.T) {
	// Use temp dir as HOME to avoid picking up real ~/.rampart/token
	testSetHome(t, t.TempDir())
	t.Setenv("RAMPART_TOKEN", "env-tok")

	if got, source, err := resolveTokenForEndpoint("http://localhost:9090", "explicit"); err != nil || got != "explicit" || source != "flag" {
		t.Errorf("explicit token = %q/%q err=%v", got, source, err)
	}
	if got, source, err := resolveTokenForEndpoint("http://localhost:9090", ""); err != nil || got != "env-tok" || source != "env" {
		t.Errorf("environment token = %q/%q err=%v", got, source, err)
	}

	os.Unsetenv("RAMPART_TOKEN")
	if got, source, err := resolveTokenForEndpoint("http://localhost:9090", ""); err != nil || got != "" || source != "" {
		t.Errorf("empty token = %q/%q err=%v", got, source, err)
	}
}

func TestResolveApprovalRefusesRemotePersistedTokenBeforeRequest(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("RAMPART_TOKEN", "")
	if err := os.MkdirAll(filepath.Join(home, ".rampart"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".rampart", "token"), []byte("persisted-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	requests := 0
	previousClient := rampartHTTPClient
	t.Cleanup(func() { rampartHTTPClient = previousClient })
	rampartHTTPClient = newRampartHTTPClient(0)
	rampartHTTPClient.Transport = redirectTestTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, fmt.Errorf("unexpected request")
	})

	cmd := &cobra.Command{}
	err := resolveApproval(cmd, "https://attacker.example", "", "0123456789", true)
	if err == nil || !strings.Contains(err.Error(), "auto-discovered token") {
		t.Fatalf("resolveApproval error = %v, want persisted-token refusal", err)
	}
	if requests != 0 {
		t.Fatalf("sent %d request(s) before rejecting unsafe credentials", requests)
	}
}

func TestResolveAddr(t *testing.T) {
	defaultAddr := fmt.Sprintf("http://localhost:%d", defaultServePort)

	t.Run("empty addr falls back to default", func(t *testing.T) {
		os.Unsetenv("RAMPART_API")
		os.Unsetenv("RAMPART_URL")
		os.Unsetenv("RAMPART_SERVE_URL")
		if got, err := resolveAddr(""); err != nil || got != defaultAddr {
			t.Fatalf("got %q err=%v", got, err)
		}
	})

	t.Run("empty addr uses RAMPART_API override", func(t *testing.T) {
		t.Setenv("RAMPART_API", "http://custom:1234/")
		if got, err := resolveAddr(""); err != nil || got != "http://custom:1234" {
			t.Fatalf("got %q err=%v", got, err)
		}
	})

	t.Run("empty addr uses serve url resolution chain", func(t *testing.T) {
		os.Unsetenv("RAMPART_API")
		t.Setenv("RAMPART_URL", "http://proxy:7777/")
		if got, err := resolveAddr(""); err != nil || got != "http://proxy:7777" {
			t.Fatalf("got %q err=%v", got, err)
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
		if got, err := resolveAddr(""); err != nil || got != "http://config-api:8123" {
			t.Fatalf("got %q err=%v", got, err)
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
		if got, err := resolveAddr(""); err != nil || got != "http://compat-serve:8124" {
			t.Fatalf("got %q err=%v", got, err)
		}
	})

	t.Run("explicit addr wins", func(t *testing.T) {
		t.Setenv("RAMPART_API", "http://custom:1234")
		if got, err := resolveAddr("http://other:5678"); err != nil || got != "http://other:5678" {
			t.Fatalf("got %q err=%v", got, err)
		}
	})

	t.Run("invalid config surfaces error", func(t *testing.T) {
		home := t.TempDir()
		testSetHome(t, home)
		os.Unsetenv("RAMPART_API")
		os.Unsetenv("RAMPART_URL")
		os.Unsetenv("RAMPART_SERVE_URL")
		if err := os.MkdirAll(filepath.Join(home, ".rampart"), 0o755); err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(home, ".rampart", "config.yaml")
		if err := os.WriteFile(cfgPath, []byte("serveUrl: http://typo\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveAddr(""); err == nil {
			t.Fatal("expected config parse error")
		}
	})
}
