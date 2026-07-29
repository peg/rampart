package cli

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type redirectTestTransport func(*http.Request) (*http.Response, error)

func (f redirectTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestValidateCredentialEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		source string
		ok     bool
	}{
		{name: "localhost HTTP file", url: "http://localhost:9090", source: "file", ok: true},
		{name: "loopback IPv4 HTTP file", url: "http://127.0.0.1:9090", source: "file", ok: true},
		{name: "loopback IPv6 HTTP file", url: "http://[::1]:9090", source: "file", ok: true},
		{name: "remote HTTPS env", url: "https://rampart.example", source: "env", ok: true},
		{name: "remote HTTPS flag", url: "https://rampart.example/base", source: "flag", ok: true},
		{name: "remote HTTP env", url: "http://rampart.example", source: "env", ok: false},
		{name: "remote HTTPS file", url: "https://rampart.example", source: "file", ok: false},
		{name: "userinfo", url: "https://user@rampart.example", source: "env", ok: false},
		{name: "query", url: "https://rampart.example?redirect=evil", source: "env", ok: false},
		{name: "fragment", url: "https://rampart.example#fragment", source: "env", ok: false},
		{name: "relative", url: "rampart.example", source: "env", ok: false},
		{name: "file scheme", url: "file:///tmp/token", source: "env", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCredentialEndpoint(tt.url, tt.source)
			if (err == nil) != tt.ok {
				t.Fatalf("validateCredentialEndpoint(%q, %q) error = %v, want ok=%v", tt.url, tt.source, err, tt.ok)
			}
		})
	}
}

func TestResolveTokenForEndpointRefusesPersistedTokenForRemote(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("RAMPART_TOKEN", "")
	if err := os.MkdirAll(filepath.Join(home, ".rampart"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".rampart", "token"), []byte("persisted-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	token, source, err := resolveTokenForEndpoint("https://attacker.example", "")
	if err == nil {
		t.Fatal("expected remote persisted-token endpoint to be rejected")
	}
	if token != "" || source != "file" {
		t.Fatalf("token/source = %q/%q, want empty/file", token, source)
	}
	if !strings.Contains(err.Error(), "RAMPART_TOKEN") {
		t.Fatalf("error should explain explicit remote-token opt-in: %v", err)
	}
}

func TestRampartHTTPClientRefusesRedirectBeforeCredentialForward(t *testing.T) {
	requests := 0
	client := newRampartHTTPClient(time.Second)
	client.Transport = redirectTestTransport(func(req *http.Request) (*http.Response, error) {
		requests++
		if requests > 1 {
			t.Fatalf("credential-bearing request followed redirect to %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://attacker.example/capture"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	})

	req, err := http.NewRequest(http.MethodGet, "https://trusted.example/v1/policy", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || requests != 1 {
		t.Fatalf("status/requests = %d/%d, want 302/1", resp.StatusCode, requests)
	}
}
