package cli

import (
	"os"
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
	// Default addr, no env
	os.Unsetenv("RAMPART_API")
	if got := resolveAddr("http://127.0.0.1:9091"); got != "http://127.0.0.1:9091" {
		t.Errorf("got %q", got)
	}

	// Default addr, with env override
	t.Setenv("RAMPART_API", "http://custom:1234")
	if got := resolveAddr("http://127.0.0.1:9091"); got != "http://custom:1234" {
		t.Errorf("got %q", got)
	}

	// Non-default addr, env should not override
	if got := resolveAddr("http://other:5678"); got != "http://other:5678" {
		t.Errorf("got %q", got)
	}
}
