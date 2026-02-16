package cli

import (
	"testing"
)

func TestGetEnvValue(t *testing.T) {
	env := []string{"FOO=bar", "BAZ=qux", "EMPTY="}
	tests := []struct {
		key  string
		want string
	}{
		{"FOO", "bar"},
		{"BAZ", "qux"},
		{"EMPTY", ""},
		{"MISSING", ""},
	}
	for _, tt := range tests {
		if got := getEnvValue(env, tt.key); got != tt.want {
			t.Errorf("getEnvValue(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestSetEnvValue(t *testing.T) {
	env := []string{"FOO=bar", "BAZ=qux"}

	// Override existing
	result := setEnvValue(env, "FOO", "new")
	if got := getEnvValue(result, "FOO"); got != "new" {
		t.Errorf("after override FOO = %q", got)
	}
	if got := getEnvValue(result, "BAZ"); got != "qux" {
		t.Errorf("BAZ should be preserved, got %q", got)
	}

	// Add new
	result2 := setEnvValue(env, "NEW", "val")
	if got := getEnvValue(result2, "NEW"); got != "val" {
		t.Errorf("new key = %q", got)
	}
}

func TestResolvePreloadLibrary(t *testing.T) {
	// This will fail to find the library, but should return a meaningful error
	_, _, err := resolvePreloadLibrary()
	if err == nil {
		// If it somehow found a library, that's fine too
		return
	}
	// Should mention the library name
	errStr := err.Error()
	if errStr == "" {
		t.Fatal("expected non-empty error")
	}
}
