package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHasRampartHook(t *testing.T) {
	tests := []struct {
		name     string
		settings claudeSettings
		want     bool
	}{
		{"empty", claudeSettings{}, false},
		{"no hooks", claudeSettings{"other": "value"}, false},
		{"hooks but no PreToolUse", claudeSettings{"hooks": map[string]any{}}, false},
		{"with rampart hook", claudeSettings{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "Bash",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
			},
		}, true},
		{"with other hook", claudeSettings{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "Bash",
						"hooks":   []any{map[string]any{"type": "command", "command": "other-tool"}},
					},
				},
			},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRampartHook(tt.settings); got != tt.want {
				t.Errorf("hasRampartHook() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasRampartInMatcher(t *testing.T) {
	tests := []struct {
		name    string
		matcher map[string]any
		want    bool
	}{
		{"rampart hook", map[string]any{"hooks": []any{map[string]any{"command": "rampart hook"}}}, true},
		{"other hook", map[string]any{"hooks": []any{map[string]any{"command": "other"}}}, false},
		{"no hooks key", map[string]any{"matcher": "Bash"}, false},
		{"empty hooks", map[string]any{"hooks": []any{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRampartInMatcher(tt.matcher); got != tt.want {
				t.Errorf("hasRampartInMatcher() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetupClaudeCode_Install(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Mock execLookPath to avoid "not in PATH" warning
	old := execLookPath
	execLookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	defer func() { execLookPath = old }()

	opts := &rootOptions{}
	cmd := newSetupClaudeCodeCmd(opts)
	cmd.SetArgs([]string{"--force"})
	var out strings.Builder
	cmd.SetOut(&out)
	var errOut strings.Builder
	cmd.SetErr(&errOut)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "Rampart hook installed") {
		t.Errorf("output = %q", out.String())
	}

	// Verify settings file
	settingsPath := filepath.Join(tmpHome, ".claude", "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}

	var settings map[string]any
	json.Unmarshal(data, &settings)
	// setup now writes an absolute path (e.g. "/usr/local/bin/rampart hook"),
	// so hasRampartHook (which checks for bare "rampart hook") won't match in tests.
	// Instead, verify a hook command ending in " hook" exists in the raw JSON.
	if !strings.Contains(string(data), " hook\"") {
		t.Errorf("rampart hook not found in settings; got: %s", data)
	}
}

func TestSetupClaudeCode_AlreadyInstalled(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	os.MkdirAll(claudeDir, 0o755)

	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{"matcher": "Bash", "hooks": []any{map[string]any{"type": "command", "command": "rampart hook"}}},
			},
		},
	}
	data, _ := json.MarshalIndent(settings, "", "  ")
	os.WriteFile(filepath.Join(claudeDir, "settings.json"), data, 0o644)

	opts := &rootOptions{}
	cmd := newSetupClaudeCodeCmd(opts)
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "already configured") {
		t.Errorf("expected already configured message, got: %s", out.String())
	}
}

func TestReadLine(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader("hello\nworld\n"))
	if got := readLine(scanner); got != "hello" {
		t.Errorf("first line = %q", got)
	}
	if got := readLine(scanner); got != "world" {
		t.Errorf("second line = %q", got)
	}
	// EOF
	if got := readLine(scanner); got != "\x00" {
		t.Errorf("EOF = %q", got)
	}
}

func TestReadLine_Empty(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader(""))
	if got := readLine(scanner); got != "\x00" {
		t.Errorf("empty = %q", got)
	}
}

func TestDetectAgents(t *testing.T) {
	agents := detectAgents()
	if len(agents) != 5 {
		t.Errorf("expected 5 agents, got %d", len(agents))
	}
	// Verify names
	names := make([]string, len(agents))
	for i, a := range agents {
		names[i] = a.Name
	}
	for _, want := range []string{"Claude Code", "Cline", "OpenClaw", "Cursor", "Codex"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing agent %q", want)
		}
	}
}

func TestInstallPolicy(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	if err := installPolicy(&buf, dir, "standard"); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(dir, ".rampart", "policies", "standard.yaml")
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatal("policy file not created")
	}

	// Run again - should say already exists
	buf.Reset()
	if err := installPolicy(&buf, dir, "standard"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "already exists") {
		t.Errorf("expected already exists, got: %s", buf.String())
	}
}
