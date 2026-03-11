package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
		// PreToolUse alone is not enough — PostToolUseFailure must also be present
		// so that existing installs are upgraded to include the new hook.
		{"with rampart PreToolUse only (incomplete)", claudeSettings{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "Bash",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
			},
		}, false},
		{"with both PreToolUse and PostToolUseFailure (complete)", claudeSettings{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "Bash",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
				"PostToolUseFailure": []any{
					map[string]any{
						"matcher": ".*",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
			},
		}, true},
		{"with other hook only", claudeSettings{
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
	testSetHome(t, tmpHome)

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
	if !strings.Contains(out.String(), "rampart init") {
		t.Errorf("expected init tip, got: %s", out.String())
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

func TestSetupOpenClaw_AlreadyConfiguredMessage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("openclaw setup is not supported on windows")
	}
	tmpHome := t.TempDir()
	testSetHome(t, tmpHome)

	shimPath := filepath.Join(tmpHome, ".local", "bin", "rampart-shim")
	if err := os.MkdirAll(filepath.Dir(shimPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shimPath, []byte("#!/usr/bin/env bash\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := newSetupOpenClawCmd(&rootOptions{})
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "Already configured (pass --force to reconfigure)") {
		t.Fatalf("expected already-configured message, got: %s", got)
	}
	if strings.Contains(got, "Use --force to overwrite") {
		t.Fatalf("did not expect legacy overwrite prompt, got: %s", got)
	}
}

func TestSetupClaudeCode_AlreadyInstalled(t *testing.T) {
	tmpHome := t.TempDir()
	testSetHome(t, tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	os.MkdirAll(claudeDir, 0o755)

	// Both PreToolUse and PostToolUseFailure must be present for "already configured".
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{"matcher": "Bash", "hooks": []any{map[string]any{"type": "command", "command": "rampart hook"}}},
			},
			"PostToolUseFailure": []any{
				map[string]any{"matcher": ".*", "hooks": []any{map[string]any{"type": "command", "command": "rampart hook"}}},
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
	if len(agents) != 7 {
		t.Errorf("expected 7 agents, got %d", len(agents))
	}
	// Verify names
	names := make([]string, len(agents))
	for i, a := range agents {
		names[i] = a.Name
	}
	for _, want := range []string{"Claude Code", "Cline", "OpenClaw", "Codex", "Aider", "Cursor", "Windsurf"} {
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
