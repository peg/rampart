package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests cover a fail-open defect in the Claude Code integration: the
// installed hook carried no onFailure option, so when the hook could not run
// at all — binary missing, moved, renamed, or not executable — Claude Code
// treated it as a non-blocking error and carried out the tool call unchecked.
// Rampart enforced nothing and recorded nothing. The installed config must
// now pin onFailure to "block", and an install written without it must be
// treated as stale so it is rewritten rather than left fail-open.

// claudeSetupInTempHome runs `setup claude-code` against a throwaway HOME and
// returns the settings path and the command's stdout.
func claudeSetupInTempHome(t *testing.T, home string, args ...string) (string, string) {
	t.Helper()
	testSetHome(t, home)

	oldLookPath := execLookPath
	execLookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	t.Cleanup(func() { execLookPath = oldLookPath })

	cmd := newSetupClaudeCodeCmd(&rootOptions{})
	cmd.SetArgs(args)
	var out, errOut strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup claude-code: %v (stderr: %s)", err, errOut.String())
	}
	return filepath.Join(home, ".claude", "settings.json"), out.String()
}

// readRampartHookEntries returns every Rampart-owned hook object recorded for
// the given lifecycle event.
func readRampartHookEntries(t *testing.T, settingsPath, event string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("settings has no hooks object: %s", data)
	}
	entries, ok := hooks[event].([]any)
	if !ok {
		t.Fatalf("settings has no %s array: %s", event, data)
	}
	var found []map[string]any
	for _, rawMatcher := range entries {
		matcher, ok := rawMatcher.(map[string]any)
		if !ok {
			continue
		}
		rawHooks, _ := matcher["hooks"].([]any)
		for _, rawHook := range rawHooks {
			hook, ok := rawHook.(map[string]any)
			if !ok {
				continue
			}
			if command, _ := hook["command"].(string); isRampartClaudeHookCommand(command) {
				found = append(found, hook)
			}
		}
	}
	return found
}

// failOpenClaudeSettings builds the configuration Rampart used to install:
// current in every respect except that it carries no onFailure option.
func failOpenClaudeSettings(command string) map[string]any {
	hook := map[string]any{
		"type":    "command",
		"command": command,
	}
	matcher := []any{map[string]any{"matcher": ".*", "hooks": []any{hook}}}
	return map[string]any{
		"hooks": map[string]any{
			"PreToolUse":         matcher,
			"PostToolUse":        matcher,
			"PostToolUseFailure": matcher,
		},
	}
}

func writeClaudeSettings(t *testing.T, home string, settings map[string]any) string {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	return path
}

// TestSetupClaudeCodeInstallsFailClosedHook pins the fix: every lifecycle hook
// Rampart installs must deny the action when the hook cannot run.
func TestSetupClaudeCodeInstallsFailClosedHook(t *testing.T) {
	settingsPath, _ := claudeSetupInTempHome(t, t.TempDir(), "--force")

	for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		entries := readRampartHookEntries(t, settingsPath, event)
		if len(entries) != 1 {
			t.Fatalf("%s: expected exactly one Rampart hook, got %d", event, len(entries))
		}
		if got := entries[0]["onFailure"]; got != claudeHookOnFailure {
			t.Errorf("%s: onFailure = %#v, want %q — a hook that cannot start must deny, not pass the call through",
				event, got, claudeHookOnFailure)
		}
	}
}

// TestClaudeHooksUseCommandRejectsFailOpenInstall covers the upgrade trigger.
// An install missing onFailure is not current, which is what makes setup
// rewrite it and `rampart verify` report drift.
func TestClaudeHooksUseCommandRejectsFailOpenInstall(t *testing.T) {
	command := currentClaudeHookCommand()

	failOpen := claudeSettings(failOpenClaudeSettings(command))
	if claudeHooksUseCommand(failOpen, command) {
		t.Error("an install without onFailure was reported as current; it would never be upgraded and would keep failing open")
	}

	current := failOpenClaudeSettings(command)
	hooks := current["hooks"].(map[string]any)
	for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		matcher := hooks[event].([]any)[0].(map[string]any)
		matcher["hooks"].([]any)[0].(map[string]any)["onFailure"] = claudeHookOnFailure
	}
	if !claudeHooksUseCommand(claudeSettings(current), command) {
		t.Error("an install with onFailure set was not reported as current; setup would rewrite it on every run")
	}
}

// TestSetupClaudeCodeUpgradesFailOpenInstall checks that an existing fail-open
// install is actually repaired by a plain `setup claude-code`, without --force
// and without duplicating lifecycle matchers.
func TestSetupClaudeCodeUpgradesFailOpenInstall(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	writeClaudeSettings(t, home, failOpenClaudeSettings(currentClaudeHookCommand()))

	settingsPath, out := claudeSetupInTempHome(t, home)
	if strings.Contains(out, "already configured") {
		t.Fatalf("setup treated a fail-open install as current and left it unrepaired: %s", out)
	}

	for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		entries := readRampartHookEntries(t, settingsPath, event)
		if len(entries) != 1 {
			t.Fatalf("%s: expected exactly one Rampart hook after upgrade, got %d", event, len(entries))
		}
		if got := entries[0]["onFailure"]; got != claudeHookOnFailure {
			t.Errorf("%s: onFailure = %#v after upgrade, want %q", event, got, claudeHookOnFailure)
		}
	}
}

// TestHasRampartHookStillDetectsFailOpenInstall guards the uninstall path:
// hasRampartHook answers "is Rampart installed at all", so it must keep
// recognising installs written before onFailure was set, or uninstall would
// silently leave them behind.
func TestHasRampartHookStillDetectsFailOpenInstall(t *testing.T) {
	settings := claudeSettings(failOpenClaudeSettings(currentClaudeHookCommand()))
	if !hasRampartHook(settings) {
		t.Error("hasRampartHook missed a pre-onFailure install; uninstall would leave it in place")
	}
}
