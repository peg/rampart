// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupCodexInstallsNativeHooksWithoutCodexOrPreload(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())

	var stdout bytes.Buffer
	cmd := NewRootCmd(context.Background(), &stdout, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "codex"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup codex: %v", err)
	}

	settings := testReadJSONMap(t, filepath.Join(home, ".codex", "hooks.json"))
	assertRampartCodexHook(t, settings, "PreToolUse")
	assertRampartCodexHook(t, settings, "PostToolUse")
	if !strings.Contains(stdout.String(), "Open `/hooks`") {
		t.Fatalf("setup output must explain Codex hook trust:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "bin", "codex")); !os.IsNotExist(err) {
		t.Fatalf("native setup must not create a codex wrapper: %v", err)
	}
}

func TestSetupCodexHonorsCodexHome(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	codexHome := filepath.Join(home, "isolated-codex")
	t.Setenv("CODEX_HOME", codexHome)

	if err := testExecuteRoot(t, "setup", "codex"); err != nil {
		t.Fatalf("setup codex: %v", err)
	}
	assertRampartCodexHook(t, testReadJSONMap(t, filepath.Join(codexHome, "hooks.json")), "PreToolUse")
	if _, err := os.Stat(filepath.Join(home, ".codex", "hooks.json")); !os.IsNotExist(err) {
		t.Fatalf("default Codex home should remain untouched: %v", err)
	}
}

func TestCodexHomeDirExpandsPortableTildeForms(t *testing.T) {
	home := t.TempDir()
	tests := []struct {
		name       string
		configured string
		want       string
	}{
		{name: "tilde only", configured: "~", want: home},
		{name: "slash", configured: "~/isolated-codex", want: filepath.Join(home, "isolated-codex")},
		{name: "backslash", configured: `~\isolated-codex`, want: filepath.Join(home, "isolated-codex")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CODEX_HOME", tt.configured)
			if got := codexHomeDir(home); got != tt.want {
				t.Fatalf("codexHomeDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetupCodexPreservesOtherHooksAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := `{
	  "description": "user hooks",
	  "hooks": {
	    "PreToolUse": [
	      {"matcher":"Bash","hooks":[{"type":"command","command":"user-policy"},{"type":"command","command":"notify hook --format codex --dry-run"}]}
	    ],
	    "SessionStart": [
	      {"hooks":[{"type":"command","command":"session-notes"}]}
	    ]
	  }
	}`
	if err := os.WriteFile(hooksPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	for iteration := 0; iteration < 2; iteration++ {
		if err := testExecuteRoot(t, "setup", "codex"); err != nil {
			t.Fatalf("setup iteration %d: %v", iteration+1, err)
		}
	}

	settings := testReadJSONMap(t, hooksPath)
	if settings["description"] != "user hooks" {
		t.Fatalf("description was overwritten: %#v", settings["description"])
	}
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse entries = %d, want user + one Rampart entry", len(pre))
	}
	userMatcher := pre[0].(map[string]any)
	if got := len(userMatcher["hooks"].([]any)); got != 2 {
		t.Fatalf("protocol-mentioning user handler was removed: %#v", userMatcher)
	}
	if len(hooks["SessionStart"].([]any)) != 1 {
		t.Fatal("unrelated SessionStart hooks were not preserved")
	}
	assertRampartCodexHook(t, settings, "PreToolUse")
	assertRampartCodexHook(t, settings, "PostToolUse")
}

func TestSetupCodexPreservesLargeHostInteger(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooksPath, []byte(`{"hostSequence":9007199254740993}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := testExecuteRoot(t, "setup", "codex"); err != nil {
		t.Fatalf("setup codex: %v", err)
	}
	data, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := decodeUserJSON(data, &settings); err != nil {
		t.Fatal(err)
	}
	sequence, ok := settings["hostSequence"].(json.Number)
	if !ok || sequence.String() != "9007199254740993" {
		t.Fatalf("unrelated large integer changed: %#v", settings["hostSequence"])
	}
}

func TestSetupCodexRefreshesStaleCommandsBeforeReportingConfigured(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	oldLookPath := execLookPath
	oldExecutable := osExecutable
	execLookPath = func(name string) (string, error) { return filepath.Join(home, "bin", name), nil }
	osExecutable = func() (string, error) { return filepath.Join(home, "bin", "rampart"), nil }
	defer func() {
		execLookPath = oldLookPath
		osExecutable = oldExecutable
	}()

	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"'/old/rampart' hook --format codex","commandWindows":"\"C:\\\\old\\\\rampart.exe\" hook --format codex"}]}],"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"'/old/rampart' hook --format codex","commandWindows":"\"C:\\\\old\\\\rampart.exe\" hook --format codex"}]}]}}`
	if err := os.WriteFile(hooksPath, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if codexHooksConfiguredForHome(home) {
		t.Fatal("stale Codex hook commands must not be reported as currently configured")
	}
	if check := verifyCodexHooksInstalled(); check.Status != verificationFail || !strings.Contains(check.Actual, "stale") {
		t.Fatalf("stale Codex verification = %#v", check)
	}

	if err := testExecuteRoot(t, "setup", "codex"); err != nil {
		t.Fatal(err)
	}
	if !codexHooksConfiguredForHome(home) {
		t.Fatal("refreshed Codex hook commands were not reported as configured")
	}
	if check := verifyCodexHooksInstalled(); check.Status != verificationPass {
		t.Fatalf("refreshed Codex verification = %#v", check)
	}
}

func TestSetupCodexMigratesAndRemovesManagedWrapper(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	wrapperPath := filepath.Join(home, ".local", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(wrapperPath), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/bin/sh\n# Rampart wrapper for Codex\nexec rampart preload -- /usr/bin/codex \"$@\"\n"
	if err := os.WriteFile(wrapperPath, []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	cmd := NewRootCmd(context.Background(), &stdout, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "codex"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wrapperPath); !os.IsNotExist(err) {
		t.Fatalf("managed wrapper was not removed: %v", err)
	}
	if !strings.Contains(stdout.String(), "Removed legacy preload wrapper") {
		t.Fatalf("migration was not reported:\n%s", stdout.String())
	}
}

func TestSetupCodexRemovePreservesUnrelatedHooks(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"user-policy"}]}]}}`
	if err := os.WriteFile(hooksPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := testExecuteRoot(t, "setup", "codex"); err != nil {
		t.Fatal(err)
	}

	if err := testExecuteRoot(t, "setup", "codex", "--remove"); err != nil {
		t.Fatal(err)
	}

	settings := testReadJSONMap(t, hooksPath)
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("PreToolUse entries = %d, want one user hook", len(pre))
	}
	if isRampartCodexMatcher(pre[0].(map[string]any)) {
		t.Fatal("Rampart hook remained after removal")
	}
	if _, ok := hooks["PostToolUse"]; ok {
		t.Fatal("empty Rampart-only PostToolUse group remained after removal")
	}
}

func TestSetupCodexPreservesHandlersSharingRampartMatcher(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := `{"hooks":{"PreToolUse":[{"matcher":"*","note":"preserve","hooks":[{"type":"command","command":"user-policy"},{"type":"command","command":"'/retired/rampart' hook --format codex"}]}]}}`
	if err := os.WriteFile(hooksPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := testExecuteRoot(t, "setup", "codex"); err != nil {
		t.Fatal(err)
	}
	settings := testReadJSONMap(t, hooksPath)
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse entries = %d, want preserved user matcher + current Rampart matcher", len(pre))
	}
	preserved := pre[0].(map[string]any)
	if preserved["note"] != "preserve" {
		t.Fatalf("shared matcher metadata was lost: %#v", preserved)
	}
	handlers := preserved["hooks"].([]any)
	if len(handlers) != 1 || handlers[0].(map[string]any)["command"] != "user-policy" {
		t.Fatalf("shared matcher handlers were not narrowed safely: %#v", handlers)
	}

	if err := testExecuteRoot(t, "setup", "codex", "--remove"); err != nil {
		t.Fatal(err)
	}
	settings = testReadJSONMap(t, hooksPath)
	hooks = settings["hooks"].(map[string]any)
	pre = hooks["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("PreToolUse entries after remove = %d, want preserved user matcher", len(pre))
	}
	preserved = pre[0].(map[string]any)
	handlers = preserved["hooks"].([]any)
	if preserved["note"] != "preserve" || len(handlers) != 1 || handlers[0].(map[string]any)["command"] != "user-policy" {
		t.Fatalf("uninstall changed the shared user matcher: %#v", preserved)
	}
}

func TestSetupCodexInvalidJSONRequiresForce(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooksPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := testExecuteRoot(t, "setup", "codex"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("invalid JSON error = %v, want --force guidance", err)
	}

	if err := testExecuteRoot(t, "setup", "codex", "--force"); err != nil {
		t.Fatalf("force setup: %v", err)
	}
	assertRampartCodexHook(t, testReadJSONMap(t, hooksPath), "PreToolUse")
}

func TestSetupCodexInvalidHookShapeRequiresForce(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooksPath, []byte(`{"hooks":{"PreToolUse":"user-value"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := testExecuteRoot(t, "setup", "codex"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("invalid hook shape error = %v, want --force guidance", err)
	}

	if err := testExecuteRoot(t, "setup", "codex", "--force"); err != nil {
		t.Fatalf("force setup: %v", err)
	}
	assertRampartCodexHook(t, testReadJSONMap(t, hooksPath), "PreToolUse")
}

func TestCodexInstallAndRemoveRefuseSymlinkedHooksFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "operator-hooks.json")
	initial := []byte(`{"hooks":{"SessionStart":[]}}`)
	if err := os.WriteFile(target, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hooks.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := installCodexHooks(path, "rampart hook --format codex", "rampart.exe hook --format codex", false); err == nil || !strings.Contains(err.Error(), "linked") {
		t.Fatalf("install error = %v, want symlink refusal", err)
	}
	if removed, err := removeCodexHooks(path); err == nil || removed || !strings.Contains(err.Error(), "linked") {
		t.Fatalf("remove = (%v, %v), want symlink refusal", removed, err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("hooks symlink was replaced: info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != string(initial) {
		t.Fatalf("hooks target changed: data=%q err=%v", data, err)
	}
}

func TestCodexConfiguredRequiresFullMatcherCoverage(t *testing.T) {
	command, commandWindows := currentCodexHookCommands()
	handler := map[string]any{
		"type": "command", "command": command, "commandWindows": commandWindows,
	}
	settings := map[string]any{"hooks": map[string]any{
		"PreToolUse":  []any{map[string]any{"matcher": "Bash", "hooks": []any{handler}}},
		"PostToolUse": []any{map[string]any{"matcher": "*", "hooks": []any{handler}}},
	}}
	if codexHooksUseCommands(settings, command, commandWindows) {
		t.Fatal("an exact command under a narrowed matcher must not establish complete protection")
	}
}

func TestCodexOwnershipRejectsOtherProtocolExecutable(t *testing.T) {
	handler := map[string]any{
		"command":        "notify hook --format codex",
		"commandWindows": `& "C:\Tools\notify.exe" hook --format codex`,
	}
	if isRampartCodexHandler(handler) {
		t.Fatal("unrelated executable was claimed as a Rampart Codex handler")
	}
}

func assertRampartCodexHook(t *testing.T, settings map[string]any, event string) {
	t.Helper()
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("missing hooks object: %#v", settings)
	}
	entries, ok := hooks[event].([]any)
	if !ok {
		t.Fatalf("missing %s entries: %#v", event, hooks)
	}
	found := 0
	for _, entry := range entries {
		matcher, ok := entry.(map[string]any)
		if !ok || !isRampartCodexMatcher(matcher) {
			continue
		}
		found++
		if matcher["matcher"] != "*" {
			t.Fatalf("%s matcher = %#v, want *", event, matcher["matcher"])
		}
		handlers := matcher["hooks"].([]any)
		handler := handlers[0].(map[string]any)
		if !strings.Contains(handler["command"].(string), "hook --format codex") {
			t.Fatalf("%s command = %#v", event, handler["command"])
		}
		if !strings.Contains(handler["commandWindows"].(string), "hook --format codex") {
			t.Fatalf("%s commandWindows = %#v", event, handler["commandWindows"])
		}
		if handler["timeout"] != float64(330) {
			t.Fatalf("%s timeout = %#v, want 330", event, handler["timeout"])
		}
	}
	if found != 1 {
		t.Fatalf("%s Rampart entries = %d, want 1", event, found)
	}
}
