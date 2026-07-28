// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
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
	      {"matcher":"Bash","hooks":[{"type":"command","command":"user-policy"}]}
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
	if len(hooks["SessionStart"].([]any)) != 1 {
		t.Fatal("unrelated SessionStart hooks were not preserved")
	}
	assertRampartCodexHook(t, settings, "PreToolUse")
	assertRampartCodexHook(t, settings, "PostToolUse")
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
