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

func TestSetupGeminiPreservesSettingsAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	settingsPath := filepath.Join(home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := `{
  "theme":"GitHub",
  "hooks":{
    "BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":"user-policy"}]}],
    "SessionStart":[{"hooks":[{"type":"command","command":"notes"}]}]
  }
}`
	if err := os.WriteFile(settingsPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
		cmd.SetArgs([]string{"setup", "gemini"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("setup iteration %d: %v", i+1, err)
		}
	}

	settings := readGeminiSettings(t, settingsPath)
	if settings["theme"] != "GitHub" {
		t.Fatalf("theme was not preserved: %#v", settings["theme"])
	}
	hooks := settings["hooks"].(map[string]any)
	if len(hooks["BeforeTool"].([]any)) != 2 {
		t.Fatalf("BeforeTool should contain the user hook and one Rampart hook: %#v", hooks["BeforeTool"])
	}
	if len(hooks["SessionStart"].([]any)) != 1 {
		t.Fatal("unrelated SessionStart hook was not preserved")
	}
	assertRampartGeminiHook(t, settings, "BeforeTool")
	assertRampartGeminiHook(t, settings, "AfterTool")
	if !geminiHooksConfiguredForHome(home) {
		t.Fatal("installed Gemini hooks were not detected")
	}
}

func TestSetupGeminiRemovePreservesUnrelatedHooks(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	setup := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	setup.SetArgs([]string{"setup", "gemini"})
	if err := setup.Execute(); err != nil {
		t.Fatal(err)
	}

	settingsPath := filepath.Join(home, ".gemini", "settings.json")
	settings := readGeminiSettings(t, settingsPath)
	hooks := settings["hooks"].(map[string]any)
	hooks["BeforeTool"] = append(hooks["BeforeTool"].([]any), map[string]any{
		"matcher": "run_shell_command",
		"hooks":   []any{map[string]any{"type": "command", "command": "user-policy"}},
	})
	if err := writeGeminiSettings(settingsPath, settings); err != nil {
		t.Fatal(err)
	}

	remove := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	remove.SetArgs([]string{"setup", "gemini", "--remove"})
	if err := remove.Execute(); err != nil {
		t.Fatal(err)
	}
	settings = readGeminiSettings(t, settingsPath)
	hooks = settings["hooks"].(map[string]any)
	if _, exists := hooks["AfterTool"]; exists {
		t.Fatal("Rampart-only AfterTool group remained")
	}
	entries := hooks["BeforeTool"].([]any)
	if len(entries) != 1 || isRampartGeminiMatcher(entries[0].(map[string]any)) {
		t.Fatalf("unrelated BeforeTool hook was not preserved: %#v", entries)
	}
}

func TestSetupGeminiInvalidJSONRequiresForce(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	settingsPath := filepath.Join(home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "gemini"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("invalid JSON error = %v, want --force guidance", err)
	}
	cmd = NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "gemini", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("force setup: %v", err)
	}
	assertRampartGeminiHook(t, readGeminiSettings(t, settingsPath), "BeforeTool")
}

func readGeminiSettings(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	return settings
}

func assertRampartGeminiHook(t *testing.T, settings map[string]any, event string) {
	t.Helper()
	hooks := settings["hooks"].(map[string]any)
	entries := hooks[event].([]any)
	found := 0
	for _, entry := range entries {
		matcher := entry.(map[string]any)
		if !isRampartGeminiMatcher(matcher) {
			continue
		}
		found++
		if matcher["matcher"] != ".*" {
			t.Fatalf("%s matcher = %#v, want .*", event, matcher["matcher"])
		}
		handler := matcher["hooks"].([]any)[0].(map[string]any)
		if !strings.Contains(handler["command"].(string), "hook --format gemini") {
			t.Fatalf("%s command = %#v", event, handler["command"])
		}
		if handler["timeout"] != float64(330000) {
			t.Fatalf("%s timeout = %#v", event, handler["timeout"])
		}
	}
	if found != 1 {
		t.Fatalf("%s Rampart entries = %d, want 1", event, found)
	}
}
