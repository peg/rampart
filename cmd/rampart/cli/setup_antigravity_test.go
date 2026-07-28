// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupAntigravityCreatesManagedPluginAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	for i := 0; i < 2; i++ {
		if err := testExecuteRoot(t, "setup", "antigravity"); err != nil {
			t.Fatalf("setup iteration %d: %v", i+1, err)
		}
	}
	pluginDir := antigravityPluginDir(home)
	if !antigravityPluginConfiguredForHome(home) {
		t.Fatal("installed Antigravity plugin was not detected")
	}
	manifest := testReadJSONMap(t, filepath.Join(pluginDir, "plugin.json"))
	if manifest["name"] != "rampart" {
		t.Fatalf("manifest name = %#v", manifest["name"])
	}
	hooks := testReadJSONMap(t, filepath.Join(pluginDir, "hooks.json"))
	policy := hooks["rampart-policy"].(map[string]any)
	if _, exists := policy["PostToolUse"]; exists {
		t.Fatal("PostToolUse must not be installed without a result-bearing host payload")
	}
	entries := policy["PreToolUse"].([]any)
	matcher := entries[0].(map[string]any)
	if matcher["matcher"] != "*" {
		t.Fatalf("matcher = %#v", matcher["matcher"])
	}
	handler := matcher["hooks"].([]any)[0].(map[string]any)
	if !strings.Contains(handler["command"].(string), "hook --format antigravity") || handler["timeout"] != float64(330) {
		t.Fatalf("handler = %#v", handler)
	}
}

func TestSetupAntigravityRefusesAndForceReplacesUnmanagedPlugin(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	pluginDir := antigravityPluginDir(home)
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(`{"name":"someone-else"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := testExecuteRoot(t, "setup", "antigravity"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("unmanaged plugin error = %v", err)
	}
	if err := testExecuteRoot(t, "setup", "antigravity", "--force"); err != nil {
		t.Fatalf("force setup: %v", err)
	}
	if !antigravityPluginManaged(pluginDir) {
		t.Fatal("forced replacement is not managed")
	}
}

func TestSetupAntigravityRemoveRefusesUnmanagedAndRemovesManaged(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	pluginDir := antigravityPluginDir(home)
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(`{"name":"someone-else"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := testExecuteRoot(t, "setup", "antigravity", "--remove"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("unmanaged remove error = %v", err)
	}
	if err := testExecuteRoot(t, "setup", "antigravity", "--force"); err != nil {
		t.Fatal(err)
	}
	if err := testExecuteRoot(t, "setup", "agy", "--remove"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pluginDir); !os.IsNotExist(err) {
		t.Fatalf("plugin directory still exists: %v", err)
	}
}

func TestAntigravityManagedDetectionRequiresExpectedSchema(t *testing.T) {
	data := []byte(`{"rampart-policy":{"note":"hook --format antigravity"}}`)
	if antigravityHookDataManaged(data) {
		t.Fatal("a marker string outside the expected hook schema must not establish ownership")
	}
}
