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

func TestSetupAntigravityCreatesManagedPluginAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	for i := 0; i < 2; i++ {
		cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
		cmd.SetArgs([]string{"setup", "antigravity"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("setup iteration %d: %v", i+1, err)
		}
	}
	pluginDir := antigravityPluginDir(home)
	if !antigravityPluginConfiguredForHome(home) {
		t.Fatal("installed Antigravity plugin was not detected")
	}
	manifest := readJSONMap(t, filepath.Join(pluginDir, "plugin.json"))
	if manifest["name"] != "rampart" {
		t.Fatalf("manifest name = %#v", manifest["name"])
	}
	hooks := readJSONMap(t, filepath.Join(pluginDir, "hooks.json"))
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
	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "antigravity"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("unmanaged plugin error = %v", err)
	}
	cmd = NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "antigravity", "--force"})
	if err := cmd.Execute(); err != nil {
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
	remove := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	remove.SetArgs([]string{"setup", "antigravity", "--remove"})
	if err := remove.Execute(); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("unmanaged remove error = %v", err)
	}
	setup := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	setup.SetArgs([]string{"setup", "antigravity", "--force"})
	if err := setup.Execute(); err != nil {
		t.Fatal(err)
	}
	remove = NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	remove.SetArgs([]string{"setup", "agy", "--remove"})
	if err := remove.Execute(); err != nil {
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

func readJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
