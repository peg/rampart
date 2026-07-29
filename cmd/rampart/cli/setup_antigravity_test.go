// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"errors"
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
	data = []byte(`{"rampart-policy":{"enabled":true,"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify hook --format antigravity --dry-run"}]}]}}`)
	if antigravityHookDataManaged(data) {
		t.Fatal("a command that only mentions the protocol must not establish ownership")
	}
	data = []byte(`{"rampart-policy":{"enabled":true,"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify hook --format antigravity"}]}]}}`)
	if antigravityHookDataManaged(data) {
		t.Fatal("an unrelated executable implementing the exact protocol must not establish ownership")
	}
}

func TestSetupAntigravityRefreshesStaleCommandBeforeReportingConfigured(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	pluginDir := antigravityPluginDir(home)
	if err := installAntigravityPlugin(pluginDir, "'/retired/rampart' hook --format antigravity", false); err != nil {
		t.Fatal(err)
	}
	if !antigravityPluginManaged(pluginDir) {
		t.Fatal("stale plugin should remain generically owned for safe migration")
	}
	if antigravityPluginConfiguredForHome(home) {
		t.Fatal("stale Antigravity command must not be reported as currently configured")
	}
	if check := verifyAntigravityPluginInstalled(); check.Status != verificationFail || !strings.Contains(check.Actual, "stale") {
		t.Fatalf("stale Antigravity verification = %#v", check)
	}

	if err := testExecuteRoot(t, "setup", "antigravity"); err != nil {
		t.Fatal(err)
	}
	if !antigravityPluginConfiguredForHome(home) {
		t.Fatal("refreshed Antigravity command was not reported as configured")
	}
	if check := verifyAntigravityPluginInstalled(); check.Status != verificationPass {
		t.Fatalf("refreshed Antigravity verification = %#v", check)
	}
}

func TestAntigravityOwnershipRejectsAndPreservesUnexpectedFiles(t *testing.T) {
	pluginDir := filepath.Join(t.TempDir(), "plugins", "rampart")
	if err := installAntigravityPlugin(pluginDir, "rampart hook --format antigravity", false); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(pluginDir, "operator-notes.txt")
	if err := os.WriteFile(extra, []byte("preserve me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if antigravityPluginManaged(pluginDir) {
		t.Fatal("a directory containing non-Rampart files must not be claimed as wholly managed")
	}
	if err := installAntigravityPlugin(pluginDir, "'/new/rampart' hook --format antigravity", false); err == nil {
		t.Fatal("non-force setup replaced a directory containing operator data")
	}
	if removed, err := removeAntigravityPlugin(pluginDir); err == nil || removed {
		t.Fatalf("remove = (%v, %v), want ownership refusal", removed, err)
	}
	data, err := os.ReadFile(extra)
	if err != nil || string(data) != "preserve me" {
		t.Fatalf("operator file changed: data=%q err=%v", data, err)
	}
}

func TestAntigravitySetupAndRemoveRefuseSymlinkedPluginRoot(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "operator-plugin")
	if err := installAntigravityPlugin(target, "'/retired/rampart' hook --format antigravity", false); err != nil {
		t.Fatal(err)
	}
	pluginDir := antigravityPluginDir(home)
	if err := os.MkdirAll(filepath.Dir(pluginDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, pluginDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := installAntigravityPlugin(pluginDir, "'/new/rampart' hook --format antigravity", true); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("symlinked setup error = %v", err)
	}
	if removed, err := removeAntigravityPlugin(pluginDir); err == nil || removed {
		t.Fatalf("symlinked remove = (%v, %v), want refusal", removed, err)
	}
	hooks := testReadJSONMap(t, filepath.Join(target, "hooks.json"))
	policy := hooks["rampart-policy"].(map[string]any)
	matcher := policy["PreToolUse"].([]any)[0].(map[string]any)
	handler := matcher["hooks"].([]any)[0].(map[string]any)
	if !strings.Contains(handler["command"].(string), "/retired/rampart") {
		t.Fatalf("symlink target was modified: %#v", handler)
	}
}

func TestAntigravityManagedUpdateDoesNotSwapPluginDirectory(t *testing.T) {
	pluginDir := filepath.Join(t.TempDir(), "plugins", "rampart")
	if err := installAntigravityPlugin(pluginDir, "'/retired/rampart' hook --format antigravity", false); err != nil {
		t.Fatal(err)
	}
	rename := func(_, _ string) error {
		return errors.New("managed updates must not rename the plugin directory")
	}
	if err := installAntigravityPluginWithRename(
		pluginDir, "'/new/rampart' hook --format antigravity", false, rename,
	); err != nil {
		t.Fatal(err)
	}
	hooks := testReadJSONMap(t, filepath.Join(pluginDir, "hooks.json"))
	policy := hooks["rampart-policy"].(map[string]any)
	matcher := policy["PreToolUse"].([]any)[0].(map[string]any)
	handler := matcher["hooks"].([]any)[0].(map[string]any)
	if !strings.Contains(handler["command"].(string), "/new/rampart") {
		t.Fatalf("managed plugin was not updated in place: %#v", handler)
	}
}

func TestAntigravityForceInstallRestoresPriorDirectoryOnActivationFailure(t *testing.T) {
	pluginDir := filepath.Join(t.TempDir(), "plugins", "rampart")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(pluginDir, "operator-plugin.txt")
	if err := os.WriteFile(markerPath, []byte("preserve on failure"), 0o600); err != nil {
		t.Fatal(err)
	}
	rename := func(source, destination string) error {
		if filepath.Base(source) == "stage" && destination == pluginDir {
			return errors.New("injected activation failure")
		}
		return os.Rename(source, destination)
	}
	if err := installAntigravityPluginWithRename(
		pluginDir, "'/new/rampart' hook --format antigravity", true, rename,
	); err == nil || !strings.Contains(err.Error(), "injected activation failure") {
		t.Fatalf("install error = %v", err)
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil || string(marker) != "preserve on failure" {
		t.Fatalf("prior plugin directory was not restored: data=%q err=%v", marker, err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(pluginDir), ".rampart-antigravity-install-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("completed rollback left transaction directories: %v", matches)
	}
}
