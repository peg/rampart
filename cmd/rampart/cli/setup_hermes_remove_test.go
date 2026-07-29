// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	hermesplugin "github.com/peg/rampart/internal/plugin/hermes"
	"gopkg.in/yaml.v3"
)

func TestRemoveHermesIntegrationPreservesUnrelatedStateAndIsIdempotent(t *testing.T) {
	hermesHome := t.TempDir()
	pluginDir := filepath.Join(hermesHome, "plugins", "rampart")
	if err := hermesplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	userFile := filepath.Join(pluginDir, "operator-notes.txt")
	if err := os.WriteFile(userFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	memoryPath := filepath.Join(hermesHome, "memories", "profile.md")
	if err := os.MkdirAll(filepath.Dir(memoryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(memoryPath, []byte("important memory"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(hermesHome, "config.yaml")
	config := `model: keep/model
plugins:
  enabled: [other, rampart]
  disabled: [paused, rampart]
  entries:
    other:
      config:
        keep: true
    rampart:
      config:
        serve_url: http://127.0.0.1:9090
sessions:
  write_json_snapshots: true
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)

	}
	removed, err := removeHermesIntegration(pluginDir, hermesHome)
	if err != nil || !removed {
		t.Fatalf("removeHermesIntegration() = (%v, %v), want (true, nil)", removed, err)
	}
	for _, name := range []string{"__init__.py", "plugin.yaml"} {
		if _, err := os.Stat(filepath.Join(pluginDir, name)); !os.IsNotExist(err) {
			t.Fatalf("managed Hermes file %s still exists: %v", name, err)
		}
	}
	if data, err := os.ReadFile(userFile); err != nil || string(data) != "keep" {
		t.Fatalf("user plugin file changed: data=%q err=%v", data, err)
	}
	if data, err := os.ReadFile(memoryPath); err != nil || string(data) != "important memory" {
		t.Fatalf("Hermes memory changed: data=%q err=%v", data, err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	plugins := got["plugins"].(map[string]any)
	for _, key := range []string{"enabled", "disabled"} {
		for _, raw := range plugins[key].([]any) {
			if raw == "rampart" {
				t.Fatalf("plugins.%s still contains rampart: %#v", key, plugins[key])
			}
		}
	}
	entries := plugins["entries"].(map[string]any)
	if _, exists := entries["rampart"]; exists {
		t.Fatalf("plugins.entries.rampart still exists: %#v", entries)
	}
	if _, exists := entries["other"]; !exists || got["model"] != "keep/model" {
		t.Fatalf("unrelated Hermes config changed: %#v", got)
	}

	afterFirst, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	removed, err = removeHermesIntegration(pluginDir, hermesHome)
	if err != nil || removed {
		t.Fatalf("second remove = (%v, %v), want (false, nil)", removed, err)
	}
	afterSecond, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterFirst, afterSecond) {
		t.Fatal("idempotent Hermes removal rewrote config")
	}
}

func TestRemoveHermesIntegrationRefusesUnmanagedPlugin(t *testing.T) {
	hermesHome := t.TempDir()
	pluginDir := filepath.Join(hermesHome, "plugins", "rampart")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := []byte("name: rampart\nauthor: someone-else\nprovides_hooks: [pre_tool_call]\n")
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "__init__.py"), []byte("def register(ctx): pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(hermesHome, "config.yaml")
	before := []byte("plugins:\n  enabled: [rampart]\n")
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := removeHermesIntegration(pluginDir, hermesHome); err == nil {
		t.Fatal("expected unmanaged plugin ownership refusal")
	}
	if data, err := os.ReadFile(configPath); err != nil || !bytes.Equal(data, before) {
		t.Fatalf("Hermes config changed after refusal: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(pluginDir, "__init__.py")); err != nil {
		t.Fatalf("unmanaged plugin was removed: %v", err)
	}
}

func TestRemoveHermesIntegrationRefusesConfigOnlyIdentity(t *testing.T) {
	hermesHome := t.TempDir()
	pluginDir := filepath.Join(hermesHome, "plugins", "rampart")
	configPath := filepath.Join(hermesHome, "config.yaml")
	before := []byte("plugins:\n  enabled: [rampart]\n  entries:\n    rampart:\n      config: {}\n")
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := removeHermesIntegration(pluginDir, hermesHome); err == nil || !strings.Contains(err.Error(), "config-only") {
		t.Fatalf("expected config-only ownership refusal, got %v", err)
	}
	if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("Hermes config changed after refusal: data=%q err=%v", after, err)
	}
}

func TestRemoveHermesIntegrationRefusesSymlinkedPluginDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlink creation requires privileges on many Windows hosts")
	}
	hermesHome := t.TempDir()
	targetDir := filepath.Join(t.TempDir(), "rampart")
	if err := hermesplugin.Extract(targetDir); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(hermesHome, "plugins", "rampart")
	if err := os.MkdirAll(filepath.Dir(pluginDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, pluginDir); err != nil {
		t.Fatal(err)
	}

	if _, err := removeHermesIntegration(pluginDir, hermesHome); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("expected symlink ownership refusal, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "__init__.py")); err != nil {
		t.Fatalf("symlink target was changed: %v", err)
	}
}

func TestHermesFailOpenToolsDefaultIsFailClosed(t *testing.T) {
	if got := hermesFailOpenTools(nil); len(got) != 0 {
		t.Fatalf("hermesFailOpenTools(nil) = %v, want no implicit fail-open tools", got)
	}
	if got := hermesFailOpenTools(map[string]any{}); len(got) != 0 {
		t.Fatalf("hermesFailOpenTools(empty) = %v, want no implicit fail-open tools", got)
	}
}

func TestHermesHomeHonoredAcrossSetupStatusAndRemove(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hermesHome := filepath.Join(home, "custom-hermes")
	t.Setenv("HERMES_HOME", hermesHome)

	install := newSetupHermesCmd()
	install.SetOut(&bytes.Buffer{})
	install.SetErr(&bytes.Buffer{})
	if err := install.Execute(); err != nil {
		t.Fatalf("setup hermes: %v", err)
	}
	pluginDir := filepath.Join(hermesHome, "plugins", "rampart")
	if !hermesPluginFilesInstalled(pluginDir) {
		t.Fatalf("Hermes plugin was not installed at %s", pluginDir)
	}
	if _, err := os.Stat(filepath.Join(home, ".hermes", "plugins", "rampart")); !os.IsNotExist(err) {
		t.Fatalf("default Hermes home unexpectedly used: %v", err)
	}

	config := []byte("plugins:\n  enabled: [rampart]\n")
	if err := os.WriteFile(filepath.Join(hermesHome, "config.yaml"), config, 0o600); err != nil {
		t.Fatal(err)
	}
	state := detectHermesPluginStateForHome(home)
	if !state.Installed || !state.Enabled || !state.ManifestValid || !state.HookDeclared || state.PluginDir != pluginDir {
		t.Fatalf("custom Hermes state = %#v", state)
	}
	if !hermesRampartIntegrationPresent(home) {
		t.Fatal("uninstall detection did not recognize custom Hermes home")
	}

	remove := newSetupHermesCmd()
	remove.SetArgs([]string{"--remove"})
	remove.SetOut(&bytes.Buffer{})
	remove.SetErr(&bytes.Buffer{})
	if err := remove.Execute(); err != nil {
		t.Fatalf("remove hermes: %v", err)
	}
	if hermesPluginFilesInstalled(pluginDir) || hermesRampartIntegrationPresent(home) {
		t.Fatal("custom Hermes integration remained after removal")
	}
}
