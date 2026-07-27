// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
	"github.com/peg/rampart/policies"
)

func TestProtectKeepsExperimentalGeminiExplicit(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	if err := os.MkdirAll(filepath.Join(home, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"protect", "gemini", "--no-restart"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "remains experimental") || !strings.Contains(err.Error(), "rampart setup gemini") {
		t.Fatalf("error = %v, want experimental setup guidance", err)
	}
}

func TestInstallManagedGuardPolicy(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	path, err := installManagedGuardPolicy()
	if err != nil {
		t.Fatalf("installManagedGuardPolicy: %v", err)
	}
	if want := filepath.Join(home, ".rampart", "policies", "guard.yaml"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := policies.Profile("guard")
	if err != nil {
		t.Fatal(err)
	}
	if string(normalizeManagedPolicyContent(installed)) != string(embedded) {
		t.Fatal("installed Guard policy does not match the embedded profile")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil {
			t.Fatal(err)
		} else if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestConfigureOpenClawGuardModePreservesConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openclaw.json")
	input := `{
  "models": {"provider": "local"},
  "plugins": {
    "allow": ["existing", "rampart"],
    "entries": {
      "existing": {"enabled": true},
      "rampart": {
        "enabled": false,
        "config": {
          "serveUrl": "http://127.0.0.1:9191",
          "failOpen": true,
          "failOpenTools": ["read", "web_search"],
          "approvalTimeoutMs": 240000
        }
      }
    }
  }
}`
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := configureOpenClawGuardModeAtPath(path)
	if err != nil {
		t.Fatalf("configureOpenClawGuardModeAtPath: %v", err)
	}
	if !changed {
		t.Fatal("expected config to change")
	}

	var cfg map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	plugins := cfg["plugins"].(map[string]any)
	entries := plugins["entries"].(map[string]any)
	entry := entries["rampart"].(map[string]any)
	pluginConfig := entry["config"].(map[string]any)
	if enabled, _ := entry["enabled"].(bool); !enabled {
		t.Fatal("Rampart plugin was not enabled")
	}
	if failOpen, ok := pluginConfig["failOpen"].(bool); !ok || failOpen {
		t.Fatalf("failOpen = %#v, want false", pluginConfig["failOpen"])
	}
	if _, exists := pluginConfig["failOpenTools"]; exists {
		t.Fatal("failOpenTools should be removed so failOpen=false controls every tool")
	}
	if pluginConfig["serveUrl"] != "http://localhost:9090" || pluginConfig["approvalTimeoutMs"] != float64(240000) {
		t.Fatal("unrelated Rampart plugin settings were not preserved")
	}
	if cfg["models"].(map[string]any)["provider"] != "local" {
		t.Fatal("unrelated OpenClaw settings were not preserved")
	}
	if _, exists := entries["existing"]; !exists {
		t.Fatal("another plugin entry was removed")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil {
			t.Fatal(err)
		} else if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want 600", info.Mode().Perm())
		}
	}

	changed, err = configureOpenClawGuardModeAtPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("Guard mode configuration should be idempotent")
	}
}

func TestConfigureOpenClawGuardModeRejectsMalformedShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openclaw.json")
	if err := os.WriteFile(path, []byte(`{"plugins": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configureOpenClawGuardModeAtPath(path); err == nil {
		t.Fatal("expected a malformed plugins value to be rejected")
	}
}

func TestOpenClawPluginCurrentDetectsSameVersionDrift(t *testing.T) {
	dir := t.TempDir()
	bundled, err := ocplugin.PluginFS.ReadFile("index.js")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), bundled, 0o600); err != nil {
		t.Fatal(err)
	}
	state := openClawPluginState{
		Installed: true, Allowed: true, Enabled: true, StartupExplicit: true,
		ManifestVersion: ocplugin.Version(), RuntimeVersion: ocplugin.Version(), Dir: dir,
	}
	if !openClawPluginCurrent(state) {
		t.Fatal("exact bundled plugin should be current")
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), append(bundled, []byte("\n// drift")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if openClawPluginCurrent(state) {
		t.Fatal("same-version runtime drift should force a managed reinstall")
	}
}
