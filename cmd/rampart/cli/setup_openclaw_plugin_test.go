package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractOpenClawPluginRuntimeVersion(t *testing.T) {
	got := extractOpenClawPluginRuntimeVersion(`export const id = "rampart";
export const version = "1.0.0";
`)
	if got != "1.0.0" {
		t.Fatalf("runtime version = %q, want 1.0.0", got)
	}
}

func TestFindOpenClawBinaryHonorsOverride(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "custom-openclaw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)

	got, err := findOpenClawBinary()
	if err != nil {
		t.Fatalf("findOpenClawBinary returned error: %v", err)
	}
	if got != bin {
		t.Fatalf("findOpenClawBinary = %q, want %q", got, bin)
	}
}

func TestFindOpenClawBinaryRejectsBadOverride(t *testing.T) {
	skipOnWindows(t, "POSIX executable bits are not meaningful on Windows")

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "not-executable")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)

	_, err := findOpenClawBinary()
	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("expected not executable error, got %v", err)
	}
}

func TestResolveOpenClawStateDirHonorsStateEnv(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPENCLAW_STATE_DIR", tmp)

	stateDir, configPath, err := resolveOpenClawStateDir("/missing/openclaw")
	if err != nil {
		t.Fatalf("resolveOpenClawStateDir returned error: %v", err)
	}
	if stateDir != tmp {
		t.Fatalf("stateDir = %q, want %q", stateDir, tmp)
	}
	if configPath != filepath.Join(tmp, "openclaw.json") {
		t.Fatalf("configPath = %q", configPath)
	}
}

func TestResolveOpenClawStateDirHonorsConfigEnv(t *testing.T) {
	tmp := t.TempDir()
	cfg := filepath.Join(tmp, "custom.json")
	t.Setenv("OPENCLAW_CONFIG_PATH", cfg)

	stateDir, configPath, err := resolveOpenClawStateDir("/missing/openclaw")
	if err != nil {
		t.Fatalf("resolveOpenClawStateDir returned error: %v", err)
	}
	if stateDir != tmp || configPath != cfg {
		t.Fatalf("stateDir/configPath = %q/%q, want %q/%q", stateDir, configPath, tmp, cfg)
	}
}

func TestAddToOpenClawPluginsAllowPreservesAbsentAllowlist(t *testing.T) {
	skipOnWindows(t, "PATH shim binaries in this test are Unix-only")
	configPath := setupOpenClawConfigTest(t, `{"plugins":{"entries":{"rampart":{"enabled":true}}}}`)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	added, existing, err := addToOpenClawPluginsAllow("rampart")
	if err != nil {
		t.Fatalf("addToOpenClawPluginsAllow returned error: %v", err)
	}
	if added || existing != nil {
		t.Fatalf("expected no change with nil existing allowlist, got added=%v existing=%v", added, existing)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("config changed when plugins.allow was absent:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestAddToOpenClawPluginsAllowAppendsExistingAllowlist(t *testing.T) {
	skipOnWindows(t, "PATH shim binaries in this test are Unix-only")
	configPath := setupOpenClawConfigTest(t, `{"plugins":{"allow":["codex"]}}`)

	added, existing, err := addToOpenClawPluginsAllow("rampart")
	if err != nil {
		t.Fatalf("addToOpenClawPluginsAllow returned error: %v", err)
	}
	if !added || len(existing) != 1 || existing[0] != "codex" {
		t.Fatalf("expected append after existing codex allowlist, got added=%v existing=%v", added, existing)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"codex"`, `"rampart"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("updated config missing %s: %s", want, data)
		}
	}
}

func setupOpenClawConfigTest(t *testing.T, config string) string {
	t.Helper()
	stateDir := t.TempDir()
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "openclaw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}
