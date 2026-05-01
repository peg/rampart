package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractOpenClawPluginRuntimeVersion(t *testing.T) {
	got := extractOpenClawPluginRuntimeVersion(`export const id = "rampart";
export const version = "0.9.22";
`)
	if got != "0.9.22" {
		t.Fatalf("runtime version = %q, want 0.9.22", got)
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
