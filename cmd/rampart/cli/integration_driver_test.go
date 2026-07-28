// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindIntegrationDriverResolvesCanonicalIDsAndAliases(t *testing.T) {
	for input, want := range map[string]string{
		"openclaw":       "openclaw",
		"claude":         "claude-code",
		"codex":          "codex",
		"gemini":         "gemini",
		"gemini-cli":     "gemini",
		"antigravity":    "antigravity",
		"agy":            "antigravity",
		"copilot":        "copilot",
		"copilot-cli":    "copilot",
		"github-copilot": "copilot",
		"cline":          "cline",
	} {
		driver, ok := findIntegrationDriver(input)
		if !ok || driver.ID != want || driver.VerifyTarget == "" || driver.Installed == nil || driver.VerifyChecks == nil {
			t.Fatalf("findIntegrationDriver(%q) = %#v, %v; want %q", input, driver, ok, want)
		}
	}
	gemini, ok := findIntegrationDriver("gemini")
	if !ok || gemini.AutoProtect {
		t.Fatal("experimental Gemini CLI must remain explicit setup/verification, not zero-configuration protection")
	}
	if _, ok := findIntegrationDriver("hermes"); ok {
		t.Fatal("experimental Hermes must not be advertised as zero-configuration protection")
	}
}

func TestDetectInstalledIntegrationDriversUsesIsolatedHome(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("CODEX_HOME", "")
	for _, dir := range []string{filepath.Join(home, ".claude"), filepath.Join(home, ".gemini"), filepath.Join(home, ".copilot")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	drivers, err := detectInstalledIntegrationDrivers()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, driver := range drivers {
		ids = append(ids, driver.ID)
	}
	if len(ids) != 2 || ids[0] != "claude-code" || ids[1] != "copilot" {
		t.Fatalf("detected IDs = %#v, want claude-code and copilot only", ids)
	}
}

func TestIntegrationDriverPlatformEligibility(t *testing.T) {
	drivers := supportedIntegrationDrivers()
	find := func(id string) integrationDriver {
		t.Helper()
		for _, driver := range drivers {
			if driver.ID == id {
				return driver
			}
		}
		t.Fatalf("driver %q not found", id)
		return integrationDriver{}
	}

	if !integrationDriverSupportsPlatform(find("cline"), "windows") {
		t.Fatal("Cline should install its current PowerShell hook artifacts on Windows")
	}
	if integrationDriverSupportsPlatform(find("openclaw"), "windows") {
		t.Fatal("OpenClaw must not be auto-protected on Windows")
	}
	for _, id := range []string{"claude-code", "codex", "antigravity", "copilot", "cline"} {
		if !integrationDriverSupportsPlatform(find(id), "windows") {
			t.Fatalf("%s should support Windows", id)
		}
	}
}

func TestClineIntegrationDriverDetectsCurrentVSCodeExtension(t *testing.T) {
	home := t.TempDir()
	extension := filepath.Join(home, ".vscode", "extensions", "saoudrizwan.claude-dev-4.19.0")
	if err := os.MkdirAll(extension, 0o755); err != nil {
		t.Fatal(err)
	}
	driver, ok := findIntegrationDriver("cline")
	if !ok || driver.Installed == nil || !driver.Installed(home) {
		t.Fatal("Cline driver did not detect the current VS Code extension")
	}
}
