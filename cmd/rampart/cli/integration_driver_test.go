// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/assurance"
)

func TestIntegrationDriversMatchAssuranceManifest(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration driver test path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	manifest, err := assurance.LoadManifest(filepath.Join(repoRoot, "assurance", "integrations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(repoRoot); err != nil {
		t.Fatal(err)
	}

	byTarget := make(map[string]assurance.Integration, len(manifest.Integrations))
	for _, integration := range manifest.Integrations {
		byTarget[integration.ID] = integration
	}

	driverTargets := make(map[string]bool)
	for _, driver := range supportedIntegrationDrivers() {
		driverTargets[driver.ID] = true
		integration, found := byTarget[driver.ID]
		if !found {
			t.Errorf("runtime integration driver %q is missing from assurance/integrations.yaml", driver.ID)
			continue
		}
		if driver.DisplayName != integration.DisplayName {
			t.Errorf("driver %q display name = %q, manifest = %q", driver.ID, driver.DisplayName, integration.DisplayName)
		}
		if driver.VerifyTarget != integration.ID {
			t.Errorf("driver %q verify target = %q, manifest id = %q", driver.ID, driver.VerifyTarget, integration.ID)
		}
		wantProof := assuranceAdapterVerified
		if integration.Verification.HostBoundary && integration.Verification.Command == "rampart verify "+driver.VerifyTarget {
			wantProof = assuranceHostVerified
		}
		if driver.ProofLevel != wantProof {
			t.Errorf("driver %q proof level = %q, manifest host boundary = %t", driver.ID, driver.ProofLevel, integration.Verification.HostBoundary)
		}
		if len(driver.Executables) == 0 {
			t.Errorf("driver %q has no executable identity for receipt invalidation", driver.ID)
		}
		if integration.AutoProtect == nil || driver.AutoProtect != *integration.AutoProtect {
			t.Errorf("driver %q auto-protect = %t, manifest = %v", driver.ID, driver.AutoProtect, integration.AutoProtect)
		}
		if driver.ServiceRequired != integration.ServiceRequired {
			t.Errorf("driver %q service-required = %t, manifest = %t", driver.ID, driver.ServiceRequired, integration.ServiceRequired)
		}
		if got := integrationBoundaryKind(driver.Boundary); got != integration.Boundary {
			t.Errorf("driver %q boundary = %q (%q), manifest = %q", driver.ID, driver.Boundary, got, integration.Boundary)
		}
		if diff := platformDifference(driver.Platforms, integration.Platforms); diff != "" {
			t.Errorf("driver %q platform mismatch: %s", driver.ID, diff)
		}
		if strings.HasPrefix(integration.SetupCommand, "rampart setup ") && driver.SetupCommand == nil {
			t.Errorf("driver %q has no setup command callback for manifest command %q", driver.ID, integration.SetupCommand)
		}
	}

	for _, integration := range manifest.Integrations {
		if integration.AutoProtect != nil && *integration.AutoProtect && !driverTargets[integration.ID] {
			t.Errorf("manifest integration %q enables bare protect without a runtime driver", integration.ID)
		}
	}
}

func integrationBoundaryKind(boundary string) string {
	switch {
	case strings.Contains(boundary, "plugin"):
		return "native_plugin"
	case strings.Contains(boundary, "hook"):
		return "native_hook"
	default:
		return ""
	}
}

func platformDifference(driverPlatforms, manifestPlatforms []string) string {
	driverSet := make(map[string]bool, len(driverPlatforms))
	for _, platform := range driverPlatforms {
		driverSet[platform] = true
	}
	manifestSet := make(map[string]bool, len(manifestPlatforms))
	for _, platform := range manifestPlatforms {
		if platform == "macos" {
			platform = "darwin"
		}
		manifestSet[platform] = true
	}
	for platform := range driverSet {
		if !manifestSet[platform] {
			return "driver includes " + platform + " but manifest does not"
		}
	}
	for platform := range manifestSet {
		if !driverSet[platform] {
			return "manifest includes " + platform + " but driver does not"
		}
	}
	return ""
}

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
	// findOpenClawBinary also checks common system-wide install paths. Point its
	// explicit override at a missing fixture so this test depends only on the
	// isolated home, even when the host running the suite has OpenClaw installed.
	t.Setenv("RAMPART_OPENCLAW_BIN", filepath.Join(home, "missing-openclaw"))
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

func TestAntigravityIntegrationDriverDetectsIDEStateWithoutCLIOnPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	if err := os.MkdirAll(filepath.Join(home, ".gemini", "antigravity"), 0o700); err != nil {
		t.Fatal(err)
	}
	driver, ok := findIntegrationDriver("antigravity")
	if !ok || driver.Installed == nil || !driver.Installed(home) {
		t.Fatal("Antigravity driver did not detect the IDE state directory")
	}
}
