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
		"openclaw":   "openclaw",
		"claude":     "claude-code",
		"codex":      "codex",
		"gemini":     "gemini",
		"gemini-cli": "gemini",
		"cline":      "cline",
	} {
		driver, ok := findIntegrationDriver(input)
		if !ok || driver.ID != want || driver.VerifyTarget == "" || driver.Installed == nil || driver.VerifyChecks == nil {
			t.Fatalf("findIntegrationDriver(%q) = %#v, %v; want %q", input, driver, ok, want)
		}
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
	for _, dir := range []string{filepath.Join(home, ".claude"), filepath.Join(home, ".gemini")} {
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
	if len(ids) != 2 || ids[0] != "claude-code" || ids[1] != "gemini" {
		t.Fatalf("detected IDs = %#v, want claude-code and gemini", ids)
	}
}
