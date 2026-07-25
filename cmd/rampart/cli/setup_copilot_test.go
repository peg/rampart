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
)

func TestSetupCopilotInstallsSharedUserHooksIdempotently(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("COPILOT_HOME", "")

	for i := 0; i < 2; i++ {
		cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
		cmd.SetArgs([]string{"setup", "copilot"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("setup iteration %d: %v", i+1, err)
		}
	}

	path := filepath.Join(home, ".copilot", "hooks", copilotRampartHookFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !copilotHookDataManaged(data) || !copilotHooksConfiguredForHome(home) {
		t.Fatalf("generated hook was not detected: %s", data)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config["version"] != float64(1) {
		t.Fatalf("version = %#v", config["version"])
	}
	hooks := config["hooks"].(map[string]any)
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		entries := hooks[event].([]any)
		if len(entries) != 1 {
			t.Fatalf("%s entries = %d, want 1", event, len(entries))
		}
		entry := entries[0].(map[string]any)
		if !strings.Contains(entry["bash"].(string), "hook --format copilot") ||
			!strings.Contains(entry["powershell"].(string), "hook --format copilot") {
			t.Fatalf("%s commands = %#v", event, entry)
		}
		if entry["timeoutSec"] != float64(30) {
			t.Fatalf("%s timeout = %#v", event, entry["timeoutSec"])
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestSetupCopilotRefusesForeignFileWithoutForce(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	path := filepath.Join(home, ".copilot", "hooks", copilotRampartHookFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"hooks":{"PreToolUse":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "copilot"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("error = %v, want --force guidance", err)
	}
	cmd = NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "copilot", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("force setup: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !copilotHookDataManaged(data) {
		t.Fatalf("forced hook was not installed: %v, %s", err, data)
	}
}

func TestSetupCopilotRemoveOnlyDeletesManagedFile(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	setup := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	setup.SetArgs([]string{"setup", "copilot"})
	if err := setup.Execute(); err != nil {
		t.Fatal(err)
	}
	remove := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	remove.SetArgs([]string{"setup", "copilot", "--remove"})
	if err := remove.Execute(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".copilot", "hooks", copilotRampartHookFile)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("managed hook still exists: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	remove = NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	remove.SetArgs([]string{"setup", "copilot", "--remove"})
	if err := remove.Execute(); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("foreign file removal error = %v", err)
	}
}

func TestCopilotHomeHonorsEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("COPILOT_HOME", "~/custom-copilot")
	if got, want := copilotHomeDir(home), filepath.Join(home, "custom-copilot"); got != want {
		t.Fatalf("copilotHomeDir = %q, want %q", got, want)
	}
}
