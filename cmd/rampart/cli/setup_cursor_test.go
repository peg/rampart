// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSetupCursorPreservesForeignHooksAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	path := cursorHooksPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := `{"version":1,"owner":"user","hooks":{"preToolUse":[{"command":"./foreign.sh","matcher":"Shell"}],"afterFileEdit":[{"command":"./format.sh"}]}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := testExecuteRoot(t, "setup", "cursor"); err != nil {
			t.Fatalf("setup iteration %d: %v", i+1, err)
		}
	}
	if !cursorHooksConfiguredForHome(home) {
		t.Fatal("managed Cursor hook was not detected as current")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["owner"] != "user" {
		t.Fatalf("unrelated top-level setting was changed: %#v", settings)
	}
	hooks := settings["hooks"].(map[string]any)
	if len(hooks["afterFileEdit"].([]any)) != 1 {
		t.Fatalf("unrelated event was changed: %#v", hooks)
	}
	entries := hooks["preToolUse"].([]any)
	if len(entries) != 2 {
		t.Fatalf("preToolUse entries = %d, want foreign + Rampart", len(entries))
	}
	managed := entries[1].(map[string]any)
	if managed["command"] != currentCursorHookCommand() || managed["failClosed"] != true || managed["timeout"] != float64(cursorHookTimeoutSeconds) {
		t.Fatalf("managed hook = %#v", managed)
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

func TestSetupCursorRepairsStaleOwnedHookAndRemovalPreservesForeignHooks(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	path := cursorHooksPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"version":1,"hooks":{"preToolUse":[{"command":"'/retired/rampart' hook --format cursor","timeout":1,"failClosed":false},{"command":"./foreign.sh"}]}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if !cursorRampartHooksPresent(home) || cursorHooksConfiguredForHome(home) {
		t.Fatal("stale owned Cursor hook must be removable but not current")
	}
	if err := testExecuteRoot(t, "setup", "cursor"); err != nil {
		t.Fatal(err)
	}
	if !cursorHooksConfiguredForHome(home) {
		t.Fatal("setup did not repair the stale managed hook")
	}
	if err := testExecuteRoot(t, "setup", "cursor", "--remove"); err != nil {
		t.Fatal(err)
	}
	if cursorRampartHooksPresent(home) {
		t.Fatal("managed Cursor hook remains after removal")
	}
	settings, err := readCursorHooks(path, false)
	if err != nil {
		t.Fatal(err)
	}
	hooks := settings["hooks"].(map[string]any)
	entries := hooks["preToolUse"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["command"] != "./foreign.sh" {
		t.Fatalf("foreign hook was not preserved: %#v", entries)
	}
}
