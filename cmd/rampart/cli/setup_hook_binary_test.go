// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"testing"
)

func TestResolveRampartHookBinary(t *testing.T) {
	originalExecutable := osExecutable
	originalLookPath := execLookPath
	t.Cleanup(func() {
		osExecutable = originalExecutable
		execLookPath = originalLookPath
	})

	t.Run("side-by-side candidate binds to itself", func(t *testing.T) {
		osExecutable = func() (string, error) { return "/opt/homebrew/bin/rampart-staging", nil }
		execLookPath = func(string) (string, error) { return "/opt/homebrew/bin/rampart", nil }
		if got, want := resolveRampartHookBinary(), "/opt/homebrew/bin/rampart-staging"; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want %q", got, want)
		}
	})

	t.Run("stable build prefers package manager path", func(t *testing.T) {
		osExecutable = func() (string, error) { return "/opt/homebrew/Cellar/rampart/1.4.0/bin/rampart", nil }
		execLookPath = func(string) (string, error) { return "/opt/homebrew/bin/rampart", nil }
		if got, want := resolveRampartHookBinary(), "/opt/homebrew/bin/rampart"; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want %q", got, want)
		}
	})

	t.Run("current executable is final fallback", func(t *testing.T) {
		osExecutable = func() (string, error) { return "/tmp/custom-rampart", nil }
		execLookPath = func(string) (string, error) { return "", os.ErrNotExist }
		if got, want := resolveRampartHookBinary(), "/tmp/custom-rampart"; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want %q", got, want)
		}
	})
}
