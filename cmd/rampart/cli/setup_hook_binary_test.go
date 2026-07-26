// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveRampartHookBinary(t *testing.T) {
	originalExecutable := osExecutable
	originalLookPath := execLookPath
	t.Cleanup(func() {
		osExecutable = originalExecutable
		execLookPath = originalLookPath
	})
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	root := t.TempDir()
	candidate := filepath.Join(root, "bin", "rampart-staging"+suffix)
	stable := filepath.Join(root, "bin", "rampart"+suffix)
	versionedStable := filepath.Join(root, "Cellar", "rampart", "1.4.0", "bin", "rampart"+suffix)
	fallback := filepath.Join(root, "custom-rampart"+suffix)

	t.Run("side-by-side candidate binds to itself", func(t *testing.T) {
		osExecutable = func() (string, error) { return candidate, nil }
		execLookPath = func(string) (string, error) { return stable, nil }
		if got, want := resolveRampartHookBinary(), candidate; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want %q", got, want)
		}
	})

	t.Run("stable build prefers package manager path", func(t *testing.T) {
		osExecutable = func() (string, error) { return versionedStable, nil }
		execLookPath = func(string) (string, error) { return stable, nil }
		if got, want := resolveRampartHookBinary(), stable; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want %q", got, want)
		}
	})

	t.Run("current executable is final fallback", func(t *testing.T) {
		osExecutable = func() (string, error) { return fallback, nil }
		execLookPath = func(string) (string, error) { return "", os.ErrNotExist }
		if got, want := resolveRampartHookBinary(), fallback; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want %q", got, want)
		}
	})
}
