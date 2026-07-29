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
	shadow := filepath.Join(root, "shadow", "rampart"+suffix)
	stable := filepath.Join(root, "stable", "rampart"+suffix)
	versionedStable := filepath.Join(root, "Cellar", "rampart", "1.4.0", "bin", "rampart"+suffix)
	fallback := filepath.Join(root, "custom-rampart"+suffix)
	for _, path := range []string{candidate, shadow, versionedStable, fallback} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(stable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(versionedStable, stable); err != nil {
		if linkErr := os.Link(versionedStable, stable); linkErr != nil {
			t.Fatalf("create stable package-manager alias: symlink=%v hardlink=%v", err, linkErr)
		}
	}

	t.Run("side-by-side candidate binds to itself", func(t *testing.T) {
		osExecutable = func() (string, error) { return candidate, nil }
		execLookPath = func(string) (string, error) { return stable, nil }
		if got, want := resolveRampartHookBinary(), candidate; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want %q", got, want)
		}
	})

	t.Run("same-name candidate rejects distinct PATH shadow", func(t *testing.T) {
		osExecutable = func() (string, error) { return fallback, nil }
		execLookPath = func(string) (string, error) { return shadow, nil }
		if got, want := resolveRampartHookBinary(), fallback; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want current executable %q", got, want)
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

	t.Run("PATH is used when executable identity is unavailable", func(t *testing.T) {
		osExecutable = func() (string, error) { return "", os.ErrNotExist }
		execLookPath = func(string) (string, error) { return stable, nil }
		if got, want := resolveRampartHookBinary(), stable; got != want {
			t.Fatalf("resolveRampartHookBinary() = %q, want %q", got, want)
		}
	})
}
