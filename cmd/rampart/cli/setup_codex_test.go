// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetupCodexRequiresPreloadLibrary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("codex setup is unsupported on Windows")
	}

	home := t.TempDir()
	testSetHome(t, home)
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	codexPath := filepath.Join(binDir, "codex")
	if err := os.WriteFile(codexPath, []byte("#!/bin/sh\necho codex\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "codex"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected setup codex to fail when librampart is missing")
	}
	if !strings.Contains(err.Error(), "preload library unavailable") {
		t.Fatalf("error = %q, want preload library unavailable", err.Error())
	}
	if _, statErr := os.Stat(filepath.Join(home, ".local", "bin", "codex")); !os.IsNotExist(statErr) {
		t.Fatalf("wrapper should not be installed without preload library; stat err=%v", statErr)
	}
}

func TestSetupCodexInstallsWrapperWhenPreloadLibraryExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("codex setup is unsupported on Windows")
	}

	home := t.TempDir()
	testSetHome(t, home)
	binDir := filepath.Join(home, "bin")
	libDir := filepath.Join(home, ".rampart", "lib")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	codexPath := filepath.Join(binDir, "codex")
	if err := os.WriteFile(codexPath, []byte("#!/bin/sh\necho codex\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	libName := "librampart.so"
	if runtime.GOOS == "darwin" {
		libName = "librampart.dylib"
	}
	if err := os.WriteFile(filepath.Join(libDir, libName), []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "codex"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup codex: %v", err)
	}
	wrapperPath := filepath.Join(home, ".local", "bin", "codex")
	data, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatalf("read wrapper: %v", err)
	}
	if !strings.Contains(string(data), "rampart preload") {
		t.Fatalf("wrapper missing rampart preload: %s", data)
	}
}

func TestSetupCodexRemoveDoesNotRequireCodexOrPreloadLibrary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("codex setup is unsupported on Windows")
	}

	home := t.TempDir()
	testSetHome(t, home)
	wrapperPath := filepath.Join(home, ".local", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(wrapperPath), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/bin/sh\n# Rampart wrapper for Codex — managed by 'rampart setup codex'\n# Real codex: /missing/codex\nexec rampart preload -- /missing/codex \"$@\"\n"
	if err := os.WriteFile(wrapperPath, []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "codex", "--remove"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove should not require codex or librampart: %v", err)
	}
	if _, err := os.Stat(wrapperPath); !os.IsNotExist(err) {
		t.Fatalf("wrapper should be removed, stat err=%v", err)
	}
}

func TestSetupCodexIsIdempotentWhenWrapperFirstOnPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("codex setup is unsupported on Windows")
	}

	home := t.TempDir()
	testSetHome(t, home)
	realBinDir := filepath.Join(home, "real-bin")
	wrapperDir := filepath.Join(home, ".local", "bin")
	libDir := filepath.Join(home, ".rampart", "lib")
	for _, dir := range []string{realBinDir, wrapperDir, libDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	realCodex := filepath.Join(realBinDir, "codex")
	if err := os.WriteFile(realCodex, []byte("#!/bin/sh\necho real codex\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	libName := "librampart.so"
	if runtime.GOOS == "darwin" {
		libName = "librampart.dylib"
	}
	if err := os.WriteFile(filepath.Join(libDir, libName), []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+realBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	for i := 0; i < 2; i++ {
		cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
		cmd.SetArgs([]string{"setup", "codex"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("setup codex iteration %d: %v", i+1, err)
		}
	}

	wrapperPath := filepath.Join(wrapperDir, "codex")
	data, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatalf("read wrapper: %v", err)
	}
	content := string(data)
	recordedReal := extractRealBinFromWrapper(content)
	if !sameCodexPath(recordedReal, realCodex) {
		t.Fatalf("wrapper should keep real codex path %q, got %q in:\n%s", realCodex, recordedReal, content)
	}
	if sameCodexPath(recordedReal, wrapperPath) || strings.Contains(content, "preload -- "+wrapperPath) {
		t.Fatalf("wrapper became self-recursive:\n%s", content)
	}
}
