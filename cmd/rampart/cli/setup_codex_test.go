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
