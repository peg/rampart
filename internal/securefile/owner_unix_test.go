// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerOnlyRestrictsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := OwnerOnly(path); err != nil {
		t.Fatalf("OwnerOnly: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions = %04o, want 0600", got)
	}
}

func TestOwnerOnlyFailsForMissingFile(t *testing.T) {
	if err := OwnerOnly(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("OwnerOnly unexpectedly accepted a missing file")
	}
}
