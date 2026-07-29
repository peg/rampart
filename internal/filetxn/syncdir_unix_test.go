// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

package filetxn

import (
	"path/filepath"
	"testing"
)

func TestSyncDir(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
}

func TestSyncDir_MissingDirectory(t *testing.T) {
	err := SyncDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("SyncDir on a missing directory succeeded")
	}
}
