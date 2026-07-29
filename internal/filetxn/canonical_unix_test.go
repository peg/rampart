// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

package filetxn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalPathResolvesParentSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	linkDir := filepath.Join(root, "link")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	got, err := CanonicalPath(filepath.Join(linkDir, "state.json"))
	if err != nil {
		t.Fatalf("CanonicalPath: %v", err)
	}
	wantParent, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(wantParent, "state.json")
	if got != want {
		t.Fatalf("CanonicalPath = %q, want %q", got, want)
	}
}
