// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package filetxn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireLockRejectsSymlinkAnchor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lifetime")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".rampart.lock"); err != nil {
		t.Skipf("creating symlink requires Windows developer mode or privilege: %v", err)
	}

	lock, err := AcquireLock(path)
	if lock != nil {
		_ = lock.Close()
		t.Fatal("AcquireLock unexpectedly followed a symlinked anchor")
	}
	if err == nil {
		t.Fatal("AcquireLock unexpectedly accepted a symlinked anchor")
	}
}

func TestAcquireLockRejectsDirectoryAnchor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lifetime")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".rampart.lock", 0o700); err != nil {
		t.Fatal(err)
	}

	lock, err := AcquireLock(path)
	if lock != nil {
		_ = lock.Close()
		t.Fatal("AcquireLock unexpectedly accepted a directory anchor")
	}
	if err == nil {
		t.Fatal("AcquireLock unexpectedly accepted a directory anchor")
	}
}

func TestAcquireLockRejectsHardLinkedAnchor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lifetime")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, path+".rampart.lock"); err != nil {
		t.Skipf("creating a hard link is unavailable: %v", err)
	}

	lock, err := AcquireLock(path)
	if lock != nil {
		_ = lock.Close()
		t.Fatal("AcquireLock unexpectedly accepted a hard-linked anchor")
	}
	if err == nil {
		t.Fatal("AcquireLock unexpectedly accepted a hard-linked anchor")
	}
}
