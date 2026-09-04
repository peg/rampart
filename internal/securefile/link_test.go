// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSingleLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := SingleLink(file); err != nil {
		t.Fatalf("unshared file: %v", err)
	}
	alias := path + ".alias"
	if err := os.Link(path, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := SingleLink(file); err == nil {
		t.Fatal("accepted a hard-linked file")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := SingleLink(file); err != nil {
		t.Fatalf("unlinked alias: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := SingleLink(file); err == nil {
		t.Fatal("accepted a closed file")
	}
}
