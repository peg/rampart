// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package hermes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionReadsManifest(t *testing.T) {
	if got, want := Version(), "1.3.0"; got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
}

func TestExtractWritesPluginFiles(t *testing.T) {
	dir := t.TempDir()
	if err := Extract(dir); err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	for _, name := range []string{"__init__.py", "plugin.yaml"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("expected %s to be written: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("expected %s to be non-empty", name)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		t.Fatalf("read extracted manifest: %v", err)
	}
	if !strings.Contains(string(manifest), "provides_hooks:") || !strings.Contains(string(manifest), "pre_tool_call") {
		t.Fatalf("manifest must declare pre_tool_call hook: %s", string(manifest))
	}
}
