// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package hermes

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionReadsManifest(t *testing.T) {
	if got, want := Version(), "1.6.0"; got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
}

func TestExtractWritesPluginFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rampart")
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

func TestExtractRefusesUnmanagedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rampart")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("operator-owned")
	if err := os.WriteFile(filepath.Join(dir, "__init__.py"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}

	err := Extract(dir)
	if err == nil || !strings.Contains(err.Error(), "non-Rampart") {
		t.Fatalf("expected ownership refusal, got %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "__init__.py"))
	if readErr != nil || !bytes.Equal(got, foreign) {
		t.Fatalf("unmanaged content changed: data=%q err=%v", got, readErr)
	}
}

func TestExtractRefusesSymlinkedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlink creation requires privileges on many Windows hosts")
	}
	parent := t.TempDir()
	target := t.TempDir()
	sentinel := filepath.Join(target, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "rampart")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}

	err := Extract(dir)
	if err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("expected symlink refusal, got %v", err)
	}
	if data, readErr := os.ReadFile(sentinel); readErr != nil || string(data) != "keep" {
		t.Fatalf("symlink target changed: data=%q err=%v", data, readErr)
	}
}

func TestExtractRollsBackManagedPluginOnActivationFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rampart")
	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "plugin.yaml")
	oldManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	oldManifest = bytes.Replace(oldManifest, []byte("version: 1.6.0"), []byte("version: 1.5.0"), 1)
	if err := os.WriteFile(manifestPath, oldManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "operator-notes.txt")
	if err := os.WriteFile(userPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected activation failure")
	err = extractWithRename(dir, func(oldPath, newPath string) error {
		if filepath.Base(filepath.Dir(oldPath)) == "stage" && filepath.Base(oldPath) == "plugin.yaml" {
			return injected
		}
		return os.Rename(oldPath, newPath)
	})
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected failure, got %v", err)
	}
	gotManifest, readErr := os.ReadFile(manifestPath)
	if readErr != nil || !bytes.Equal(gotManifest, oldManifest) {
		t.Fatalf("prior manifest was not restored: data=%q err=%v", gotManifest, readErr)
	}
	if data, readErr := os.ReadFile(userPath); readErr != nil || string(data) != "preserve" {
		t.Fatalf("unrelated file was not restored: data=%q err=%v", data, readErr)
	}
}

func TestExtractUpgradePreservesUnrelatedFilesAndDropsCache(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rampart")
	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "operator-notes.txt")
	if err := os.WriteFile(userPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(dir, "__pycache__", "plugin.pyc")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}
	if !Current(dir) {
		t.Fatal("upgraded plugin does not match the embedded payload")
	}
	if data, err := os.ReadFile(userPath); err != nil || string(data) != "preserve" {
		t.Fatalf("unrelated file was not preserved: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("stale Python cache survived upgrade: %v", err)
	}
}
