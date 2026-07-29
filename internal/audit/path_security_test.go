// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func createTestSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable on this host: %v", err)
	}
}

func TestJSONLSinkRejectsSymlinkedAuditDirectory(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "audit")
	createTestSymlink(t, target, link)

	if _, err := NewJSONLSink(link, WithFsync(false)); err == nil || !strings.Contains(err.Error(), "non-symlink directory") {
		t.Fatalf("NewJSONLSink accepted symlinked audit directory: %v", err)
	}
}

func TestJSONLSinkRejectsSymlinkedManagedFileWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	const original = "do not change"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	createTestSymlink(t, victim, managed)

	if _, err := NewJSONLSink(dir, WithFsync(false)); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("NewJSONLSink accepted symlinked managed file: %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("symlink target changed: got %q", data)
	}
}

func TestJSONLSinkRejectsNonRegularJSONLFile(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := NewJSONLSink(dir, WithFsync(false)); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("NewJSONLSink accepted non-regular managed file: %v", err)
	}
}

func TestJSONLSinkRejectsSymlinkedSharedStateWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	const original = "state victim"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	createTestSymlink(t, victim, filepath.Join(dir, sharedStateFilename))

	if _, err := NewJSONLSink(dir, WithFsync(false)); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("NewJSONLSink accepted symlinked state: %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("state symlink target changed: got %q", data)
	}
}

func TestJSONLSinkRejectsSymlinkedAnchorWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	const original = "anchor victim"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	createTestSymlink(t, victim, filepath.Join(dir, anchorFilename))

	if _, err := NewJSONLSink(dir, WithFsync(false)); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("NewJSONLSink accepted symlinked anchor: %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("anchor symlink target changed: got %q", data)
	}
}

func TestJSONLSinkAnchorUsesRandomTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	const original = "predictable temp victim"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	createTestSymlink(t, victim, filepath.Join(dir, anchorFilename+".tmp"))

	sink, err := NewJSONLSink(dir, WithFsync(false), WithAnchorInterval(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	if err := sink.Write(sampleEvent("exec")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("predictable temporary-file symlink target changed: got %q", data)
	}
	if info, err := os.Lstat(filepath.Join(dir, anchorFilename)); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("anchor was not atomically published as a regular file: info=%v err=%v", info, err)
	}
}

func TestJSONLSinkRotationRejectsPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir, WithFsync(false), WithRotateSize(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	if err := sink.Write(sampleEvent("exec")); err != nil {
		t.Fatal(err)
	}

	victim := filepath.Join(t.TempDir(), "victim")
	const original = "rotation victim"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".p1.jsonl")
	createTestSymlink(t, victim, rotated)

	if err := sink.Write(sampleEvent("write")); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("rotation accepted a planted symlink: %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("rotation symlink target changed: got %q", data)
	}
}

func TestReadEventsFromOffsetRejectsSymlink(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(victim, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "events.jsonl")
	createTestSymlink(t, victim, link)

	if _, _, err := ReadEventsFromOffset(link, 0); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("ReadEventsFromOffset accepted symlink: %v", err)
	}
}

func TestCEFFileSinkRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "victim")
	const original = "cef victim"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "cef.log")
	createTestSymlink(t, victim, link)

	if _, err := NewCEFFileSink(link, nil); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("NewCEFFileSink accepted symlink: %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("CEF symlink target changed: got %q", data)
	}
}

func TestJSONLSinkMetadataAndLogAreOwnerOnlyOnUnix(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Unix mode bits")
	}
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir, WithFsync(false), WithAnchorInterval(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	if err := sink.Write(sampleEvent("exec")); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		sink.filePath(),
		filepath.Join(dir, sharedStateFilename),
		filepath.Join(dir, anchorFilename),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, got)
		}
	}
}
