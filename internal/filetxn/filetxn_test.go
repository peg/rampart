// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package filetxn

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestCanonicalPathAllowsMissingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	got, err := CanonicalPath(path)
	if err != nil {
		t.Fatalf("CanonicalPath: %v", err)
	}
	wantParent, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(wantParent, filepath.Base(path))
	if got != want {
		t.Fatalf("CanonicalPath = %q, want %q", got, want)
	}
}

func TestWithLockSerializesWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	const writers = 32

	start := make(chan struct{})
	var wg sync.WaitGroup
	var value int
	var firstErr error
	var errMu sync.Mutex
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := WithLock(path, func() error {
				current := value
				runtime.Gosched()
				value = current + 1
				return nil
			}); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if firstErr != nil {
		t.Fatalf("WithLock: %v", firstErr)
	}
	if value != writers {
		t.Fatalf("serialized value = %d, want %d", value, writers)
	}
	if _, err := os.Stat(path + ".rampart.lock"); err != nil {
		t.Fatalf("lock sidecar: %v", err)
	}
}

func TestWithLockReturnsCallbackError(t *testing.T) {
	want := errors.New("write failed")
	err := WithLock(filepath.Join(t.TempDir(), "state.json"), func() error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("WithLock error = %v, want %v", err, want)
	}
}

func TestReplaceAtomicallyReplacesDestination(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "state.tmp")
	destination := filepath.Join(dir, "state.json")
	if err := os.WriteFile(source, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Replace(source, destination); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new\n" {
		t.Fatalf("destination content = %q, want %q", data, "new\n")
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists after Replace: %v", err)
	}
}
