// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package filetxn

import (
	"errors"
	"os"
	"os/exec"
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

func TestAcquireLockExcludesProcessesAndReleases(t *testing.T) {
	const helperEnv = "RAMPART_FILETXN_LOCK_HELPER"
	if path := os.Getenv(helperEnv); path != "" {
		lock, err := AcquireLock(path)
		if lock != nil {
			_ = lock.Close()
			t.Fatal("helper unexpectedly acquired parent lock")
		}
		if !errors.Is(err, ErrLockHeld) {
			t.Fatalf("helper AcquireLock error = %v, want ErrLockHeld", err)
		}
		return
	}

	path := filepath.Join(t.TempDir(), "lifetime")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if _, err := AcquireLock(path); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("same-process AcquireLock error = %v, want ErrLockHeld", err)
	}

	// On Unix the lifetime lock is held on the stable parent directory, so an
	// unlinked/replaced legacy sidecar cannot create a second lock inode. On
	// Windows the exclusive anchor handle must prevent the replacement itself.
	anchorPath := path + ".rampart.lock"
	if runtime.GOOS == "windows" {
		if err := os.Remove(anchorPath); err == nil {
			t.Fatal("removed Windows lifetime-lock anchor while its no-share handle was open")
		}
		if err := os.Rename(anchorPath, anchorPath+".moved"); err == nil {
			t.Fatal("renamed Windows lifetime-lock anchor while its no-share handle was open")
		}
	} else {
		if err := os.WriteFile(anchorPath, []byte("old anchor\n"), 0o600); err != nil {
			t.Fatalf("write replaceable sidecar: %v", err)
		}
		if err := os.Remove(anchorPath); err != nil {
			t.Fatalf("remove replaceable sidecar: %v", err)
		}
		if err := os.WriteFile(anchorPath, []byte("replacement anchor\n"), 0o600); err != nil {
			t.Fatalf("replace sidecar: %v", err)
		}
	}

	// The lifetime primitive is anchored outside the state directory. Even if
	// a non-cooperating process renames and recreates that directory, another
	// Rampart process must still observe the existing owner.
	movedPath := path + ".moved"
	if err := os.Rename(path, movedPath); err != nil {
		t.Fatalf("rename locked data directory: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("recreate locked data directory path: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAcquireLockExcludesProcessesAndReleases$")
	cmd.Env = append(os.Environ(), helperEnv+"="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-process lock helper: %v\n%s", err, output)
	}

	if err := lock.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
	reacquired, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("AcquireLock after release: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatalf("reacquired Close: %v", err)
	}
}

func TestAcquireLockRejectsSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "state")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	lock, err := AcquireLock(link)
	if lock != nil {
		_ = lock.Close()
		t.Fatal("AcquireLock unexpectedly accepted a symlinked data directory")
	}
	if err == nil {
		t.Fatal("AcquireLock unexpectedly accepted a symlinked data directory")
	}
}

func TestAcquireLockRejectsNonDirectoryTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireLock(path)
	if lock != nil {
		_ = lock.Close()
		t.Fatal("AcquireLock unexpectedly accepted a non-directory target")
	}
	if err == nil || errors.Is(err, ErrLockHeld) {
		t.Fatalf("AcquireLock error = %v, want invalid target error", err)
	}
}

func TestReplaceAtomicallyReplacesDestination(t *testing.T) {
	testReplacement(t, Replace)
}

func TestReplaceAtomicReplacesDestination(t *testing.T) {
	testReplacement(t, ReplaceAtomic)
}

func testReplacement(t *testing.T, replace func(string, string) error) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "state.tmp")
	destination := filepath.Join(dir, "state.json")
	if err := os.WriteFile(source, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := replace(source, destination); err != nil {
		t.Fatalf("replace: %v", err)
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
