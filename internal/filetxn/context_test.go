// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package filetxn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func expectLockTimeoutAndRecovery(t *testing.T, path string, release func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	called := false
	start := time.Now()
	err := WithLockContext(ctx, path, func() error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called || time.Since(start) > time.Second {
		t.Fatalf("held lock result=%v callback=%v elapsed=%v", err, called, time.Since(start))
	}
	release()
	ctx, cancelRecovery := context.WithTimeout(context.Background(), time.Second)
	defer cancelRecovery()
	if err := WithLockContext(ctx, path, func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("canceled acquisition leaked lock state: %v callback=%v", err, called)
	}
	want := errors.New("callback result")
	if err := WithLock(path, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("normal writer did not recover: %v", err)
	}
}

func TestWithLockContextCancelsProcessWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	canonical, err := CanonicalPath(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock := lockProcessPath(canonical)
	released := false
	defer func() {
		if !released {
			unlock()
		}
	}()
	expectLockTimeoutAndRecovery(t, path, func() { unlock(); released = true })
}

func TestWithLockContextCancelsOSWait(t *testing.T) {
	const helperEnv = "RAMPART_FILETXN_CONTEXT_HELPER"
	if path := os.Getenv(helperEnv); path != "" {
		if err := WithLock(path, func() error {
			fmt.Fprintln(os.Stdout, "locked")
			_, err := bufio.NewReader(os.Stdin).ReadByte()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "state.json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWithLockContextCancelsOSWait$")
	child.Env = append(os.Environ(), helperEnv+"="+path)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = child.Process.Kill(); _ = child.Wait() })
	ready, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || ready != "locked\n" {
		t.Fatalf("child readiness=%q error=%v", ready, err)
	}
	expectLockTimeoutAndRecovery(t, path, func() {
		if _, err := input.Write([]byte("\n")); err != nil {
			t.Fatal(err)
		}
		if err := child.Wait(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestWithLockContextAlreadyCanceledAndOpenFailureReleaseProcessKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WithLockContext(ctx, path, func() error { t.Fatal("canceled callback ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled result: %v", err)
	}
	if err := os.Mkdir(path+".rampart.lock", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WithLockContext(context.Background(), path, func() error { t.Fatal("failed-open callback ran"); return nil }); err == nil {
		t.Fatal("accepted a directory lock sidecar")
	}
	if err := os.Remove(path + ".rampart.lock"); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := WithLockContext(ctx, path, func() error { return nil }); err != nil {
		t.Fatalf("failed open leaked process key: %v", err)
	}
}
