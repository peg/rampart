// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStopBackgroundServeRefusesUnrelatedStalePID(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".rampart"), 0o700); err != nil {
		t.Fatal(err)
	}

	other := exec.Command("sleep", "30")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = other.Process.Kill()
		_, _ = other.Process.Wait()
	})

	pidPath := filepath.Join(home, ".rampart", "serve.pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", other.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}

	err := stopBackgroundServe(&bytes.Buffer{}, false)
	if err == nil {
		t.Fatal("expected an unrelated process to be rejected")
	}
	if signalErr := other.Process.Signal(syscall.Signal(0)); signalErr != nil {
		t.Fatalf("unrelated process was terminated: %v", signalErr)
	}
	if _, statErr := os.Stat(pidPath); !os.IsNotExist(statErr) {
		t.Fatalf("stale PID file was not removed: %v", statErr)
	}
}
