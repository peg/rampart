// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestUpgradePIDInspectionAndStopRefuseUnrelatedProcess(t *testing.T) {
	home := t.TempDir()
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
	if err := os.WriteFile(
		filepath.Join(home, ".rampart", "serve.pid"),
		[]byte(fmt.Sprintf("%d\n", other.Process.Pid)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	pid, running, err := inspectServePID(func() (string, error) { return home, nil }, os.ReadFile)
	if err != nil {
		t.Fatalf("inspectServePID: %v", err)
	}
	if pid != other.Process.Pid || running {
		t.Fatalf("inspection=(pid=%d running=%t), want unrelated pid and false", pid, running)
	}
	if err := stopServeProcess(other.Process.Pid); err == nil || !strings.Contains(err.Error(), "refusing to signal") {
		t.Fatalf("expected ownership refusal, got %v", err)
	}
	if err := other.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was signaled: %v", err)
	}
}
