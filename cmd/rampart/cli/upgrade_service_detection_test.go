// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDetectActiveSystemdServiceRequiresMatchingExecutable(t *testing.T) {
	home := t.TempDir()
	serviceDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(home, "bin", "rampart")
	unrelated := filepath.Join(home, "other", "rampart")
	for _, path := range []string{executable, unrelated} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	unitPath := filepath.Join(serviceDir, "rampart-serve.service")
	runnerCalls := 0
	runner := func(string, ...string) *exec.Cmd {
		runnerCalls++
		return exec.Command("true")
	}
	homeDir := func() (string, error) { return home, nil }

	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf("[Service]\nExecStart=\"%s\" serve\n", unrelated)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectActiveSystemdService(runner, homeDir, executable); got != "" {
		t.Fatalf("unrelated service detected as %q", got)
	}
	if runnerCalls != 0 {
		t.Fatal("systemctl was queried before service ownership matched")
	}

	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf("[Service]\nExecStart=\"%s\" serve\n", executable)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectActiveSystemdService(runner, homeDir, executable); got != "rampart-serve.service" {
		t.Fatalf("matching service = %q", got)
	}
}

func TestDetectActiveLaunchdServiceRequiresMatchingExecutable(t *testing.T) {
	home := t.TempDir()
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(home, "bin", "rampart")
	unrelated := filepath.Join(home, "other", "rampart")
	for _, path := range []string{executable, unrelated} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	plistPath := filepath.Join(agentDir, plistLabel+".plist")
	writePlist := func(binary string) {
		t.Helper()
		content := fmt.Sprintf(`<?xml version="1.0"?><plist><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>serve</string></array>
</dict></plist>`, plistLabel, binary)
		if err := os.WriteFile(plistPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runnerCalls := 0
	runner := func(string, ...string) *exec.Cmd {
		runnerCalls++
		return exec.Command("true")
	}
	homeDir := func() (string, error) { return home, nil }

	writePlist(unrelated)
	if got := detectActiveLaunchdServices(runner, homeDir, executable); len(got) != 0 {
		t.Fatalf("unrelated services detected: %#v", got)
	}
	if runnerCalls != 0 {
		t.Fatal("launchctl was queried before service ownership matched")
	}

	writePlist(executable)
	got := detectActiveLaunchdServices(runner, homeDir, executable)
	if len(got) != 1 || got[0].Label != plistLabel {
		t.Fatalf("matching services = %#v", got)
	}
}
