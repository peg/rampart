// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package cli

import (
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSetDetachAttrsWindows(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit", "0")
	setDetachAttrs(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("setDetachAttrs left SysProcAttr nil")
	}
	want := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP)
	if got := cmd.SysProcAttr.CreationFlags & want; got != want {
		t.Fatalf("CreationFlags = %#x, want flags %#x", cmd.SysProcAttr.CreationFlags, want)
	}
}

func TestWindowsProcessInspectionScriptTargetsExactPID(t *testing.T) {
	script := windowsProcessInspectionScript(4242)
	for _, want := range []string{
		"UTF8Encoding",
		"Get-CimInstance Win32_Process",
		"ProcessId = 4242",
		"Name,CommandLine",
		"ConvertTo-Json -Compress",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("inspection script missing %q: %s", want, script)
		}
	}
}
