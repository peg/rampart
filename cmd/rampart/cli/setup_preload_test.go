// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateShimContent(t *testing.T) {
	shim := generateShimContent("/bin/bash", 19090, "rampart_test123")

	if !strings.Contains(shim, `REAL_SHELL="/bin/bash"`) {
		t.Error("shim should contain REAL_SHELL")
	}
	if !strings.Contains(shim, `RAMPART_URL="http://127.0.0.1:19090"`) {
		t.Error("shim should contain RAMPART_URL with correct port")
	}
	if !strings.Contains(shim, `RAMPART_TOKEN="rampart_test123"`) {
		t.Error("shim should contain RAMPART_TOKEN")
	}
	if !strings.Contains(shim, "#!/usr/bin/env bash") {
		t.Error("shim should start with shebang")
	}
}

func TestSetupOpenClaw_PatchToolsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not supported on Windows")
	}

	root := newTestRoot()
	cmd := newSetupOpenClawCmd(root)

	// --patch-tools-only should attempt to patch (will fail gracefully without node_modules)
	cmd.SetArgs([]string{"--patch-tools-only", "--port", "19999"})
	// This will return an error because no tools dir exists, which is expected
	_ = cmd.Execute()
}

func TestSetupOpenClaw_ShimOnlyFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not supported on Windows")
	}

	// Create a temp home directory
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")

	// Create required dirs
	os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700)
	os.MkdirAll(filepath.Join(home, ".rampart", "policies"), 0o700)
	os.MkdirAll(filepath.Join(home, ".config", "systemd", "user"), 0o700)

	root := newTestRoot()
	cmd := newSetupOpenClawCmd(root)
	cmd.SetArgs([]string{"--shim-only", "--force"})

	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	_ = cmd.Execute()
	output := buf.String()

	// Shim should exist
	shimPath := filepath.Join(home, ".local", "bin", "rampart-shim")
	if _, err := os.Stat(shimPath); os.IsNotExist(err) {
		t.Error("shim should be created with --shim-only")
	}

	// Drop-in should NOT exist
	dropinPath := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d", "rampart.conf")
	if _, err := os.Stat(dropinPath); err == nil {
		t.Error("drop-in should NOT be created with --shim-only")
	}

	// Output should mention SHELL config
	if !strings.Contains(output, "SHELL=") {
		t.Error("shim-only output should mention SHELL config")
	}
}

func TestSetupOpenClaw_DropinContent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd drop-in only on Linux")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create the OpenClaw service file (required for drop-in to install)
	serviceDir := filepath.Join(home, ".config", "systemd", "user")
	os.MkdirAll(serviceDir, 0o700)
	os.WriteFile(filepath.Join(serviceDir, "openclaw-gateway.service"), []byte("[Service]\nExecStart=/usr/bin/node\n"), 0o600)

	// Create a fake librampart.so
	libDir := filepath.Join(home, ".rampart", "lib")
	os.MkdirAll(libDir, 0o700)
	os.WriteFile(filepath.Join(libDir, "librampart.so"), []byte("fake"), 0o700)

	root := newTestRoot()
	cmd := newSetupOpenClawCmd(root)

	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	// Call installOpenClawPreload directly
	installed, err := installOpenClawPreload(cmd, home, "/usr/local/bin/rampart", "rampart_testtoken", 19090, false, false)
	if err != nil {
		t.Fatalf("installOpenClawPreload failed: %v", err)
	}
	if !installed {
		t.Fatal("expected preload to be installed")
	}

	// Read drop-in and verify content
	dropinPath := filepath.Join(serviceDir, "openclaw-gateway.service.d", "rampart.conf")
	data, err := os.ReadFile(dropinPath)
	if err != nil {
		t.Fatalf("drop-in not written: %v", err)
	}
	content := string(data)

	// Check quoting
	if !strings.Contains(content, `Environment=LD_PRELOAD="`) {
		t.Error("LD_PRELOAD value should be quoted")
	}
	if !strings.Contains(content, `Environment=RAMPART_TOKEN="rampart_testtoken"`) {
		t.Error("RAMPART_TOKEN should be quoted")
	}
	if !strings.Contains(content, `Environment=RAMPART_URL="http://127.0.0.1:19090"`) {
		t.Error("RAMPART_URL should be quoted with correct port")
	}
	if !strings.Contains(content, "ExecStartPre=") {
		t.Error("ExecStartPre should be present")
	}
	if !strings.Contains(content, "--patch-tools-only") {
		t.Error("ExecStartPre should use --patch-tools-only")
	}

	// Check permissions
	info, _ := os.Stat(dropinPath)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("drop-in should be 0600, got %o", perm)
	}
}

func TestSetupOpenClaw_DropinNoPreload(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd drop-in only on Linux")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	serviceDir := filepath.Join(home, ".config", "systemd", "user")
	os.MkdirAll(serviceDir, 0o700)
	os.WriteFile(filepath.Join(serviceDir, "openclaw-gateway.service"), []byte("[Service]\n"), 0o600)

	// No librampart.so created — --no-preload should NOT require it
	root := newTestRoot()
	cmd := newSetupOpenClawCmd(root)
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	installed, err := installOpenClawPreload(cmd, home, "/usr/local/bin/rampart", "rampart_tok", 19090, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !installed {
		t.Fatal("should be installed even with --no-preload")
	}

	dropinPath := filepath.Join(serviceDir, "openclaw-gateway.service.d", "rampart.conf")
	data, _ := os.ReadFile(dropinPath)
	content := string(data)

	if strings.Contains(content, "LD_PRELOAD") {
		t.Error("drop-in should NOT contain LD_PRELOAD when noPreload=true")
	}
	if !strings.Contains(content, "RAMPART_URL") {
		t.Error("drop-in should still contain RAMPART_URL")
	}
}

func TestSetupOpenClaw_RemoveDropin(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd drop-in only on Linux")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create drop-in
	dropinDir := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d")
	os.MkdirAll(dropinDir, 0o700)
	os.WriteFile(filepath.Join(dropinDir, "rampart.conf"), []byte("[Service]\n"), 0o600)

	// Create shim
	shimDir := filepath.Join(home, ".local", "bin")
	os.MkdirAll(shimDir, 0o700)
	os.WriteFile(filepath.Join(shimDir, "rampart-shim"), []byte("#!/bin/bash\n"), 0o700)

	root := newTestRoot()
	cmd := newSetupOpenClawCmd(root)
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := removeOpenClaw(cmd)
	if err != nil {
		t.Fatalf("removeOpenClaw failed: %v", err)
	}
	output := buf.String()

	// Drop-in should be removed
	if _, err := os.Stat(filepath.Join(dropinDir, "rampart.conf")); err == nil {
		t.Error("drop-in should be removed")
	}

	// Empty drop-in dir should be removed
	if _, err := os.Stat(dropinDir); err == nil {
		t.Error("empty drop-in dir should be removed")
	}

	// Shim should be removed
	if _, err := os.Stat(filepath.Join(shimDir, "rampart-shim")); err == nil {
		t.Error("shim should be removed")
	}

	if !strings.Contains(output, "Removed") {
		t.Error("output should list removed files")
	}
}

func newTestRoot() *rootOptions {
	return &rootOptions{}
}

func TestSetupOpenClaw_DarwinPlistPatch(t *testing.T) {
	// Test plist patching logic without requiring macOS
	// We test the string manipulation directly

	plistContent := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openclaw.gateway</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/node</string>
    </array>
</dict>
</plist>`

	// Simulate the injection logic from installOpenClawPreloadDarwin
	envEntries := `        <key>RAMPART_URL</key>
        <string>http://127.0.0.1:9090</string>
        <key>RAMPART_TOKEN</key>
        <string>rampart_testtoken</string>
`

	// No existing EnvironmentVariables — should inject before </dict></plist>
	if !strings.Contains(plistContent, "<key>EnvironmentVariables</key>") {
		patched := strings.Replace(plistContent,
			"</dict>\n</plist>",
			"    <key>EnvironmentVariables</key>\n    <dict>\n"+envEntries+"    </dict>\n</dict>\n</plist>", 1)

		if patched == plistContent {
			t.Fatal("plist injection should have modified the content")
		}
		if !strings.Contains(patched, "RAMPART_URL") {
			t.Error("patched plist should contain RAMPART_URL")
		}
		if !strings.Contains(patched, "EnvironmentVariables") {
			t.Error("patched plist should contain EnvironmentVariables key")
		}
		if !strings.Contains(patched, "</plist>") {
			t.Error("patched plist should still end with </plist>")
		}
	}

	// Test with existing EnvironmentVariables
	plistWithEnv := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>/Users/test</string>
    </dict>
</dict>
</plist>`

	patched := strings.Replace(plistWithEnv,
		"<key>EnvironmentVariables</key>\n    <dict>\n",
		"<key>EnvironmentVariables</key>\n    <dict>\n"+envEntries, 1)

	if patched == plistWithEnv {
		t.Fatal("plist injection into existing EnvironmentVariables should modify content")
	}
	if !strings.Contains(patched, "RAMPART_URL") {
		t.Error("patched plist should contain RAMPART_URL")
	}
	if !strings.Contains(patched, "HOME") {
		t.Error("patched plist should preserve existing HOME key")
	}

	// Test with non-standard formatting (should fail to patch)
	weirdPlist := `<?xml version="1.0"?><plist><dict><key>Label</key><string>test</string></dict></plist>`
	patchedWeird := strings.Replace(weirdPlist,
		"</dict>\n</plist>",
		"INJECTED\n</dict>\n</plist>", 1)
	if patchedWeird != weirdPlist {
		t.Error("non-standard plist formatting should NOT be modified by simple Replace")
	}
}
