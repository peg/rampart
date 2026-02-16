package cli

import (
	"os"
	"strings"
	"testing"
)

func TestFindRampartBinary(t *testing.T) {
	// Save and restore
	origExec := osExecutable
	origLook := execLookPath
	defer func() {
		osExecutable = origExec
		execLookPath = origLook
	}()

	// Case 1: os.Executable works
	osExecutable = func() (string, error) { return "/usr/bin/rampart", nil }
	got, err := findRampartBinary()
	if err != nil || got != "/usr/bin/rampart" {
		t.Errorf("got %q, err=%v", got, err)
	}

	// Case 2: os.Executable fails, LookPath works
	osExecutable = func() (string, error) { return "", os.ErrNotExist }
	execLookPath = func(name string) (string, error) { return "/usr/local/bin/rampart", nil }
	got, err = findRampartBinary()
	if err != nil || got != "/usr/local/bin/rampart" {
		t.Errorf("got %q, err=%v", got, err)
	}

	// Case 3: both fail
	execLookPath = func(name string) (string, error) { return "", os.ErrNotExist }
	_, err = findRampartBinary()
	if err == nil {
		t.Error("expected error")
	}
}

func TestCreatePreToolUseScript(t *testing.T) {
	script := createPreToolUseScript("/usr/bin/rampart")
	if !strings.Contains(script, "/usr/bin/rampart") {
		t.Error("missing binary path")
	}
	if !strings.Contains(script, "--format cline") {
		t.Error("missing cline format flag")
	}
	if !strings.Contains(script, "#!/") {
		t.Error("missing shebang")
	}
}

func TestCreatePostToolUseScript(t *testing.T) {
	script := createPostToolUseScript("/usr/bin/rampart")
	if !strings.Contains(script, "/usr/bin/rampart") {
		t.Error("missing binary path")
	}
	if !strings.Contains(script, "--mode audit") {
		t.Error("missing audit mode")
	}
}

func TestInstallHookScript(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hook.sh"

	// Install
	if err := installHookScript(path, "#!/bin/bash\necho hi", false); err != nil {
		t.Fatal(err)
	}

	// Verify content
	data, _ := os.ReadFile(path)
	if string(data) != "#!/bin/bash\necho hi" {
		t.Errorf("content = %q", string(data))
	}

	// Should fail without force
	if err := installHookScript(path, "new", false); err == nil {
		t.Error("expected error for existing file without force")
	}

	// Should succeed with force
	if err := installHookScript(path, "new content", true); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != "new content" {
		t.Errorf("after force = %q", string(data))
	}
}
