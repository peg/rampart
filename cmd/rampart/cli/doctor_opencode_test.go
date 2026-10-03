// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorOpenCodeHooksChecksStaticFilesWithoutLoadingHost(t *testing.T) {
	for _, tc := range []struct {
		name, fixture, status, message string
		installed                      bool
		issues, checks                 int
	}{
		{name: "undetected", checks: 0},
		{name: "installed missing plugin", installed: true, status: "fail", message: "not installed", issues: 1, checks: 1},
		{name: "current plugin without host", fixture: "current", status: "ok", message: "static check only; host loading unverified", checks: 1},
		{name: "stale executable", fixture: "stale", status: "fail", message: "executable binding is stale", issues: 1, checks: 1},
		{name: "owned source drift", fixture: "drift", status: "fail", message: "source or Rampart executable binding is stale", issues: 1, checks: 1},
		{name: "unowned collision", fixture: "unowned", status: "fail", message: "not owned by Rampart", issues: 1, checks: 1},
		{name: "linked plugin", fixture: "symlink", status: "fail", message: "unsafe or unreadable", issues: 1, checks: 1},
		{name: "hard-linked plugin", fixture: "hardlink", status: "fail", message: "unsafe or unreadable", issues: 1, checks: 1},
		{name: "nonregular plugin", fixture: "directory", status: "fail", message: "unsafe or unreadable", issues: 1, checks: 1},
		{name: "linked config directory", fixture: "config symlink", installed: true, status: "fail", message: "unsafe or unreadable", issues: 1, checks: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			config := filepath.Join(home, "config")
			t.Setenv("OPENCODE_CONFIG_DIR", config)
			t.Setenv("XDG_CONFIG_HOME", "")
			binary := filepath.Join(home, "rampart-candidate")
			oldExecutable, oldLookPath := osExecutable, execLookPath
			osExecutable = func() (string, error) { return binary, nil }
			execLookPath = func(name string) (string, error) {
				if name == "opencode" && tc.installed {
					// Existence detection must not run this executable.
					return filepath.Join(home, "host-must-not-run"), nil
				}
				return "", os.ErrNotExist
			}
			t.Cleanup(func() { osExecutable, execLookPath = oldExecutable, oldLookPath })
			path := openCodePluginPath(home)
			if tc.fixture != "" {
				if err := installOpenCodePlugin(path, binary); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.fixture {
			case "stale":
				if err := installOpenCodePlugin(path, filepath.Join(home, "rampart-retired")); err != nil {
					t.Fatal(err)
				}
			case "drift":
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString("\n// stale managed source\n"); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "unowned":
				if err := os.WriteFile(path, []byte("export default () => {};\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				alias := filepath.Join(home, "operator.js")
				if err := os.Rename(path, alias); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if tc.fixture == "hardlink" {
					link = os.Link
				}
				if err := link(alias, path); err != nil {
					t.Skipf("creating %s unavailable: %v", tc.fixture, err)
				}
			case "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "config symlink":
				alias := filepath.Join(home, "actual-config")
				if err := os.Rename(config, alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(alias, config); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			before, _ := os.ReadFile(path)
			var checks []checkResult
			issues := doctorOpenCodeHooks(func(name, status, message string) {
				checks = append(checks, checkResult{Name: name, Status: status, Message: message})
			}, home)
			if issues != tc.issues || len(checks) != tc.checks {
				t.Fatalf("doctor = %d issues, %#v; want %d issues, %d checks", issues, checks, tc.issues, tc.checks)
			}
			if len(checks) != 0 && (checks[0].Name != "OpenCode plugin" || checks[0].Status != tc.status || !strings.Contains(checks[0].Message, tc.message)) {
				t.Fatalf("doctor check = %#v, want %q containing %q", checks[0], tc.status, tc.message)
			}
			if tc.status == "ok" && !strings.Contains(checks[0].Message, "ask decisions refuse execution") {
				t.Fatal("static diagnostic must retain the approval limitation")
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Fatal("static doctor check changed plugin contents")
			}
		})
	}
}

func TestDoctorHooksIncludesOpenCodeStaticCheck(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("OPENCODE_CONFIG_DIR", filepath.Join(home, "opencode"))
	oldExecutable, oldLookPath := osExecutable, execLookPath
	binary := filepath.Join(home, "rampart-candidate")
	osExecutable = func() (string, error) { return binary, nil }
	execLookPath = func(string) (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { osExecutable, execLookPath = oldExecutable, oldLookPath })
	if err := installOpenCodePlugin(openCodePluginPath(home), binary); err != nil {
		t.Fatal(err)
	}
	found := false
	issues := doctorHooks(func(name, status, message string) {
		if name == "OpenCode plugin" {
			found = status == "ok" && strings.Contains(message, "host loading unverified")
		}
	})
	if issues != 0 || !found {
		t.Fatalf("doctorHooks = %d issues; OpenCode static check found = %t", issues, found)
	}
}
