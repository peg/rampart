// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	opencodeplugin "github.com/peg/rampart/internal/plugin/opencode"
	"github.com/spf13/cobra"
)

func TestOpenCodeConfigDirectoryMatchesHostDiscovery(t *testing.T) {
	home := t.TempDir()
	xdg := filepath.Join(t.TempDir(), "xdg")
	custom := filepath.Join(t.TempDir(), "custom config")
	for _, tc := range []struct {
		name, xdg, custom, want string
	}{
		{"default", "", "", filepath.Join(home, ".config", "opencode")},
		{"xdg", xdg, "", filepath.Join(xdg, "opencode")},
		{"relative xdg ignored", "relative-xdg", "", filepath.Join(home, ".config", "opencode")},
		{"custom wins", xdg, custom, custom},
		{"relative custom", xdg, "relative-config", "relative-config"},
		{"literal custom", xdg, "$HOME/literal", filepath.Join("$HOME", "literal")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", tc.xdg)
			t.Setenv("OPENCODE_CONFIG_DIR", tc.custom)
			if got := openCodeConfigDir(home); got != tc.want {
				t.Fatalf("config directory = %q, want %q", got, tc.want)
			}
			if got := openCodePluginPath(home); got != filepath.Join(tc.want, "plugins", "rampart.js") {
				t.Fatalf("plugin path = %q", got)
			}
		})
	}
}

func TestOpenCodeInstallRepairsOwnedPluginAtomicallyAndPreservesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opencode", "plugins", "rampart.js")
	oldBinary := filepath.Join(t.TempDir(), "rampart-retired")
	currentBinary := filepath.Join(t.TempDir(), "rampart-current")
	if err := installOpenCodePlugin(path, oldBinary); err != nil {
		t.Fatal(err)
	}
	oldInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Ownership survives a stale executable and a drifted managed body.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("\n// stale owned customization\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(filepath.Dir(path), "operator.js")
	settings := filepath.Join(filepath.Dir(filepath.Dir(path)), "opencode.json")
	for _, unrelated := range []string{sibling, settings} {
		if err := os.WriteFile(unrelated, []byte("keep operator data\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := installOpenCodePlugin(path, currentBinary); err != nil {
		t.Fatal(err)
	}
	currentInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(oldInfo, currentInfo) {
		t.Fatal("owned plugin update must replace the file atomically")
	}
	if runtime.GOOS != "windows" && currentInfo.Mode().Perm() != 0o600 {
		t.Fatalf("installed plugin mode = %o, want 600", currentInfo.Mode().Perm())
	}
	if err := installOpenCodePlugin(path, currentBinary); err != nil {
		t.Fatalf("repeat installation: %v", err)
	}
	want, err := opencodeplugin.Render(currentBinary)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("installed source differs from current bound template: %v", err)
	}
	if err := installOpenCodePlugin(path, "rampart"); err == nil {
		t.Fatal("invalid executable binding was accepted")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
		t.Fatal("rejected executable binding changed the enforcing plugin")
	}
	removed, err := removeOpenCodePlugin(path)
	if err != nil || !removed {
		t.Fatalf("remove = (%v, %v)", removed, err)
	}
	if removed, err := removeOpenCodePlugin(path); err != nil || removed {
		t.Fatalf("repeat remove = (%v, %v)", removed, err)
	}
	for _, unrelated := range []string{sibling, settings} {
		got, err := os.ReadFile(unrelated)
		if err != nil || string(got) != "keep operator data\n" {
			t.Fatalf("operator file changed: %s: %v", unrelated, err)
		}
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("removal deleted the shared plugins directory: %v", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".rampart-write-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("installation left temporary files: %v, %v", leftovers, err)
	}
}

func TestOpenCodeInstallerRefusesUnownedCollisionAndLinkedFiles(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "rampart")
	for _, kind := range []string{"unowned", "marker mention", "directory", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "opencode", "plugins", "rampart.js")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			var alias string
			switch kind {
			case "unowned", "marker mention":
				data := "export default () => {};\n"
				if kind == "marker mention" {
					data += "// Rampart OpenCode policy gate\n"
				}
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				alias = filepath.Join(t.TempDir(), "operator.js")
				data, err := opencodeplugin.Render(binary)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(alias, data, 0o600); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if kind == "hardlink" {
					link = os.Link
				}
				if err := link(alias, path); err != nil {
					t.Skipf("creating %s unavailable: %v", kind, err)
				}
			}
			before, _ := os.ReadFile(path)
			if err := installOpenCodePlugin(path, binary); err == nil {
				t.Fatal("installation accepted an unowned or linked collision")
			}
			if removed, err := removeOpenCodePlugin(path); err == nil || removed {
				t.Fatalf("remove = (%v, %v), want refusal", removed, err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("refusal changed collision: %v", err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed collision contents")
			}
			if alias != "" {
				got, err := os.ReadFile(alias)
				if err != nil || !bytes.Equal(got, before) {
					t.Fatal("refusal changed the linked operator file")
				}
			}
		})
	}
}

func TestOpenCodeInstallerRefusesLinkedDirectories(t *testing.T) {
	for _, name := range []string{"config", "plugins"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			target := t.TempDir()
			config := filepath.Join(root, "opencode")
			linked := config
			if name == "plugins" {
				if err := os.Mkdir(config, 0o700); err != nil {
					t.Fatal(err)
				}
				linked = filepath.Join(config, "plugins")
			}
			if err := os.Symlink(target, linked); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			path := filepath.Join(config, "plugins", "rampart.js")
			if err := installOpenCodePlugin(path, filepath.Join(root, "rampart")); err == nil {
				t.Fatal("installation followed a linked directory")
			}
			if removed, err := removeOpenCodePlugin(path); err == nil || removed {
				t.Fatalf("remove = (%v, %v), want directory-link refusal", removed, err)
			}
			entries, err := os.ReadDir(target)
			if err != nil || len(entries) != 0 {
				t.Fatal("installation changed the directory-link target")
			}
		})
	}
}

func TestSetupOpenCodeBindsExecutingBinaryAndReportsStaticScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("experimental OpenCode setup supports Linux and macOS")
	}
	home := t.TempDir()
	testSetHome(t, home)
	t.Chdir(t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("OPENCODE_CONFIG_DIR", filepath.Join(home, "custom config"))
	oldExecutable, oldLookPath := osExecutable, execLookPath
	binary := filepath.Join(home, "rampart-candidate")
	osExecutable = func() (string, error) { return binary, nil }
	execLookPath = func(string) (string, error) { return filepath.Join(home, "older-rampart"), nil }
	t.Cleanup(func() { osExecutable, execLookPath = oldExecutable, oldLookPath })
	cmd := newSetupOpenCodeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if cmd.Flags().Lookup("force") != nil {
		t.Fatal("OpenCode installer must not offer overwriting operator files")
	}
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Host loading has not been verified") || !strings.Contains(out.String(), "Ask decisions refuse execution") {
		t.Fatalf("setup overstated its verification/approval scope: %s", out.String())
	}
	if !openCodePluginConfiguredForHome(home) {
		t.Fatal("current executable binding should be recognized as configured")
	}
	osExecutable = func() (string, error) { return filepath.Join(home, "rampart-next"), nil }
	if openCodePluginConfiguredForHome(home) {
		t.Fatal("stale executable binding must not be reported as current")
	}
	remove := newSetupOpenCodeCmd()
	if err := remove.Flags().Set("remove", "true"); err != nil {
		t.Fatal(err)
	}
	remove.SetOut(&out)
	if err := remove.RunE(remove, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(openCodePluginPath(home)); !os.IsNotExist(err) {
		t.Fatalf("plugin remains after remove: %v", err)
	}
}

func TestUninstallOpenCodeRemovesOnlyOwnedGlobalPlugin(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Chdir(t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("PATH", t.TempDir())
	for _, key := range []string{"CLAUDE_CONFIG_DIR", "HERMES_HOME", "COPILOT_HOME", "OPENCLAW_CONFIG_PATH", "APPDATA", "LOCALAPPDATA", "ProgramData"} {
		t.Setenv(key, "")
	}
	t.Setenv("OPENCLAW_STATE_DIR", filepath.Join(home, ".openclaw"))
	t.Setenv("RAMPART_OPENCLAW_BIN", filepath.Join(home, "missing-openclaw"))
	oldPolicyPath := copilotPolicyHookPathForRuntime
	copilotPolicyHookPathForRuntime = func() string { return filepath.Join(home, "machine-policy", "50-rampart.json") }
	t.Cleanup(func() { copilotPolicyHookPathForRuntime = oldPolicyPath })
	path := openCodePluginPath(home)
	if err := installOpenCodePlugin(path, filepath.Join(home, "rampart")); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(filepath.Dir(path), "operator.js")
	if err := os.WriteFile(sibling, []byte("operator content"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	removed, failed := removeManagedAgentIntegrations(cmd, &rootOptions{}, home)
	if len(failed) != 0 || len(removed) != 1 || removed[0] != "OpenCode plugin" {
		t.Fatalf("uninstall = removed %v, failed %v", removed, failed)
	}
	if data, err := os.ReadFile(sibling); err != nil || string(data) != "operator content" {
		t.Fatalf("uninstall changed sibling plugin: %v", err)
	}
}
