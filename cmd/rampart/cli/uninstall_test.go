// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRampartLaunchdServicePathsIncludeCurrentAndLegacyLabels(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "test")
	got := rampartLaunchdServicePaths(home)
	want := []string{
		filepath.Join(home, "Library", "LaunchAgents", "sh.rampart.serve.plist"),
		filepath.Join(home, "Library", "LaunchAgents", "com.rampart.proxy.plist"),
		filepath.Join(home, "Library", "LaunchAgents", "com.rampart.serve.plist"),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("launchd paths = %v, want %v", got, want)
	}
}

func TestWindowsStopServeScriptUsesProcessCommandLineAndExcludesUninstaller(t *testing.T) {
	script := windowsStopServeScript(4242)
	for _, want := range []string{
		"Get-CimInstance Win32_Process",
		"$uninstallPid=4242",
		"$_.ProcessId -ne $uninstallPid",
		"$_.CommandLine -like '*serve*'",
		"Invoke-CimMethod",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("stop script missing %q: %s", want, script)
		}
	}
	if strings.Contains(script, "Get-Process") {
		t.Fatalf("stop script uses Get-Process, whose Process objects do not reliably expose CommandLine: %s", script)
	}
}

func TestRemoveManagedAgentIntegrationsIsComprehensiveAndPreservesUserState(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Chdir(t.TempDir())
	t.Setenv("PATH", t.TempDir())
	oldPolicyPath := copilotPolicyHookPathForRuntime
	copilotPolicyHookPathForRuntime = func() string { return filepath.Join(home, "machine-policy", "50-rampart.json") }
	t.Cleanup(func() { copilotPolicyHookPathForRuntime = oldPolicyPath })

	claudePath := filepath.Join(home, ".claude", "settings.json")
	claudeConfig := `{
  "memory": "keep-claude",
  "hooks": {
    "PreToolUse": [
      {"matcher":"custom","hooks":[{"type":"command","command":"custom-hook"}]},
      {"matcher":"*","hooks":[{"type":"command","command":"rampart hook --format claude-code"}]}
    ],
    "PostToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"rampart hook --format claude-code"}]}],
    "PostToolUseFailure": [{"matcher":"*","hooks":[{"type":"command","command":"rampart hook --format claude-code"}]}]
  }
}`
	if err := os.MkdirAll(filepath.Dir(claudePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudePath, []byte(claudeConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	codexPath := filepath.Join(codexHomeDir(home), "hooks.json")
	if err := os.MkdirAll(filepath.Dir(codexPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexPath, []byte(`{"memory":"keep-codex","hooks":{"PreToolUse":[{"matcher":"custom","hooks":[]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installCodexHooks(codexPath, "rampart hook --format codex", "rampart.exe hook --format codex", false); err != nil {
		t.Fatal(err)
	}

	geminiPath := filepath.Join(home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(geminiPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geminiPath, []byte(`{"memory":"keep-gemini","hooks":{"BeforeTool":[{"matcher":"custom","hooks":[]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installGeminiHooks(geminiPath, "rampart hook --format gemini", false); err != nil {
		t.Fatal(err)
	}

	copilotPath := filepath.Join(copilotHomeDir(home), "hooks", copilotRampartHookFile)
	if err := installCopilotHooks(copilotPath, "rampart hook --format copilot", "rampart.exe hook --format copilot", false); err != nil {
		t.Fatal(err)
	}
	copilotSibling := filepath.Join(filepath.Dir(copilotPath), "operator.json")
	if err := os.WriteFile(copilotSibling, []byte(`{"keep":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	antigravityDir := antigravityPluginDir(home)
	if err := installAntigravityPlugin(antigravityDir, "rampart hook --format antigravity", false); err != nil {
		t.Fatal(err)
	}
	antigravitySibling := filepath.Join(filepath.Dir(antigravityDir), "operator-plugin", "memory.txt")
	if err := os.MkdirAll(filepath.Dir(antigravitySibling), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(antigravitySibling, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	clineDir := clineUserHooksDir(home)
	if _, _, err := installClineHooks(clineDir, "rampart", runtime.GOOS, false); err != nil {
		t.Fatal(err)
	}
	clineSibling := filepath.Join(clineDir, "operator-hook")
	if err := os.WriteFile(clineSibling, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	removed, failed := removeManagedAgentIntegrations(cmd, &rootOptions{}, home)
	if len(failed) != 0 {
		t.Fatalf("unexpected removal failures: %v\nstderr: %s", failed, stderr.String())
	}
	if len(removed) != 6 {
		t.Fatalf("removed %d integrations, want 6: %v\nstdout: %s", len(removed), removed, stdout.String())
	}

	for _, check := range []struct {
		name string
		ok   bool
	}{
		{name: "Claude hooks removed", ok: !claudeRampartHooksPresent(home)},
		{name: "Codex hooks removed", ok: !codexHooksConfiguredForHome(home)},
		{name: "Gemini hooks removed", ok: !geminiHooksConfiguredForHome(home)},
		{name: "Copilot hook removed", ok: !copilotHooksConfiguredForHome(home)},
		{name: "Antigravity plugin removed", ok: !antigravityPluginConfiguredForHome(home)},
		{name: "Cline hooks removed", ok: !clineManagedHooksPresentInDir(clineDir)},
		{name: "Claude config preserved", ok: fileContains(claudePath, "keep-claude") && fileContains(claudePath, "custom-hook")},
		{name: "Codex config preserved", ok: fileContains(codexPath, "keep-codex") && fileContains(codexPath, "custom")},
		{name: "Gemini config preserved", ok: fileContains(geminiPath, "keep-gemini") && fileContains(geminiPath, "custom")},
		{name: "Copilot sibling preserved", ok: fileContains(copilotSibling, "keep")},
		{name: "Antigravity sibling preserved", ok: fileContains(antigravitySibling, "keep")},
		{name: "Cline sibling preserved", ok: fileContains(clineSibling, "keep")},
	} {
		if !check.ok {
			t.Errorf("%s", check.name)
		}
	}

	stdout.Reset()
	stderr.Reset()
	removed, failed = removeManagedAgentIntegrations(cmd, &rootOptions{}, home)
	if len(removed) != 0 || len(failed) != 0 {
		t.Fatalf("second removal should be a no-op: removed=%v failed=%v", removed, failed)
	}
}
