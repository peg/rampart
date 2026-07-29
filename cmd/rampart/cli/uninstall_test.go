// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRampartLaunchdServicesIncludeCurrentAndLegacyLabels(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "test")
	services := rampartLaunchdServices(home)
	got := make([]string, 0, len(services))
	for _, service := range services {
		got = append(got, service.PlistPath)
	}
	want := []string{
		filepath.Join(home, "Library", "LaunchAgents", "sh.rampart.serve.plist"),
		filepath.Join(home, "Library", "LaunchAgents", "com.rampart.proxy.plist"),
		filepath.Join(home, "Library", "LaunchAgents", "com.rampart.serve.plist"),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("launchd paths = %v, want %v", got, want)
	}
}

func TestConfirmUninstallUsesProvidedInput(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  bool
	}{
		{input: "yes\n", want: true},
		{input: "Y\n", want: true},
		{input: "no\n", want: false},
		{input: "", want: false},
	} {
		var out bytes.Buffer
		got, err := confirmUninstall(strings.NewReader(tt.input), &out)
		if err != nil {
			t.Fatalf("confirmUninstall(%q): %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("confirmUninstall(%q) = %t, want %t", tt.input, got, tt.want)
		}
		if !strings.Contains(out.String(), "Continue?") {
			t.Errorf("missing prompt for %q: %q", tt.input, out.String())
		}
	}
}

func TestTeardownManagedRuntimePreservesServiceAfterIntegrationFailure(t *testing.T) {
	var out bytes.Buffer
	stopCalled := false
	servicesCalled := false
	removed, failed, preserved := teardownManagedRuntime(
		&out,
		t.TempDir(),
		"linux",
		nil,
		true,
		func(io.Writer, bool) error {
			stopCalled = true
			return nil
		},
		func(string, string, commandRunner) ([]string, []string) {
			servicesCalled = true
			return nil, nil
		},
	)
	if !preserved || stopCalled || servicesCalled || len(removed) != 0 || len(failed) != 0 {
		t.Fatalf("preserved=%t stop=%t services=%t removed=%v failed=%v", preserved, stopCalled, servicesCalled, removed, failed)
	}
	if !strings.Contains(out.String(), "Preserving rampart serve") {
		t.Fatalf("missing preservation explanation: %q", out.String())
	}
}

func TestTeardownManagedRuntimeStopsBackgroundBeforeServices(t *testing.T) {
	var calls []string
	removed, failed, preserved := teardownManagedRuntime(
		io.Discard,
		t.TempDir(),
		"linux",
		nil,
		false,
		func(io.Writer, bool) error {
			calls = append(calls, "stop-background")
			return nil
		},
		func(string, string, commandRunner) ([]string, []string) {
			calls = append(calls, "remove-services")
			return []string{"service"}, nil
		},
	)
	if preserved || len(failed) != 0 || strings.Join(removed, ",") != "service" {
		t.Fatalf("preserved=%t removed=%v failed=%v", preserved, removed, failed)
	}
	if got := strings.Join(calls, ","); got != "stop-background,remove-services" {
		t.Fatalf("calls = %q", got)
	}
}

func TestTeardownManagedRuntimePreservesRuntimeAfterPartialFailure(t *testing.T) {
	removed, failed, preserved := teardownManagedRuntime(
		io.Discard,
		t.TempDir(),
		"linux",
		nil,
		false,
		func(io.Writer, bool) error { return io.ErrUnexpectedEOF },
		func(string, string, commandRunner) ([]string, []string) {
			return []string{"one service"}, []string{"second service could not be removed"}
		},
	)
	if !preserved || len(removed) != 1 || len(failed) != 2 {
		t.Fatalf("preserved=%t removed=%v failed=%v", preserved, removed, failed)
	}
}

func TestRemoveManagedServeServicesUsesExactLinuxUnits(t *testing.T) {
	home := t.TempDir()
	serviceDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rampart-serve.service", "rampart-proxy.service"} {
		content := "[Service]\nExecStart=/home/user/bin/rampart serve --port 9090\n"
		if err := os.WriteFile(filepath.Join(serviceDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var calls []string
	runner := func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		return exec.Command(os.Args[0], "-test.run=^$")
	}
	removed, failed := removeManagedServeServices(home, "linux", runner)
	if len(failed) != 0 {
		t.Fatalf("unexpected failures: %v", failed)
	}
	if len(removed) != 2 {
		t.Fatalf("removed=%v, want both managed services", removed)
	}
	wantCalls := []string{
		"systemctl --user stop rampart-serve.service",
		"systemctl --user disable rampart-serve.service",
		"systemctl --user stop rampart-proxy.service",
		"systemctl --user disable rampart-proxy.service",
		"systemctl --user daemon-reload",
	}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("service calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(wantCalls, "\n"))
	}
	for _, name := range []string{"rampart-serve.service", "rampart-proxy.service"} {
		if _, err := os.Stat(filepath.Join(serviceDir, name)); !os.IsNotExist(err) {
			t.Errorf("managed unit %s still exists: %v", name, err)
		}
	}
}

func TestRemoveManagedServeServicesPreservesUnrecognizedUnit(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".config", "systemd", "user", "rampart-serve.service")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[Service]\nExecStart=/usr/bin/unrelated serve\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	called := false
	runner := func(name string, args ...string) *exec.Cmd {
		called = true
		return exec.Command(os.Args[0], "-test.run=^$")
	}
	removed, failed := removeManagedServeServices(home, "linux", runner)
	if len(removed) != 0 || len(failed) != 1 {
		t.Fatalf("removed=%v failed=%v", removed, failed)
	}
	if called {
		t.Fatal("unrecognized service must not trigger systemctl")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unrecognized service was removed: %v", err)
	}
}

func TestManagedSystemdServiceRequiresExactlyOneExecStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rampart-serve.service")
	content := "[Service]\nExecStart=/usr/local/bin/rampart serve\nExecStart=/usr/bin/unrelated\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	managed, err := managedSystemdServiceFile(path)
	if err == nil || managed || !strings.Contains(err.Error(), "2 ExecStart") {
		t.Fatalf("managed=%t err=%v, want duplicate ExecStart refusal", managed, err)
	}
}

func TestRampartServeServiceIdentityRequiresServeSubcommand(t *testing.T) {
	if !isRampartServeArguments([]string{"/usr/local/bin/rampart", "serve", "--port", "9090"}) {
		t.Fatal("generated serve arguments were not recognized")
	}
	if isRampartServeArguments([]string{"/usr/local/bin/rampart", "doctor", "--output", "serve"}) {
		t.Fatal("a later serve option value must not establish service ownership")
	}
}

func TestRemoveManagedServeServicesUsesExactLaunchdLabel(t *testing.T) {
	home := t.TempDir()
	services := rampartLaunchdServices(home)
	service := services[0]
	if err := os.MkdirAll(filepath.Dir(service.PlistPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>` + service.Label + `</string>
<key>ProgramArguments</key><array><string>/usr/local/bin/rampart</string><string>serve</string></array>
</dict></plist>`
	if err := os.WriteFile(service.PlistPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	runner := func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		return exec.Command(os.Args[0], "-test.run=^$")
	}
	removed, failed := removeManagedServeServices(home, "darwin", runner)
	if len(failed) != 0 || len(removed) != 1 {
		t.Fatalf("removed=%v failed=%v", removed, failed)
	}
	wantCalls := []string{
		"launchctl list " + service.Label,
		"launchctl remove " + service.Label,
	}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("launchd calls=%v want=%v", calls, wantCalls)
	}
	if _, err := os.Stat(service.PlistPath); !os.IsNotExist(err) {
		t.Fatalf("managed plist still exists: %v", err)
	}
}

func TestManagedLaunchdServiceRequiresRampartExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "com.rampart.proxy.plist")
	content := `<?xml version="1.0"?><plist><dict>
<key>Label</key><string>com.rampart.proxy</string>
<key>ProgramArguments</key><array><string>/usr/local/bin/unrelated</string><string>serve</string></array>
</dict></plist>`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	managed, err := managedLaunchdServiceFile(path, "com.rampart.proxy")
	if err == nil || managed {
		t.Fatalf("managed=%t err=%v, want ownership refusal", managed, err)
	}
}

func TestManagedLaunchdServiceRejectsDuplicateIdentityKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sh.rampart.serve.plist")
	content := `<?xml version="1.0"?><plist><dict>
<key>Label</key><string>sh.rampart.serve</string>
<key>Label</key><string>sh.rampart.serve</string>
<key>ProgramArguments</key><array><string>/usr/local/bin/rampart</string><string>serve</string></array>
</dict></plist>`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	managed, err := managedLaunchdServiceFile(path, "sh.rampart.serve")
	if err == nil || managed || !strings.Contains(err.Error(), "duplicate Label") {
		t.Fatalf("managed=%t err=%v, want duplicate identity refusal", managed, err)
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
