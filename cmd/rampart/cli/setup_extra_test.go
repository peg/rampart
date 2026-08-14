package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/policies"
)

func TestHasRampartHook(t *testing.T) {
	tests := []struct {
		name     string
		settings claudeSettings
		want     bool
	}{
		{"empty", claudeSettings{}, false},
		{"no hooks", claudeSettings{"other": "value"}, false},
		{"hooks but no PreToolUse", claudeSettings{"hooks": map[string]any{}}, false},
		// PreToolUse alone is not enough — both post events must also be present
		// so that existing installs are upgraded to the complete lifecycle.
		{"with rampart PreToolUse only (incomplete)", claudeSettings{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "Bash",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
			},
		}, false},
		{"missing PostToolUse (incomplete)", claudeSettings{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "Bash",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
				"PostToolUseFailure": []any{
					map[string]any{
						"matcher": ".*",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
			},
		}, false},
		{"with PreToolUse and both post events (complete)", claudeSettings{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": ".*",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
				"PostToolUse": []any{
					map[string]any{
						"matcher": ".*",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
				"PostToolUseFailure": []any{
					map[string]any{
						"matcher": ".*",
						"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
					},
				},
			},
		}, true},
		{"with other hook only", claudeSettings{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "Bash",
						"hooks":   []any{map[string]any{"type": "command", "command": "other-tool"}},
					},
				},
			},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRampartHook(tt.settings); got != tt.want {
				t.Errorf("hasRampartHook() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasRampartInMatcher(t *testing.T) {
	tests := []struct {
		name    string
		matcher map[string]any
		want    bool
	}{
		{"rampart hook", map[string]any{"hooks": []any{map[string]any{"command": "rampart hook"}}}, true},
		{"quoted current hook", map[string]any{"hooks": []any{map[string]any{"command": "'/opt/Rampart App/rampart' hook --format claude-code"}}}, true},
		{"other executable with exact protocol", map[string]any{"hooks": []any{map[string]any{"command": "notify hook --format claude-code"}}}, false},
		{"protocol mentioned as an argument", map[string]any{"hooks": []any{map[string]any{"command": "notify hook --format claude-code --dry-run"}}}, false},
		{"other hook", map[string]any{"hooks": []any{map[string]any{"command": "other"}}}, false},
		{"no hooks key", map[string]any{"matcher": "Bash"}, false},
		{"empty hooks", map[string]any{"hooks": []any{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRampartInMatcher(tt.matcher); got != tt.want {
				t.Errorf("hasRampartInMatcher() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRampartFormattedHookOwnershipIsNarrow(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "bare legacy", command: "rampart hook --format codex", want: true},
		{name: "absolute legacy", command: "/retired/bin/rampart hook --format codex", want: true},
		{name: "quoted Windows legacy", command: `& "C:\Program Files\Rampart\rampart.exe" hook --format codex`, want: true},
		{name: "other executable", command: "notify hook --format codex", want: false},
		{name: "lookalike basename", command: "/tmp/rampart-old hook --format codex", want: false},
		{name: "wrapper", command: "env rampart hook --format codex", want: false},
		{name: "extra arguments", command: "rampart hook --format codex --dry-run", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := hasRampartHookFormat(testCase.command, "codex"); got != testCase.want {
				t.Fatalf("hasRampartHookFormat(%q) = %v, want %v", testCase.command, got, testCase.want)
			}
		})
	}
}

func TestSetupClaudeCode_Install(t *testing.T) {
	tmpHome := t.TempDir()
	testSetHome(t, tmpHome)

	// Mock execLookPath to avoid "not in PATH" warning
	old := execLookPath
	execLookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	defer func() { execLookPath = old }()

	opts := &rootOptions{}
	cmd := newSetupClaudeCodeCmd(opts)
	cmd.SetArgs([]string{"--force"})
	var out strings.Builder
	cmd.SetOut(&out)
	var errOut strings.Builder
	cmd.SetErr(&errOut)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "Rampart hook installed") {
		t.Errorf("output = %q", out.String())
	}
	if !strings.Contains(out.String(), "rampart init") {
		t.Errorf("expected init tip, got: %s", out.String())
	}

	// Verify settings file
	settingsPath := filepath.Join(tmpHome, ".claude", "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}

	var settings map[string]any
	json.Unmarshal(data, &settings)
	// Setup writes an absolute, shell-quoted path and an explicit hook format.
	if !strings.Contains(string(data), "hook --format claude-code") {
		t.Errorf("rampart hook not found in settings; got: %s", data)
	}
	hooks := settings["hooks"].(map[string]any)
	for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		if entries, ok := hooks[event].([]any); !ok || len(entries) != 1 {
			t.Errorf("expected one %s matcher, got %#v", event, hooks[event])
		}
	}

	// A second run must recognize the shell-quoted current command and avoid
	// duplicating any lifecycle matcher.
	second := newSetupClaudeCodeCmd(opts)
	var secondOut strings.Builder
	second.SetOut(&secondOut)
	second.SetErr(&errOut)
	if err := second.Execute(); err != nil {
		t.Fatalf("second setup failed: %v", err)
	}
	if !strings.Contains(secondOut.String(), "already configured") {
		t.Fatalf("second setup did not report idempotency: %s", secondOut.String())
	}
	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	hooks = settings["hooks"].(map[string]any)
	for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		if entries := hooks[event].([]any); len(entries) != 1 {
			t.Errorf("second setup duplicated %s: %#v", event, entries)
		}
	}
}

func TestSetupClaudeCodePreservesLargeHostInteger(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"hostSequence":9007199254740993}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newSetupClaudeCodeCmd(&rootOptions{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup claude-code: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := decodeUserJSON(data, &settings); err != nil {
		t.Fatal(err)
	}
	sequence, ok := settings["hostSequence"].(json.Number)
	if !ok || sequence.String() != "9007199254740993" {
		t.Fatalf("unrelated large integer changed: %#v", settings["hostSequence"])
	}
}

func TestClaudeConfigDirHonoredAcrossLifecycle(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	configDir := filepath.Join(home, "custom-claude")
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	t.Setenv("PATH", t.TempDir())
	managedDir := t.TempDir()
	originalManagedResolver := claudeManagedSettingsDirResolver
	claudeManagedSettingsDirResolver = func() string { return managedDir }
	t.Cleanup(func() { claudeManagedSettingsDirResolver = originalManagedResolver })

	install := newSetupClaudeCodeCmd(&rootOptions{})
	install.SetArgs([]string{"--force"})
	install.SetOut(&bytes.Buffer{})
	install.SetErr(&bytes.Buffer{})
	if err := install.Execute(); err != nil {
		t.Fatalf("setup claude-code: %v", err)
	}

	settingsPath := filepath.Join(configDir, "settings.json")
	if _, err := os.Stat(settingsPath); err != nil {
		t.Fatalf("custom Claude settings were not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("default Claude settings unexpectedly written: %v", err)
	}
	if !claudeHooksConfiguredForHome(home) || !claudeRampartHooksPresent(home) {
		t.Fatal("custom Claude config was not recognized by configured/uninstall detection")
	}

	var hookStatus string
	doctorHooks(func(name, status, _ string) {
		if name == "Hooks" {
			hookStatus = status
		}
	})
	if hookStatus != "ok" {
		t.Fatalf("doctor Claude hook status = %q, want ok", hookStatus)
	}

	remove := newSetupClaudeCodeCmd(&rootOptions{})
	remove.SetArgs([]string{"--remove"})
	remove.SetOut(&bytes.Buffer{})
	remove.SetErr(&bytes.Buffer{})
	if err := remove.Execute(); err != nil {
		t.Fatalf("remove claude-code: %v", err)
	}
	if claudeRampartHooksPresent(home) {
		t.Fatal("custom Claude config still contains Rampart hooks after removal")
	}
}

func TestConfiguredAgentHomeExpandsPortableTilde(t *testing.T) {
	home := t.TempDir()
	for _, configured := range []string{"~", "~/agents/claude", `~\agents\claude`} {
		t.Run(configured, func(t *testing.T) {
			t.Setenv("CLAUDE_CONFIG_DIR", configured)
			want := home
			if configured != "~" {
				want = filepath.Join(home, "agents", "claude")
			}
			if got := claudeConfigDir(home); got != want {
				t.Fatalf("claudeConfigDir(%q) = %q, want %q", configured, got, want)
			}
		})
	}
}

func TestSetupOpenClaw_AlreadyConfiguredMessage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("openclaw setup is not supported on windows")
	}
	tmpHome := t.TempDir()
	testSetHome(t, tmpHome)

	shimPath := filepath.Join(tmpHome, ".local", "bin", "rampart-shim")
	if err := os.MkdirAll(filepath.Dir(shimPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shimPath, []byte("#!/usr/bin/env bash\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := newSetupOpenClawCmd(&rootOptions{})
	cmd.SetArgs([]string{"--shim-only"})
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "Already configured (pass --force to reconfigure)") {
		t.Fatalf("expected already-configured message, got: %s", got)
	}
	if strings.Contains(got, "Use --force to overwrite") {
		t.Fatalf("did not expect legacy overwrite prompt, got: %s", got)
	}
}

func TestSetupClaudeCode_UpgradesLegacyHookCommand(t *testing.T) {
	tmpHome := t.TempDir()
	testSetHome(t, tmpHome)
	oldLookPath := execLookPath
	oldExecutable := osExecutable
	execLookPath = func(name string) (string, error) { return filepath.Join(tmpHome, "bin", name), nil }
	osExecutable = func() (string, error) { return filepath.Join(tmpHome, "bin", "rampart"), nil }
	defer func() {
		execLookPath = oldLookPath
		osExecutable = oldExecutable
	}()

	claudeDir := filepath.Join(tmpHome, ".claude")
	os.MkdirAll(claudeDir, 0o755)

	// All three lifecycle events exist, but point at the legacy PATH-dependent
	// command and must be refreshed to the current resolved binary.
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{"matcher": "Bash", "hooks": []any{map[string]any{"type": "command", "command": "rampart hook"}}},
			},
			"PostToolUse": []any{
				map[string]any{"matcher": ".*", "hooks": []any{map[string]any{"type": "command", "command": "rampart hook"}}},
			},
			"PostToolUseFailure": []any{
				map[string]any{"matcher": ".*", "hooks": []any{map[string]any{"type": "command", "command": "rampart hook"}}},
			},
		},
	}
	data, _ := json.MarshalIndent(settings, "", "  ")
	os.WriteFile(filepath.Join(claudeDir, "settings.json"), data, 0o644)
	if claudeHooksConfiguredForHome(tmpHome) {
		t.Fatal("stale Claude hook commands must not be reported as currently configured")
	}
	if check := verifyClaudeHooksInstalled(); check.Status != verificationFail || !strings.Contains(check.Actual, "stale") {
		t.Fatalf("stale Claude verification = %#v", check)
	}

	opts := &rootOptions{}
	cmd := newSetupClaudeCodeCmd(opts)
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(out.String(), "already configured") {
		t.Fatalf("stale hook was incorrectly treated as current: %s", out.String())
	}
	updated, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := shellQuoteCodexHookArg(toGitBashPath(filepath.Join(tmpHome, "bin", "rampart"))) + " hook --format claude-code"
	if !strings.Contains(string(updated), want) || strings.Contains(string(updated), `"command": "rampart hook"`) {
		t.Fatalf("legacy hook was not refreshed to %q: %s", want, updated)
	}
	if !claudeHooksConfiguredForHome(tmpHome) {
		t.Fatal("refreshed Claude hook commands were not reported as configured")
	}
}

func TestSetupClaudeCodeInvalidHookShapesRequireForceAndPreserveSettings(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		initial string
	}{
		{name: "hooks is not an object", initial: `{"permissions":{"allow":["Read"]},"hooks":"host-value"}`},
		{name: "event is not an array", initial: `{"permissions":{"allow":["Read"]},"hooks":{"PreToolUse":"host-value"}}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			testSetHome(t, home)
			settingsPath := filepath.Join(home, ".claude", "settings.json")
			if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settingsPath, []byte(testCase.initial), 0o600); err != nil {
				t.Fatal(err)
			}

			if err := testExecuteRoot(t, "setup", "claude-code"); err == nil || !strings.Contains(err.Error(), "--force") {
				t.Fatalf("invalid hook shape error = %v, want --force guidance", err)
			}
			unchanged, err := os.ReadFile(settingsPath)
			if err != nil || string(unchanged) != testCase.initial {
				t.Fatalf("refused setup changed settings: data=%q err=%v", unchanged, err)
			}

			if err := testExecuteRoot(t, "setup", "claude-code", "--force"); err != nil {
				t.Fatalf("forced setup: %v", err)
			}
			settings := testReadJSONMap(t, settingsPath)
			if _, ok := settings["permissions"]; !ok {
				t.Fatalf("forced hook repair discarded unrelated settings: %#v", settings)
			}
		})
	}
}

func TestClaudeConfiguredRequiresFullMatcherCoverage(t *testing.T) {
	expected := currentClaudeHookCommand()
	settings := claudeSettings{"hooks": map[string]any{}}
	hooks := settings["hooks"].(map[string]any)
	for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		matcher := ".*"
		if event == "PreToolUse" {
			matcher = "Bash"
		}
		hooks[event] = []any{map[string]any{
			"matcher": matcher,
			"hooks":   []any{map[string]any{"type": "command", "command": expected}},
		}}
	}
	if claudeHooksUseCommand(settings, expected) {
		t.Fatal("an exact command under a narrowed matcher must not establish complete protection")
	}
}

func TestSetupClaudeCodeInstallAndRemoveRefuseSymlinkedSettings(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "operator-settings.json")
	initial := []byte(`{"permissions":{"allow":["Read"]}}`)
	if err := os.WriteFile(target, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, settingsPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	for _, args := range [][]string{{"setup", "claude-code"}, {"setup", "claude-code", "--remove"}} {
		if err := testExecuteRoot(t, args...); err == nil || !strings.Contains(err.Error(), "linked") {
			t.Fatalf("%v error = %v, want symlink refusal", args, err)
		}
	}
	if info, err := os.Lstat(settingsPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("settings symlink was replaced: info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != string(initial) {
		t.Fatalf("settings target changed: data=%q err=%v", data, err)
	}
}

func TestReadLine(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader("hello\nworld\n"))
	if got := readLine(scanner); got != "hello" {
		t.Errorf("first line = %q", got)
	}
	if got := readLine(scanner); got != "world" {
		t.Errorf("second line = %q", got)
	}
	// EOF
	if got := readLine(scanner); got != "\x00" {
		t.Errorf("EOF = %q", got)
	}
}

func TestReadLine_Empty(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader(""))
	if got := readLine(scanner); got != "\x00" {
		t.Errorf("empty = %q", got)
	}
}

func TestInstallPolicy(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer

	if err := installPolicy(&buf, dir, "standard"); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(dir, ".rampart", "policies", "standard.yaml")
	content, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal("policy file not created")
	}
	if !strings.HasPrefix(string(content), "# rampart-policy-version: ") {
		snippet := string(content)
		if len(snippet) > 40 {
			snippet = snippet[:40]
		}
		t.Fatalf("expected installed policy to be version stamped, got: %q", snippet)
	}

	// Run again - should say already exists
	buf.Reset()
	if err := installPolicy(&buf, dir, "standard"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "already exists") {
		t.Errorf("expected already exists, got: %s", buf.String())
	}
}

func TestInstallOpenClawPolicyVersionStamped(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	var out bytes.Buffer

	if err := installOpenClawPolicy(&out, &out); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(dir, ".rampart", "policies", "openclaw.yaml")
	content, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal("openclaw policy file not created")
	}
	if !strings.HasPrefix(string(content), "# rampart-policy-version: ") {
		snippet := string(content)
		if len(snippet) > 40 {
			snippet = snippet[:40]
		}
		t.Fatalf("expected installed OpenClaw policy to be version stamped, got: %q", snippet)
	}
	version, hash, installedContent := parseManagedPolicyHeaders(content)
	if version != build.Version || hash == "" {
		t.Fatalf("managed headers = version %q hash %q, want version %q and a content hash", version, hash, build.Version)
	}
	embedded, err := policies.Profile("openclaw")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installedContent, embedded) {
		t.Fatal("installed OpenClaw policy payload does not match the embedded profile")
	}
}

func TestManagedPolicyHeadersPreserveEmbeddedReleaseMetadata(t *testing.T) {
	payload := []byte("# rampart-policy-version: 1.5.0\n# Rampart built-in profile: openclaw\nversion: \"1\"\npolicies: []\n")
	installed := versionStampedPolicyContentForVersion(payload, "1.6.0")

	version, hash, content := parseManagedPolicyHeaders(installed)
	if version != "1.6.0" || hash == "" {
		t.Fatalf("managed headers = version %q hash %q, want outer version and hash", version, hash)
	}
	if !bytes.Equal(content, payload) {
		t.Fatalf("managed payload was truncated at embedded release metadata:\n%s", content)
	}
}
