package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain keeps every test away from a real Claude Code installation:
// detection reports "unknown" unless a test installs its own stub.
func TestMain(m *testing.M) {
	detectClaudeVersion = func() (claudeVersion, bool) { return claudeVersion{}, false }
	os.Exit(m.Run())
}

func stubClaudeVersion(t *testing.T, version claudeVersion, known bool) {
	t.Helper()
	previous := detectClaudeVersion
	detectClaudeVersion = func() (claudeVersion, bool) { return version, known }
	t.Cleanup(func() { detectClaudeVersion = previous })
}

func forbidClaudeDetection(t *testing.T) {
	t.Helper()
	previous := detectClaudeVersion
	detectClaudeVersion = func() (claudeVersion, bool) {
		t.Error("Claude Code version must not be probed in this scenario")
		return claudeVersion{}, false
	}
	t.Cleanup(func() { detectClaudeVersion = previous })
}

func claudeFailureTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	return home
}

func runClaudeSetup(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newSetupClaudeCodeCmd(&rootOptions{})
	cmd.SetArgs(args)
	var out, errOut strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	err := cmd.Execute()
	return out.String(), err
}

func readClaudeSettings(t *testing.T, home string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	return settings
}

// rampartHookIn returns the single Rampart-owned hook for an event.
func rampartHookIn(t *testing.T, settings map[string]any, event string) map[string]any {
	t.Helper()
	hook, ok := findRampartHook(settings, event)
	if !ok {
		t.Fatalf("no Rampart hook for %s in %#v", event, settings["hooks"])
	}
	return hook
}

func findRampartHook(settings map[string]any, event string) (map[string]any, bool) {
	hooks, _ := settings["hooks"].(map[string]any)
	entries, _ := hooks[event].([]any)
	for _, rawMatcher := range entries {
		matcher, _ := rawMatcher.(map[string]any)
		rawHooks, _ := matcher["hooks"].([]any)
		for _, rawHook := range rawHooks {
			hook, _ := rawHook.(map[string]any)
			if command, _ := hook["command"].(string); isRampartClaudeHookCommand(command) {
				return hook, true
			}
		}
	}
	return nil, false
}

func TestParseClaudeVersionAndComparison(t *testing.T) {
	for _, tc := range []struct {
		output string
		want   claudeVersion
		ok     bool
	}{
		{"2.1.295 (Claude Code)\n", claudeVersion{2, 1, 295}, true},
		{"v2.1.300", claudeVersion{2, 1, 300}, true},
		{"Claude Code 3.0.0-beta.1", claudeVersion{3, 0, 0}, true},
		{"", claudeVersion{}, false},
		{"no version here", claudeVersion{}, false},
		{"2.1", claudeVersion{}, false},
	} {
		got, ok := parseClaudeVersion(tc.output)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseClaudeVersion(%q) = %v, %v; want %v, %v", tc.output, got, ok, tc.want, tc.ok)
		}
	}
	for _, tc := range []struct {
		version claudeVersion
		want    bool
	}{
		{claudeVersion{2, 1, 295}, true},
		{claudeVersion{2, 1, 294}, false},
		{claudeVersion{2, 1, 1000}, true},
		{claudeVersion{2, 2, 0}, true},
		{claudeVersion{3, 0, 0}, true},
		{claudeVersion{1, 99, 999}, false},
		{claudeVersion{2, 0, 999}, false},
	} {
		if got := tc.version.atLeast(claudeOnFailureMinVersion); got != tc.want {
			t.Errorf("%s.atLeast(%s) = %v, want %v", tc.version, claudeOnFailureMinVersion, got, tc.want)
		}
	}
}

func TestPlanClaudeHookFailure(t *testing.T) {
	supported := func() (claudeVersion, bool) { return claudeVersion{2, 1, 295}, true }
	older := func() (claudeVersion, bool) { return claudeVersion{2, 1, 294}, true }
	unknown := func() (claudeVersion, bool) { return claudeVersion{}, false }
	mustNotProbe := func() (claudeVersion, bool) {
		t.Error("version probe must not run")
		return claudeVersion{}, false
	}
	for _, tc := range []struct {
		name            string
		mode            string
		installed       bool
		currentlyBlocks bool
		detect          func() (claudeVersion, bool)
		wantBlock       bool
		wantErr         string
		wantNotice      string
	}{
		{"fresh auto on supported version fails closed", "auto", false, false, supported, true, "", "Undo with"},
		{"fresh auto on newer version fails closed", "auto", false, false, func() (claudeVersion, bool) { return claudeVersion{2, 3, 0}, true }, true, "", "Undo with"},
		{"fresh auto on older version stays open and says why", "auto", false, false, older, false, "", "cannot fail closed"},
		{"fresh auto on unknown version stays open and says why", "auto", false, false, unknown, false, "", "Could not detect"},
		{"existing auto never changes the mode but offers it", "auto", true, false, supported, false, "", "Enable with"},
		{"existing auto on older version is silent", "auto", true, false, older, false, "", ""},
		{"existing auto keeps fail-closed without probing", "auto", true, true, mustNotProbe, true, "", ""},
		{"block on supported version", "block", true, false, supported, true, "", ""},
		{"block refuses an unknown version", "block", true, false, unknown, false, "could not be detected", ""},
		{"block refuses an older version", "block", true, false, older, false, "older than", ""},
		{"continue never probes", "continue", true, true, mustNotProbe, false, "", ""},
		{"invalid mode is rejected", "sometimes", false, false, supported, false, "invalid --hook-failure", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planClaudeHookFailure(tc.mode, tc.installed, tc.currentlyBlocks, tc.detect)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.Block != tc.wantBlock {
				t.Errorf("Block = %v, want %v", plan.Block, tc.wantBlock)
			}
			if tc.wantNotice == "" && plan.Notice != "" {
				t.Errorf("unexpected notice %q", plan.Notice)
			}
			if tc.wantNotice != "" && !strings.Contains(plan.Notice, tc.wantNotice) {
				t.Errorf("notice %q does not contain %q", plan.Notice, tc.wantNotice)
			}
		})
	}
}

func TestSetupClaudeCodeFreshInstallFailsClosedOnSupportedVersion(t *testing.T) {
	home := claudeFailureTestHome(t)
	stubClaudeVersion(t, claudeVersion{2, 1, 295}, true)

	out, err := runClaudeSetup(t)
	if err != nil {
		t.Fatal(err)
	}
	settings := readClaudeSettings(t, home)
	if got := rampartHookIn(t, settings, "PreToolUse")["onFailure"]; got != "block" {
		t.Fatalf("PreToolUse onFailure = %v, want block", got)
	}
	for _, event := range []string{"PostToolUse", "PostToolUseFailure"} {
		if _, present := rampartHookIn(t, settings, event)["onFailure"]; present {
			t.Errorf("%s must keep Claude Code's default failure behavior", event)
		}
	}
	if !strings.Contains(out, "Hook failures block tool calls") {
		t.Errorf("output does not explain the fail-closed mode: %s", out)
	}
}

func TestSetupClaudeCodeFreshInstallDoesNotWriteOnFailureWhenUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version claudeVersion
		known   bool
	}{
		{"older host", claudeVersion{2, 1, 294}, true},
		{"undetected host", claudeVersion{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := claudeFailureTestHome(t)
			stubClaudeVersion(t, tc.version, tc.known)
			if _, err := runClaudeSetup(t); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("onFailure")) {
				t.Fatalf("onFailure must never be written for an unsupported or unknown host: %s", data)
			}
		})
	}
}

func TestSetupClaudeCodeAutoLeavesExistingInstallUnchanged(t *testing.T) {
	home := claudeFailureTestHome(t)
	stubClaudeVersion(t, claudeVersion{}, false)
	if _, err := runClaudeSetup(t); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".claude", "settings.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	stubClaudeVersion(t, claudeVersion{2, 1, 295}, true)
	out, err := runClaudeSetup(t)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("auto mode rewrote an existing installation:\nbefore: %s\nafter: %s", before, after)
	}
	if !strings.Contains(out, "already configured") || !strings.Contains(out, "--hook-failure=block") {
		t.Errorf("output should report idempotency and offer the opt-in: %s", out)
	}
}

func TestSetupClaudeCodeAutoKeepsExistingFailClosedWithoutProbing(t *testing.T) {
	home := claudeFailureTestHome(t)
	stubClaudeVersion(t, claudeVersion{2, 1, 295}, true)
	if _, err := runClaudeSetup(t); err != nil {
		t.Fatal(err)
	}
	forbidClaudeDetection(t)
	out, err := runClaudeSetup(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "already configured") {
		t.Errorf("expected idempotent run, got: %s", out)
	}
	if got := rampartHookIn(t, readClaudeSettings(t, home), "PreToolUse")["onFailure"]; got != "block" {
		t.Fatalf("existing fail-closed mode was lost: %v", got)
	}
}

func TestSetupClaudeCodeExplicitBlockUpgradesExistingInstallPreservingUserSettings(t *testing.T) {
	home := claudeFailureTestHome(t)
	stubClaudeVersion(t, claudeVersion{}, false)
	if _, err := runClaudeSetup(t); err != nil {
		t.Fatal(err)
	}

	// The user customized Rampart's own entry and added their own hook and settings.
	path := filepath.Join(home, ".claude", "settings.json")
	settings := readClaudeSettings(t, home)
	rampartHookIn(t, settings, "PreToolUse")["timeout"] = float64(45)
	preToolUse := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	userHook := map[string]any{"type": "command", "command": "/usr/local/bin/audit-tool", "onFailure": "continue"}
	settings["hooks"].(map[string]any)["PreToolUse"] = append(preToolUse, map[string]any{"matcher": "Bash", "hooks": []any{userHook}})
	settings["model"] = "custom-model"
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	stubClaudeVersion(t, claudeVersion{2, 1, 300}, true)
	if _, err := runClaudeSetup(t, "--hook-failure=block"); err != nil {
		t.Fatal(err)
	}

	got := readClaudeSettings(t, home)
	hook := rampartHookIn(t, got, "PreToolUse")
	if hook["onFailure"] != "block" {
		t.Errorf("onFailure = %v, want block", hook["onFailure"])
	}
	if hook["timeout"] != float64(45) {
		t.Errorf("user's timeout on Rampart's hook was dropped: %v", hook["timeout"])
	}
	if got["model"] != "custom-model" {
		t.Errorf("unrelated setting was lost: %v", got["model"])
	}
	foundUser := false
	for _, rawMatcher := range got["hooks"].(map[string]any)["PreToolUse"].([]any) {
		matcher := rawMatcher.(map[string]any)
		for _, rawHook := range matcher["hooks"].([]any) {
			candidate := rawHook.(map[string]any)
			if candidate["command"] == "/usr/local/bin/audit-tool" {
				foundUser = true
				if candidate["onFailure"] != "continue" {
					t.Errorf("another tool's hook was modified: %v", candidate)
				}
			}
		}
	}
	if !foundUser {
		t.Error("another tool's PreToolUse hook was removed")
	}
	if n := len(got["hooks"].(map[string]any)["PreToolUse"].([]any)); n != 2 {
		t.Errorf("PreToolUse matchers = %d, want Rampart's plus the user's", n)
	}
}

func TestSetupClaudeCodeExplicitBlockRefusesUnsupportedHostWithoutWriting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version claudeVersion
		known   bool
		want    string
	}{
		{"older host", claudeVersion{2, 1, 294}, true, "older than"},
		{"undetected host", claudeVersion{}, false, "could not be detected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := claudeFailureTestHome(t)
			stubClaudeVersion(t, claudeVersion{}, false)
			if _, err := runClaudeSetup(t); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, ".claude", "settings.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			stubClaudeVersion(t, tc.version, tc.known)
			_, err = runClaudeSetup(t, "--hook-failure=block")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("a refused request must leave settings untouched")
			}
		})
	}
}

func TestSetupClaudeCodeContinueRemovesOnFailureOnlyFromRampartHook(t *testing.T) {
	home := claudeFailureTestHome(t)
	stubClaudeVersion(t, claudeVersion{2, 1, 295}, true)
	if _, err := runClaudeSetup(t); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".claude", "settings.json")
	settings := readClaudeSettings(t, home)
	userHook := map[string]any{"type": "command", "command": "/usr/local/bin/other", "onFailure": "block"}
	preToolUse := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	settings["hooks"].(map[string]any)["PreToolUse"] = append(preToolUse, map[string]any{"matcher": "Edit", "hooks": []any{userHook}})
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	forbidClaudeDetection(t)
	if _, err := runClaudeSetup(t, "--hook-failure=continue"); err != nil {
		t.Fatal(err)
	}
	got := readClaudeSettings(t, home)
	if _, present := rampartHookIn(t, got, "PreToolUse")["onFailure"]; present {
		t.Error("continue must remove onFailure from Rampart's hook")
	}
	kept := false
	for _, rawMatcher := range got["hooks"].(map[string]any)["PreToolUse"].([]any) {
		for _, rawHook := range rawMatcher.(map[string]any)["hooks"].([]any) {
			if hook := rawHook.(map[string]any); hook["command"] == "/usr/local/bin/other" && hook["onFailure"] == "block" {
				kept = true
			}
		}
	}
	if !kept {
		t.Error("another tool's onFailure was removed")
	}
}

func TestSetupClaudeCodeRejectsInvalidHookFailureMode(t *testing.T) {
	home := claudeFailureTestHome(t)
	if _, err := runClaudeSetup(t, "--hook-failure=sometimes"); err == nil || !strings.Contains(err.Error(), "invalid --hook-failure") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err == nil {
		t.Fatal("an invalid mode must not create settings")
	}
}

func TestVerifyClaudeHooksReportsFailureMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version claudeVersion
		known   bool
		want    string
	}{
		{"fail closed", claudeVersion{2, 1, 295}, true, "onFailure=block"},
		{"fail open", claudeVersion{}, false, "do not block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claudeFailureTestHome(t)
			stubClaudeVersion(t, tc.version, tc.known)
			if _, err := runClaudeSetup(t); err != nil {
				t.Fatal(err)
			}
			check := verifyClaudeHooksInstalled()
			if check.Status != verificationPass {
				t.Fatalf("status = %s (%s)", check.Status, check.Message)
			}
			if !strings.Contains(check.Message, tc.want) {
				t.Errorf("message %q does not contain %q", check.Message, tc.want)
			}
		})
	}
}
