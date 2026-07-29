// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCurrentClaudeHookSettings(t *testing.T, home string, extra map[string]any) {
	t.Helper()
	command := currentClaudeHookCommand()
	hooks := map[string]any{}
	for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		hooks[event] = []any{map[string]any{
			"matcher": ".*",
			"hooks":   []any{map[string]any{"type": "command", "command": command}},
		}}
	}
	settings := map[string]any{"hooks": hooks}
	for key, value := range extra {
		settings[key] = value
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	path := claudeSettingsPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeDisabledUserHooksFailVerificationAndStatus(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Chdir(t.TempDir())
	managedDir := t.TempDir()
	originalResolver := claudeManagedSettingsDirResolver
	claudeManagedSettingsDirResolver = func() string { return managedDir }
	t.Cleanup(func() { claudeManagedSettingsDirResolver = originalResolver })
	writeCurrentClaudeHookSettings(t, home, map[string]any{"disableAllHooks": true})

	check := verifyClaudeHooksInstalled()
	if check.Status != verificationFail || check.Actual != "configured but disabled" || !strings.Contains(check.Message, "disableAllHooks=true") {
		t.Fatalf("verification = %#v", check)
	}
	if containsString(detectProtectedAgents(), "Claude Code (hooks)") {
		t.Fatal("status reported Claude Code protected while disableAllHooks=true")
	}

	var doctorStatus, doctorMessage string
	doctorHooks(func(name, status, message string) {
		if name == "Hooks" && strings.Contains(message, "Claude Code") {
			doctorStatus, doctorMessage = status, message
		}
	})
	if doctorStatus != "fail" || !strings.Contains(doctorMessage, "will not load") {
		t.Fatalf("doctor status=%q message=%q", doctorStatus, doctorMessage)
	}
}

func TestClaudeProjectSettingOverridesUserDisableAllHooks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	writeCurrentClaudeHookSettings(t, home, map[string]any{"disableAllHooks": true})
	project := t.TempDir()
	projectConfig := filepath.Join(project, ".claude")
	if err := os.MkdirAll(projectConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectConfig, "settings.json"), []byte(`{"disableAllHooks":false}`), 0o600); err != nil {
		t.Fatal(err)
	}

	assessment := assessClaudeHookLoading(home, project, t.TempDir())
	if assessment.Blocked || assessment.Unverified {
		t.Fatalf("project override assessment = %#v", assessment)
	}
}

func TestClaudeAncestorProjectDisableAllHooksIsDetected(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	nested := filepath.Join(project, "src", "nested")
	if err := os.MkdirAll(filepath.Join(project, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(project, ".claude", "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	assessment := assessClaudeHookLoading(home, nested, t.TempDir())
	if !assessment.Blocked || assessment.Unverified || !strings.Contains(assessment.Reason, settingsPath) {
		t.Fatalf("ancestor project assessment = %#v", assessment)
	}
}

func TestClaudeConflictingAncestorSettingsAreUnverified(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	nested := filepath.Join(project, "nested")
	for path, data := range map[string][]byte{
		filepath.Join(project, ".claude", "settings.json"): []byte(`{"disableAllHooks":true}`),
		filepath.Join(nested, ".claude", "settings.json"):  []byte(`{"disableAllHooks":false}`),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	assessment := assessClaudeHookLoading(home, nested, t.TempDir())
	if !assessment.Unverified || assessment.Blocked || !strings.Contains(assessment.Reason, "conflicting disableAllHooks") {
		t.Fatalf("conflicting project assessment = %#v", assessment)
	}
}

func TestClaudeManagedDropInBlocksUserHooks(t *testing.T) {
	home := t.TempDir()
	managedDir := t.TempDir()
	dropInDir := filepath.Join(managedDir, "managed-settings.d")
	if err := os.MkdirAll(dropInDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(managedDir, "managed-settings.json"), []byte(`{"allowManagedHooksOnly":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dropInDir, "50-hooks.json")
	if err := os.WriteFile(policyPath, []byte(`{"allowManagedHooksOnly":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	assessment := assessClaudeHookLoading(home, t.TempDir(), managedDir)
	if !assessment.Blocked || assessment.Unverified || !strings.Contains(assessment.Reason, policyPath) || !strings.Contains(assessment.Reason, "allowManagedHooksOnly=true") {
		t.Fatalf("managed hook assessment = %#v", assessment)
	}
}

func TestClaudeUnreadableEffectiveSettingsAreUnverified(t *testing.T) {
	project := t.TempDir()
	configDir := filepath.Join(project, ".claude")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "settings.local.json"), []byte(`{"disableAllHooks":`), 0o600); err != nil {
		t.Fatal(err)
	}

	assessment := assessClaudeHookLoading(t.TempDir(), project, t.TempDir())
	if !assessment.Unverified || assessment.Blocked || !strings.Contains(assessment.Reason, "parse Claude settings") {
		t.Fatalf("malformed project settings assessment = %#v", assessment)
	}
}
