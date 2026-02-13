// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveClaudeCodeHooks_WithHooks(t *testing.T) {
	// Set up a temp home with settings containing rampart hooks
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	settings := map[string]any{
		"permissions": map[string]any{"allow": []any{"Bash"}},
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
				},
				map[string]any{
					"matcher": "Read",
					"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
				},
				map[string]any{
					"matcher": "Write|Edit",
					"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(settings, "", "  ")
	settingsPath := filepath.Join(claudeDir, "settings.json")
	os.WriteFile(settingsPath, data, 0o644)

	opts := &rootOptions{}
	cmd := newSetupClaudeCodeCmd(opts)
	cmd.SetArgs([]string{"--remove"})
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "Removed 3 Rampart hook(s)") {
		t.Errorf("expected removal message, got: %s", out.String())
	}

	// Verify hooks key was cleaned up
	result, _ := os.ReadFile(settingsPath)
	var parsed map[string]any
	json.Unmarshal(result, &parsed)

	if _, ok := parsed["hooks"]; ok {
		t.Error("expected hooks key to be removed when empty")
	}
	// Verify other settings preserved
	if _, ok := parsed["permissions"]; !ok {
		t.Error("expected permissions to be preserved")
	}
}

func TestRemoveClaudeCodeHooks_NoHooks(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	opts := &rootOptions{}
	cmd := newSetupClaudeCodeCmd(opts)
	cmd.SetArgs([]string{"--remove"})
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "Nothing to remove") {
		t.Errorf("expected nothing-to-remove message, got: %s", out.String())
	}
}

func TestRemoveClaudeCodeHooks_PreservesNonRampart(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	os.MkdirAll(claudeDir, 0o755)

	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks":   []any{map[string]any{"type": "command", "command": "other-tool check"}},
				},
				map[string]any{
					"matcher": "Bash",
					"hooks":   []any{map[string]any{"type": "command", "command": "rampart hook"}},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(settings, "", "  ")
	settingsPath := filepath.Join(claudeDir, "settings.json")
	os.WriteFile(settingsPath, data, 0o644)

	opts := &rootOptions{}
	cmd := newSetupClaudeCodeCmd(opts)
	cmd.SetArgs([]string{"--remove"})
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := os.ReadFile(settingsPath)
	var parsed map[string]any
	json.Unmarshal(result, &parsed)

	hooks := parsed["hooks"].(map[string]any)
	preToolUse := hooks["PreToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Errorf("expected 1 remaining hook, got %d", len(preToolUse))
	}
}

func TestRemoveClineHooks_WithHooks(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	hookDir := filepath.Join(tmpHome, "Documents", "Cline", "Hooks")
	preDir := filepath.Join(hookDir, "PreToolUse")
	postDir := filepath.Join(hookDir, "PostToolUse")
	os.MkdirAll(preDir, 0o755)
	os.MkdirAll(postDir, 0o755)
	os.WriteFile(filepath.Join(preDir, "rampart-policy"), []byte("#!/bin/bash\n"), 0o755)
	os.WriteFile(filepath.Join(postDir, "rampart-audit"), []byte("#!/bin/bash\n"), 0o755)

	opts := &rootOptions{}
	cmd := newSetupClineCmd(opts)
	cmd.SetArgs([]string{"--remove"})
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "Removed 2 Rampart hook(s)") {
		t.Errorf("expected removal message, got: %s", out.String())
	}
}

func TestRemoveClineHooks_NoHooks(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	opts := &rootOptions{}
	cmd := newSetupClineCmd(opts)
	cmd.SetArgs([]string{"--remove"})
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "Nothing to remove") {
		t.Errorf("expected nothing-to-remove message, got: %s", out.String())
	}
}

func TestRemoveClineHooks_Workspace(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	hookDir := filepath.Join(tmpDir, ".clinerules", "hooks")
	preDir := filepath.Join(hookDir, "PreToolUse")
	os.MkdirAll(preDir, 0o755)
	os.WriteFile(filepath.Join(preDir, "rampart-policy"), []byte("#!/bin/bash\n"), 0o755)

	opts := &rootOptions{}
	cmd := newSetupClineCmd(opts)
	cmd.SetArgs([]string{"--remove", "--workspace"})
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "Removed 1 Rampart hook(s)") {
		t.Errorf("expected removal message, got: %s", out.String())
	}
}
