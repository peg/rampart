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
	"testing"
)

func TestDetectEnv_OpenClaw(t *testing.T) {
	t.Setenv("OPENCLAW_SERVICE_MARKER", "openclaw")
	if got := detectEnv(); got != "openclaw" {
		t.Errorf("expected openclaw, got %q", got)
	}
}

func TestDetectEnv_ClaudeCode(t *testing.T) {
	// Ensure OpenClaw marker is absent so Claude Code takes priority.
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")
	t.Setenv("CLINE_ACTIVE", "")
	t.Setenv("CLINE_SESSION", "")

	// Create a temp claude settings file
	tmp := t.TempDir()
	testSetHome(t, tmp)

	if err := os.MkdirAll(filepath.Join(tmp, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".claude", "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := detectEnv(); got != "claude-code" {
		t.Errorf("expected claude-code, got %q", got)
	}
}

func TestDetectEnv_None(t *testing.T) {
	// Ensure OpenClaw marker is absent.
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")
	t.Setenv("CLINE_ACTIVE", "")
	t.Setenv("CLINE_SESSION", "")

	tmp := t.TempDir()
	testSetHome(t, tmp)

	// Ensure 'claude' binary is not in PATH for this test.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	if got := detectEnv(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestDetectEnv_ClineFromEnv(t *testing.T) {
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")
	t.Setenv("CLINE_ACTIVE", "1")
	t.Setenv("CLINE_SESSION", "")

	if got := detectEnv(); got != "cline" {
		t.Errorf("expected cline, got %q", got)
	}
}

func TestDetectEnv_ClineFromExtensionDir(t *testing.T) {
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")
	t.Setenv("CLINE_ACTIVE", "")
	t.Setenv("CLINE_SESSION", "")

	tmp := t.TempDir()
	testSetHome(t, tmp)

	if err := os.MkdirAll(filepath.Join(tmp, ".vscode", "extensions", "cline-1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := detectEnv(); got != "cline" {
		t.Errorf("expected cline, got %q", got)
	}
}

func TestDetectEnv_ClinePreferredOverClaudeCode(t *testing.T) {
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")
	t.Setenv("CLINE_ACTIVE", "1")
	t.Setenv("CLINE_SESSION", "")

	tmp := t.TempDir()
	testSetHome(t, tmp)

	if err := os.MkdirAll(filepath.Join(tmp, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".claude", "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := detectEnv(); got != "cline" {
		t.Errorf("expected cline, got %q", got)
	}
}

func TestQuickstartCmd_Help(t *testing.T) {
	cmd := newQuickstartCmd()
	if cmd.Use != "quickstart" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}
	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}
}

func TestQuickstartCmd_Flags(t *testing.T) {
	cmd := newQuickstartCmd()

	envFlag := cmd.Flags().Lookup("env")
	if envFlag == nil {
		t.Fatal("--env flag not registered")
	}

	skipFlag := cmd.Flags().Lookup("skip-doctor")
	if skipFlag == nil {
		t.Fatal("--skip-doctor flag not registered")
	}
}

func TestHasInstalledPolicy(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	if hasInstalledPolicy() {
		t.Fatal("expected no policy to be detected in empty home")
	}

	policyDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "standard.yaml"), []byte("version: \"1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !hasInstalledPolicy() {
		t.Fatal("expected policy to be detected")
	}
}

func TestQuickstartHooksConfigured_OpenClaw(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	if quickstartHooksConfigured("openclaw") {
		t.Fatal("expected openclaw hooks to be false without shim")
	}

	shimPath := filepath.Join(home, ".local", "bin", "rampart-shim")
	if err := os.MkdirAll(filepath.Dir(shimPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shimPath, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	if !quickstartHooksConfigured("openclaw") {
		t.Fatal("expected openclaw hooks to be true with shim")
	}
}

func TestQuickstartHooksConfigured_ClaudeCode(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
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
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	if !quickstartHooksConfigured("claude-code") {
		t.Fatal("expected claude-code hooks to be detected")
	}
}
