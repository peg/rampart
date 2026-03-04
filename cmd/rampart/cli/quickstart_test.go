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
	"runtime"
	"testing"

	"github.com/peg/rampart/internal/detect"
)

func TestDetectEnv_MultiAgentDetection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH shim binaries in this test are Unix-only")
	}

	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("CLINE_ACTIVE", "1")
	t.Setenv("OPENCLAW_SERVICE_MARKER", "openclaw")

	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	writeTestExecutable(t, filepath.Join(binDir, "codex"))
	t.Setenv("PATH", binDir)

	got, err := detect.Environment()
	if err != nil {
		t.Fatalf("detect.Environment() error = %v", err)
	}
	if !got.ClaudeCode || !got.HasCodex || !got.HasCline || !got.HasOpenClaw || !got.HasCursor {
		t.Fatalf("expected multi-agent detection, got %+v", got)
	}
}

func TestQuickstartSelectAgents_DefaultAllDetected(t *testing.T) {
	result := &detect.DetectResult{ClaudeCode: true, HasCodex: true, HasCursor: true}

	selected, err := selectQuickstartAgents(result, "", "")
	if err != nil {
		t.Fatalf("selectQuickstartAgents error = %v", err)
	}
	if len(selected) != 3 {
		t.Fatalf("expected 3 selected agents, got %d", len(selected))
	}
	if selected[0].Key != "claude-code" || selected[1].Key != "codex" || selected[2].Key != "cursor" {
		t.Fatalf("unexpected selected order: %+v", selected)
	}
}

func TestQuickstartSelectAgents_AgentsFlagOverride(t *testing.T) {
	result := &detect.DetectResult{ClaudeCode: true}

	selected, err := selectQuickstartAgents(result, "codex,cursor", "")
	if err != nil {
		t.Fatalf("selectQuickstartAgents error = %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("expected 2 selected agents, got %d", len(selected))
	}
	if selected[0].Key != "codex" || selected[1].Key != "cursor" {
		t.Fatalf("unexpected selected agents: %+v", selected)
	}
}

func TestQuickstartSelectAgents_EnvAliasOverride(t *testing.T) {
	result := &detect.DetectResult{}

	selected, err := selectQuickstartAgents(result, "", "openclaw")
	if err != nil {
		t.Fatalf("selectQuickstartAgents error = %v", err)
	}
	if len(selected) != 1 || selected[0].Key != "openclaw" {
		t.Fatalf("unexpected selected agents: %+v", selected)
	}
}

func TestQuickstartSuggestedPolicies(t *testing.T) {
	result := &detect.DetectResult{
		HasKubectl:     true,
		HasDocker:      true,
		HasNode:        true,
		HasTerraform:   true,
		HasAWSCLI:      true,
		AWSCredentials: true,
	}

	got := suggestedPolicies(result, map[string]bool{})
	want := []string{"kubernetes", "docker", "terraform", "node-python", "aws-cli"}
	if len(got) != len(want) {
		t.Fatalf("suggestedPolicies length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("suggestedPolicies[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestQuickstartSuggestedPolicies_SkipsInstalled(t *testing.T) {
	result := &detect.DetectResult{HasKubectl: true, HasDocker: true, HasNode: true}
	installed := map[string]bool{"docker": true, "node-python": true}

	got := suggestedPolicies(result, installed)
	if len(got) != 1 || got[0] != "kubernetes" {
		t.Fatalf("suggestedPolicies() = %v, want [kubernetes]", got)
	}
}

func TestQuickstartUnsupportedAgentWrapSuggestion(t *testing.T) {
	selected, err := selectQuickstartAgents(&detect.DetectResult{HasCursor: true}, "", "")
	if err != nil {
		t.Fatalf("selectQuickstartAgents error = %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("expected one selected agent, got %d", len(selected))
	}
	if selected[0].HasSetup {
		t.Fatal("cursor should be unsupported (HasSetup=false)")
	}
	if selected[0].WrapCmd != "rampart wrap -- cursor" {
		t.Fatalf("wrap cmd = %q, want cursor wrap command", selected[0].WrapCmd)
	}
}

func TestQuickstartCmd_Flags(t *testing.T) {
	cmd := newQuickstartCmd()

	agentsFlag := cmd.Flags().Lookup("agents")
	if agentsFlag == nil {
		t.Fatal("--agents flag not registered")
	}
	envFlag := cmd.Flags().Lookup("env")
	if envFlag == nil {
		t.Fatal("--env alias flag not registered")
	}
	if !envFlag.Hidden {
		t.Fatal("--env flag should be hidden")
	}
	profileFlag := cmd.Flags().Lookup("profile")
	if profileFlag == nil {
		t.Fatal("--profile flag not registered")
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

func TestQuickstartHooksConfigured_Codex(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	wrapperPath := filepath.Join(home, ".local", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(wrapperPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapperPath, []byte("#!/bin/sh\nexec rampart preload -- /usr/bin/codex \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !quickstartHooksConfigured("codex") {
		t.Fatal("expected codex wrapper to be detected")
	}
}

func TestQuickstartHooksConfigured_Cline(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	pre := filepath.Join(home, "Documents", "Cline", "Hooks", "PreToolUse", "rampart-policy")
	post := filepath.Join(home, "Documents", "Cline", "Hooks", "PostToolUse", "rampart-audit")
	if err := os.MkdirAll(filepath.Dir(pre), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(post), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pre, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(post, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !quickstartHooksConfigured("cline") {
		t.Fatal("expected cline hooks to be detected")
	}
}

func writeTestExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write test executable %s: %v", path, err)
	}
}
