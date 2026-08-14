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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	selected, err := selectQuickstartAgents(result, "")
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

	selected, err := selectQuickstartAgents(result, "codex,cursor")
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

func TestQuickstartSelectAgents_AgentsFlagSingleAgent(t *testing.T) {
	result := &detect.DetectResult{}

	selected, err := selectQuickstartAgents(result, "openclaw")
	if err != nil {
		t.Fatalf("selectQuickstartAgents error = %v", err)
	}
	if len(selected) != 1 || selected[0].Key != "openclaw" {
		t.Fatalf("unexpected selected agents: %+v", selected)
	}
}

func TestQuickstartSelectAgents_NoneDisablesDetectedAgents(t *testing.T) {
	result := &detect.DetectResult{
		ClaudeCode:     true,
		HasCodex:       true,
		HasCline:       true,
		HasOpenClaw:    true,
		HasCopilot:     true,
		HasAntigravity: true,
	}

	selected, err := selectQuickstartAgents(result, " none ")
	if err != nil {
		t.Fatalf("selectQuickstartAgents error = %v", err)
	}
	if len(selected) != 0 {
		t.Fatalf("--agents none selected %+v; want explicit opt-out", selected)
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
	selected, err := selectQuickstartAgents(&detect.DetectResult{HasCursor: true}, "")
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
	cmd := newQuickstartCmd(&rootOptions{})

	agentsFlag := cmd.Flags().Lookup("agents")
	if agentsFlag == nil {
		t.Fatal("--agents flag not registered")
	}
	// --env was removed in v0.9.9 (deprecated alias for --agents)
	envFlag := cmd.Flags().Lookup("env")
	if envFlag != nil {
		t.Fatal("--env flag should be removed in v0.9.9")
	}
	profileFlag := cmd.Flags().Lookup("profile")
	if profileFlag == nil {
		t.Fatal("--profile flag not registered")
	}
}

func TestQuickstartProtectionTargetsUseManagedOpenClawPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenClaw managed protection is not supported on Windows")
	}
	drivers, unsupported, err := quickstartProtectionTargets([]quickstartAgent{
		{Key: "openclaw", Name: "OpenClaw", HasSetup: true, SetupCmd: "openclaw"},
		{Key: "cursor", Name: "Cursor", WrapCmd: "rampart wrap -- cursor"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(drivers) != 1 || drivers[0].ID != "openclaw" || !drivers[0].OpenClaw {
		t.Fatalf("managed drivers = %#v, want OpenClaw protect driver", drivers)
	}
	if len(unsupported) != 1 || unsupported[0].Key != "cursor" {
		t.Fatalf("unsupported = %#v, want Cursor wrap guidance", unsupported)
	}
}

func TestQuickstartAgentsUseCurrentNativeRegistry(t *testing.T) {
	agents := quickstartAgents()
	byKey := make(map[string]quickstartAgent, len(agents))
	for _, agent := range agents {
		byKey[agent.Key] = agent
	}
	for _, key := range []string{"claude-code", "codex", "cline", "openclaw", "copilot", "antigravity"} {
		agent, ok := byKey[key]
		if !ok || !agent.HasSetup || agent.SetupCmd != key {
			t.Errorf("native quickstart entry %q = %+v, present=%v", key, agent, ok)
		}
	}
	if _, ok := byKey["gemini"]; ok {
		t.Fatal("experimental Gemini integration must not be auto-configured by quickstart")
	}
	if byKey["copilot"].WrapCmd != "" {
		t.Fatal("current Copilot integration must not use obsolete gh-copilot wrap guidance")
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
	for _, name := range []string{"custom.yaml", "guard.yaml"} {
		if err := os.WriteFile(filepath.Join(policyDir, name), []byte("version: \"1\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if hasInstalledPolicy() {
		t.Fatal("supplemental custom and Guard files must not suppress base profile initialization")
	}
	if err := os.WriteFile(filepath.Join(policyDir, "standard.yaml"), []byte("version: \"1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !hasInstalledPolicy() {
		t.Fatal("expected policy to be detected")
	}
}

func TestQuickstartFreshHomeInstallsSelectedProfileBeforeGuard(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Chdir(t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service": "rampart", "status": "ok", "mode": "enforce",
			"version": "test", "uptime_seconds": 1,
		})
	}))
	defer server.Close()
	t.Setenv("RAMPART_URL", server.URL)

	var out, errOut bytes.Buffer
	cmd := NewRootCmd(context.Background(), &out, &errOut)
	if err := runQuickstart(cmd, &rootOptions{configPath: "rampart.yaml"}, "none", "", true, false); err != nil {
		t.Fatalf("runQuickstart: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	for _, name := range []string{"standard.yaml", "guard.yaml"} {
		if _, err := os.Stat(filepath.Join(home, ".rampart", "policies", name)); err != nil {
			t.Fatalf("fresh quickstart did not install %s: %v", name, err)
		}
	}
}

func TestQuickstartRejectsCustomConfigBeforeMutation(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	custom := filepath.Join(home, "custom.yaml")
	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	err := runQuickstart(cmd, &rootOptions{configPath: custom}, "none", "", true, false)
	if err == nil || !strings.Contains(err.Error(), "custom --config is not supported") {
		t.Fatalf("error = %v, want fail-closed custom config rejection", err)
	}
	for _, path := range []string{custom, filepath.Join(home, ".rampart")} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("custom config rejection mutated %s: %v", path, statErr)
		}
	}
}

func writeTestExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write test executable %s: %v", path, err)
	}
}
