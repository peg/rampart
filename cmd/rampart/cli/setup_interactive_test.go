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
	"os"
	"path/filepath"
	"testing"
)

func TestDetectAgents_ReturnsAllKnownAgents(t *testing.T) {
	agents := detectAgents()
	if len(agents) != 7 {
		t.Fatalf("expected 7 agents, got %d", len(agents))
	}

	names := map[string]bool{}
	for _, a := range agents {
		names[a.Name] = true
	}

	for _, want := range []string{"Claude Code", "Cline", "OpenClaw", "Codex", "Aider", "Cursor", "Windsurf"} {
		if !names[want] {
			t.Errorf("missing agent %q", want)
		}
	}
}

func TestDetectAgents_ClaudeCodeDetectedByDir(t *testing.T) {
	// Create a temp home with .claude dir
	tmpHome := t.TempDir()
	testSetHome(t, tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// detect.Environment() checks for settings.json, not just the directory.
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	agents := detectAgents()
	for _, a := range agents {
		if a.Name == "Claude Code" {
			if !a.Detected {
				t.Error("expected Claude Code to be detected via ~/.claude/ dir")
			}
			return
		}
	}
	t.Error("Claude Code agent not found in results")
}

func TestDetectAgents_ClineDetectedByVSCodeExtension(t *testing.T) {
	tmpHome := t.TempDir()
	testSetHome(t, tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".vscode", "extensions", "cline-1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	agents := detectAgents()
	for _, a := range agents {
		if a.Name == "Cline" {
			if !a.Detected {
				t.Error("expected Cline to be detected via ~/Documents/Cline/ dir")
			}
			return
		}
	}
	t.Error("Cline agent not found in results")
}

func TestIsTerminal_PipeIsNotTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	if isTerminal(r) {
		t.Error("pipe should not be detected as terminal")
	}
}

// TestNonInteractive pipe detection is covered by TestIsTerminal_Pipe above.
