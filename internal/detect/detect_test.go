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

package detect

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestDetectMCPServersFromClaudeSettings(t *testing.T) {
	// Create a temporary file with mock Claude settings
	tempDir := t.TempDir()
	settingsPath := filepath.Join(tempDir, "settings.json")

	settingsJSON := `{
		"mcpServers": {
			"proxmox": {
				"command": "npx",
				"args": ["@peg/mcp-proxmox"]
			},
			"github": {
				"command": "npx", 
				"args": ["@peg/mcp-github"]
			}
		}
	}`

	err := os.WriteFile(settingsPath, []byte(settingsJSON), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	servers, err := detectMCPServersFromClaudeSettings(settingsPath)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	expectedServers := []string{"proxmox", "github"}
	if len(servers) != len(expectedServers) {
		t.Fatalf("Expected %d servers, got %d", len(expectedServers), len(servers))
	}

	// Sort both slices for comparison since map iteration order is not guaranteed
	for _, expected := range expectedServers {
		found := false
		for _, server := range servers {
			if server == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected server %s not found in results: %v", expected, servers)
		}
	}
}

func TestDetectMCPServersFromFile(t *testing.T) {
	// Create a temporary file with mock MCP config
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "mcp.json")

	configJSON := `{
		"servers": {
			"filesystem": {
				"command": "npx",
				"args": ["@peg/mcp-filesystem"]
			},
			"database": {
				"command": "npx",
				"args": ["@peg/mcp-database"]
			}
		}
	}`

	err := os.WriteFile(configPath, []byte(configJSON), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	servers, err := detectMCPServersFromFile(configPath)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	expectedServers := []string{"filesystem", "database"}
	if len(servers) != len(expectedServers) {
		t.Fatalf("Expected %d servers, got %d", len(expectedServers), len(servers))
	}

	for _, expected := range expectedServers {
		found := false
		for _, server := range servers {
			if server == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected server %s not found in results: %v", expected, servers)
		}
	}
}

func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "all duplicates",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeDuplicates(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDetectMCPServersFromClaudeSettingsFileNotFound(t *testing.T) {
	_, err := detectMCPServersFromClaudeSettings("/nonexistent/path")
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
}

func TestDetectMCPServersFromClaudeSettingsInvalidJSON(t *testing.T) {
	// Create a temporary file with invalid JSON
	tempDir := t.TempDir()
	settingsPath := filepath.Join(tempDir, "settings.json")

	invalidJSON := `{"mcpServers": {`
	err := os.WriteFile(settingsPath, []byte(invalidJSON), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = detectMCPServersFromClaudeSettings(settingsPath)
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}
}

func TestDetectMCPServersFromFileInvalidJSON(t *testing.T) {
	// Create a temporary file with invalid JSON
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "mcp.json")

	invalidJSON := `{"servers": {`
	err := os.WriteFile(configPath, []byte(invalidJSON), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = detectMCPServersFromFile(configPath)
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}
}

func TestEnvironmentDetectsAgentsAndToolsFromSignals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH binary shims in this test are Unix-only")
	}

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tmpHome)
	}

	t.Setenv("CLINE_ACTIVE", "1")
	t.Setenv("OPENCLAW_SERVICE_MARKER", "openclaw")

	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "codex"))
	writeExecutable(t, filepath.Join(binDir, "aider"))
	writeExecutable(t, filepath.Join(binDir, "kubectl"))
	writeExecutable(t, filepath.Join(binDir, "docker"))
	writeExecutable(t, filepath.Join(binDir, "node"))
	writeExecutable(t, filepath.Join(binDir, "npm"))
	writeExecutable(t, filepath.Join(binDir, "python3"))
	writeExecutable(t, filepath.Join(binDir, "pip3"))
	writeExecutable(t, filepath.Join(binDir, "terraform"))
	writeExecutable(t, filepath.Join(binDir, "git"))
	writeExecutable(t, filepath.Join(binDir, "go"))
	writeExecutable(t, filepath.Join(binDir, "cargo"))
	writeExecutable(t, filepath.Join(binDir, "aws"))
	t.Setenv("PATH", binDir)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpHome, ".windsurf"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := Environment()
	if err != nil {
		t.Fatalf("Environment() error = %v", err)
	}

	if !got.HasCodex || !got.HasAider || !got.HasOpenClaw || !got.HasCline {
		t.Fatalf("missing expected agent signals: %+v", got)
	}
	if !got.HasCursor || !got.HasWindsurf {
		t.Fatalf("missing expected directory signals: %+v", got)
	}
	if !got.HasKubectl || !got.HasDocker || !got.HasNode || !got.HasNpm || !got.HasPython || !got.HasPip || !got.HasTerraform || !got.HasGit || !got.HasGo || !got.HasRust || !got.HasAWSCLI {
		t.Fatalf("missing expected tool signals: %+v", got)
	}
}

func TestDetectedAgentsAndToolsOrder(t *testing.T) {
	r := &DetectResult{
		ClaudeCode:   true,
		HasCodex:     true,
		HasCline:     true,
		HasOpenClaw:  true,
		HasCursor:    true,
		HasAider:     true,
		HasWindsurf:  true,
		HasCopilot:   true,
		HasKubectl:   true,
		HasDocker:    true,
		HasNode:      true,
		HasNpm:       true,
		HasPython:    true,
		HasPip:       true,
		HasTerraform: true,
		HasGit:       true,
		HasGo:        true,
		HasRust:      true,
		HasAWSCLI:    true,
	}

	agents := r.DetectedAgents()
	wantAgents := []string{"claude-code", "codex", "cline", "openclaw", "cursor", "aider", "windsurf", "copilot"}
	if !reflect.DeepEqual(agents, wantAgents) {
		t.Fatalf("DetectedAgents() = %v, want %v", agents, wantAgents)
	}

	tools := r.DetectedTools()
	wantTools := []string{"kubectl", "docker", "node", "npm", "python", "pip", "terraform", "git", "go", "rust", "aws-cli"}
	if !reflect.DeepEqual(tools, wantTools) {
		t.Fatalf("DetectedTools() = %v, want %v", tools, wantTools)
	}
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}
