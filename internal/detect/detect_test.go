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