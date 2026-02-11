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

// Package detect implements environment detection for tailored policy generation.
package detect

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DetectResult contains the results of environment detection.
type DetectResult struct {
	ClaudeCode    bool
	MCPServers    []string
	SSHKeys       bool
	AWSCredentials bool
	HasKubectl    bool
	HasDocker     bool
}

// Environment performs environment detection and returns results.
func Environment() (*DetectResult, error) {
	result := &DetectResult{}

	// Try to get home directory, but continue with partial results if it fails
	homeDir, homeDirErr := os.UserHomeDir()
	
	// If we have a home directory, check home-based detection
	if homeDirErr == nil {
		// Detect Claude Code
		claudeSettingsPath := filepath.Join(homeDir, ".claude", "settings.json")
		if err := checkFileExists(claudeSettingsPath); err == nil {
			result.ClaudeCode = true
			
			// Also check for MCP servers in Claude settings
			servers, _ := detectMCPServersFromClaudeSettings(claudeSettingsPath)
			result.MCPServers = append(result.MCPServers, servers...)
		}

		// Detect MCP servers from other locations
		mcpPaths := []string{
			filepath.Join(homeDir, ".cursor", "mcp.json"),
			filepath.Join(homeDir, ".config", "codex", "mcp.json"),
		}
		
		for _, path := range mcpPaths {
			if servers, err := detectMCPServersFromFile(path); err == nil {
				result.MCPServers = append(result.MCPServers, servers...)
			}
		}

		// Remove duplicates from MCP servers
		result.MCPServers = removeDuplicates(result.MCPServers)

		// Detect SSH keys
		sshDir := filepath.Join(homeDir, ".ssh")
		if entries, err := os.ReadDir(sshDir); err == nil {
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "id_") && !strings.HasSuffix(entry.Name(), ".pub") {
					result.SSHKeys = true
					break
				}
			}
		}
		// Note: we skip SSH key detection on permission errors rather than failing

		// Detect AWS credentials
		awsCredsPath := filepath.Join(homeDir, ".aws", "credentials")
		if err := checkFileExists(awsCredsPath); err == nil {
			result.AWSCredentials = true
		}
		// Note: we skip AWS detection on permission errors rather than failing
	}

	// Detect kubectl (works regardless of home directory)
	if _, err := exec.LookPath("kubectl"); err == nil {
		result.HasKubectl = true
	}

	// Detect docker (works regardless of home directory)
	if _, err := exec.LookPath("docker"); err == nil {
		result.HasDocker = true
	}

	// Always return results, even if we couldn't access home directory
	return result, nil
}

// checkFileExists checks if a file exists, properly handling permission errors.
// Returns nil if file exists, error only for actual problems.
// Permission denied is treated as "skip with warning" (returns error but caller can ignore).
func checkFileExists(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		return err // File doesn't exist
	}
	// Permission denied or other errors - return error but caller can choose to ignore
	return err
}

// detectMCPServersFromClaudeSettings reads Claude settings and extracts MCP server names.
func detectMCPServersFromClaudeSettings(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var settings struct {
		MCPServers map[string]interface{} `json:"mcpServers"`
	}

	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, err
	}

	var servers []string
	for name := range settings.MCPServers {
		servers = append(servers, name)
	}

	return servers, nil
}

// detectMCPServersFromFile reads an MCP configuration file and extracts server names.
func detectMCPServersFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config struct {
		Servers map[string]interface{} `json:"servers"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	var servers []string
	for name := range config.Servers {
		servers = append(servers, name)
	}

	return servers, nil
}

// removeDuplicates removes duplicate strings from a slice.
func removeDuplicates(slice []string) []string {
	if len(slice) == 0 {
		return []string{}
	}
	
	keys := make(map[string]bool)
	result := make([]string, 0, len(slice))
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}