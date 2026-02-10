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

package mcp

import "strings"

const defaultMappingKey = "_default"

// DefaultToolTypeMapping maps common MCP tool names to Rampart tool types.
var DefaultToolTypeMapping = map[string]string{
	"read_file":        "read",
	"list_directory":   "read",
	"write_file":       "write",
	"create_directory": "write",
	"delete_file":      "write",
	"move_file":        "write",
	"execute_command":  "exec",
	"run_command":      "exec",
	"shell":            "exec",
	"fetch":            "fetch",
	"http_request":     "fetch",
	defaultMappingKey:   "mcp",
}

// destructiveKeywords triggers "mcp-destructive" classification for MCP tools
// whose names contain these words, providing out-of-box protection.
var destructiveKeywords = []string{
	"delete", "destroy", "remove", "drop", "purge", "kill",
	"format", "wipe", "truncate", "reset",
}

// dangerousKeywords triggers "mcp-dangerous" classification for risky operations.
var dangerousKeywords = []string{
	"stop", "shutdown", "reboot", "restart", "migrate",
	"resize", "modify", "update", "patch", "configure",
	"execute", "exec", "run", "send", "post",
}

// MapToolName returns the Rampart tool type for an MCP tool name.
// Custom mappings take precedence over defaults, then keyword inference.
func MapToolName(name string, custom map[string]string) string {
	if mapped, ok := lookupMapping(name, custom); ok {
		return mapped
	}
	if mapped, ok := lookupMapping(name, DefaultToolTypeMapping); ok {
		return mapped
	}

	// Keyword-based inference for unknown MCP tools.
	lower := strings.ToLower(name)
	for _, kw := range destructiveKeywords {
		if strings.Contains(lower, kw) {
			return "mcp-destructive"
		}
	}
	for _, kw := range dangerousKeywords {
		if strings.Contains(lower, kw) {
			return "mcp-dangerous"
		}
	}

	if mapped, ok := lookupMapping(defaultMappingKey, custom); ok {
		return mapped
	}
	if mapped, ok := lookupMapping(defaultMappingKey, DefaultToolTypeMapping); ok {
		return mapped
	}
	return "mcp"
}

func lookupMapping(name string, mapping map[string]string) (string, bool) {
	if mapping == nil {
		return "", false
	}
	key := strings.ToLower(strings.TrimSpace(name))
	value, ok := mapping[key]
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}
