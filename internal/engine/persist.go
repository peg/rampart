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

package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultAutoAllowedPath returns the default path for auto-generated allow rules.
func DefaultAutoAllowedPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".rampart", "policies", "auto-allowed.yaml")
}

// dangerousCommandPrefixes lists command prefixes that should NEVER be
// generalized. These commands are kept exact to prevent accidental
// auto-allow of destructive operations.
var dangerousCommandPrefixes = []string{
	"systemctl stop", "systemctl disable",
	"rm -rf", "rm -f", "rm",
	"chmod", "chown",
	"kill", "killall", "pkill",
	"dd",
	"mkfs", "fdisk",
	"reboot", "shutdown", "halt",
}

// isDangerousCommand returns true if the command starts with a dangerous prefix.
func isDangerousCommand(tokens []string) bool {
	joined := strings.Join(tokens, " ")
	for _, prefix := range dangerousCommandPrefixes {
		if joined == prefix || strings.HasPrefix(joined, prefix+" ") {
			return true
		}
	}
	return false
}

// GeneralizeCommand takes a full command string and generalizes it for
// policy use. It keeps the first 1-2 meaningful tokens and wildcards the rest.
// Dangerous commands (rm, chmod, kill, etc.) are never generalized.
// Single-token commands are kept exact.
//
// Examples:
//
//	"kubectl apply -f deployment.yaml" → "kubectl apply *"
//	"npm install express" → "npm install *"
//	"git push origin main" → "git push *"
//	"ls" → "ls"
//	"rm -rf /tmp/build" → "rm -rf /tmp/build"
func GeneralizeCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "*"
	}

	// Split on whitespace.
	tokens := strings.Fields(cmd)

	// Single-token commands: keep exact.
	if len(tokens) == 1 {
		return tokens[0]
	}

	// Dangerous commands: keep exact, never generalize.
	if isDangerousCommand(tokens) {
		return strings.Join(tokens, " ")
	}

	if len(tokens) <= 2 {
		// Short commands: keep as-is plus wildcard.
		return strings.Join(tokens, " ") + " *"
	}

	// Keep first two tokens, wildcard the rest.
	return tokens[0] + " " + tokens[1] + " *"
}

// GenerateAllowRule creates a Policy from a ToolCall that would allow
// similar future calls.
func GenerateAllowRule(call ToolCall) Policy {
	tool := call.Tool
	if tool == "" {
		tool = "*"
	}

	now := time.Now().UTC()
	var ruleName string
	var rule Rule

	switch tool {
	case "exec":
		cmd := call.Command()
		generalized := GeneralizeCommand(cmd)
		tokens := strings.Fields(cmd)
		nameParts := tokens
		if len(nameParts) > 2 {
			nameParts = nameParts[:2]
		}
		ruleName = fmt.Sprintf("auto-allow-%s", strings.Join(nameParts, "-"))
		rule = Rule{
			Action: "allow",
			When: Condition{
				CommandMatches: []string{generalized},
			},
		}

	case "read", "write":
		path := call.Path()
		if path == "" {
			path = "*"
		}
		action := tool
		ruleName = fmt.Sprintf("auto-allow-%s-%s", action, sanitizeName(path))
		rule = Rule{
			Action: "allow",
			When: Condition{
				PathMatches: []string{path},
			},
		}

	default:
		// MCP or other tools: match on tool name.
		ruleName = fmt.Sprintf("auto-allow-%s", sanitizeName(tool))
		rule = Rule{
			Action: "allow",
			When: Condition{
				Default: true,
			},
		}
	}

	return Policy{
		Name: fmt.Sprintf("%s-%s", ruleName, now.Format("20060102T150405Z")),
		Match: Match{
			Tool: StringOrSlice{tool},
		},
		Rules: []Rule{rule},
	}
}

// AppendAllowRule generates an allow rule from a ToolCall and appends it
// to the auto-allowed policy file. Creates the file and directories if needed.
func AppendAllowRule(policyPath string, call ToolCall) error {
	policy := GenerateAllowRule(call)

	// Ensure directory exists.
	dir := filepath.Dir(policyPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("persist: create policy dir: %w", err)
	}

	// Load existing config or create new one.
	var cfg Config
	data, err := os.ReadFile(policyPath)
	if err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("persist: parse existing policy: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("persist: read policy file: %w", err)
	}

	if cfg.Version == "" {
		cfg.Version = "1"
		cfg.DefaultAction = "deny"
	}

	cfg.Policies = append(cfg.Policies, policy)

	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("persist: marshal policy: %w", err)
	}

	// Add comment header.
	header := fmt.Sprintf("# Auto-generated by Rampart — do not edit manually.\n# Last updated: %s\n",
		time.Now().UTC().Format(time.RFC3339))

	// Atomic write: write to temp file then rename to prevent corruption.
	tmpFile, err := os.CreateTemp(dir, ".rampart-policy-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("persist: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.WriteString(header + string(out)); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("persist: write temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("persist: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, policyPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("persist: rename temp file: %w", err)
	}

	return nil
}

// sanitizeName converts a string to a safe policy name component.
func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		" ", "-",
		".", "-",
		":", "-",
		"*", "star",
	)
	name := replacer.Replace(s)
	// Remove leading/trailing dashes.
	name = strings.Trim(name, "-")
	if name == "" {
		return "unknown"
	}
	if len(name) > 50 {
		name = name[:50]
	}
	return name
}
