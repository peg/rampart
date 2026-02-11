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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ToolsListResponse represents the tools/list JSON-RPC response structure
type ToolsListResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Result  ToolsListResult `json:"result"`
}

type ToolsListResult struct {
	Tools []MCPTool `json:"tools"`
}

type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	Action  string            `json:"action"`
	When    map[string]interface{} `json:"when,omitempty"`
	Message string            `json:"message,omitempty"`
}

// PolicyEntry represents a policy in the generated YAML
type PolicyEntry struct {
	Name  string       `json:"name"`
	Match map[string]interface{} `json:"match"`
	Rules []PolicyRule `json:"rules"`
}

// PolicyConfig represents the complete policy configuration
type PolicyConfig struct {
	Version       string        `json:"version"`
	DefaultAction string        `json:"default_action"`
	Policies      []PolicyEntry `json:"policies"`
}

func newMCPScanCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan -- <mcp-server-command> [args...]",
		Short: "Scan MCP server tools and generate policy suggestions",
		Long: `Connect to an MCP server, read its tool list, and auto-generate a Rampart policy YAML.

Examples:
  rampart mcp scan -- npx @modelcontextprotocol/server-filesystem /tmp
  rampart mcp scan -- python -m mcp_server_files
`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("scan: command is required (use: rampart mcp scan -- <command> [args...])")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPScan(cmd, args)
		},
	}

	return cmd
}

func runMCPScan(cmd *cobra.Command, args []string) error {
	// Start the MCP server as a child process
	child := exec.Command(args[0], args[1:]...)
	child.Stderr = cmd.ErrOrStderr()

	childIn, err := child.StdinPipe()
	if err != nil {
		return fmt.Errorf("scan: create child stdin pipe: %w", err)
	}
	childOut, err := child.StdoutPipe()
	if err != nil {
		return fmt.Errorf("scan: create child stdout pipe: %w", err)
	}

	if err := child.Start(); err != nil {
		return fmt.Errorf("scan: start child process: %w", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()

	// Initialize the MCP connection
	if err := initializeMCPConnection(childIn, childOut); err != nil {
		return fmt.Errorf("scan: initialize MCP connection: %w", err)
	}

	// Get the tool list
	tools, err := getToolsList(childIn, childOut)
	if err != nil {
		return fmt.Errorf("scan: get tools list: %w", err)
	}

	// Generate policy suggestions
	policy := generatePolicyFromTools(tools, strings.Join(args, " "))

	// Output the policy YAML
	yamlContent, err := generatePolicyYAML(policy, strings.Join(args, " "), len(tools))
	if err != nil {
		return fmt.Errorf("scan: generate policy YAML: %w", err)
	}

	fmt.Print(yamlContent)
	return nil
}

func initializeMCPConnection(stdin io.WriteCloser, stdout io.Reader) error {
	// Send initialize request
	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"clientInfo": map[string]interface{}{
				"name":    "rampart-scan",
				"version": "1.0.0",
			},
		},
	}

	reqData, err := json.Marshal(initReq)
	if err != nil {
		return fmt.Errorf("marshal initialize request: %w", err)
	}

	if _, err := stdin.Write(append(reqData, '\n')); err != nil {
		return fmt.Errorf("write initialize request: %w", err)
	}

	// Read and discard initialize response
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		return fmt.Errorf("read initialize response: no data")
	}

	return scanner.Err()
}

func getToolsList(stdin io.WriteCloser, stdout io.Reader) ([]MCPTool, error) {
	// Send tools/list request
	toolsReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "2",
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}

	reqData, err := json.Marshal(toolsReq)
	if err != nil {
		return nil, fmt.Errorf("marshal tools/list request: %w", err)
	}

	if _, err := stdin.Write(append(reqData, '\n')); err != nil {
		return nil, fmt.Errorf("write tools/list request: %w", err)
	}

	// Read tools/list response
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		return nil, fmt.Errorf("read tools/list response: no data")
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read tools/list response: %w", err)
	}

	var response ToolsListResponse
	if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("parse tools/list response: %w", err)
	}

	return response.Result.Tools, nil
}

func generatePolicyFromTools(tools []MCPTool, serverCmd string) PolicyConfig {
	config := PolicyConfig{
		Version:       "1",
		DefaultAction: "allow",
		Policies:      []PolicyEntry{},
	}

	// Group tools by risk level
	var dangerousTools []string
	var destructiveTools []string
	var writeTools []string
	var readTools []string

	for _, tool := range tools {
		name := strings.ToLower(tool.Name)
		desc := strings.ToLower(tool.Description)
		combined := name + " " + desc

		if containsAny(combined, []string{"delete", "destroy", "remove", "drop", "unlink", "rm"}) {
			destructiveTools = append(destructiveTools, tool.Name)
		} else if containsAny(combined, []string{"execute", "run", "shell", "bash", "command", "eval", "exec"}) {
			dangerousTools = append(dangerousTools, tool.Name)
		} else if containsAny(combined, []string{"write", "create", "update", "modify", "edit", "save", "put", "post", "patch"}) {
			writeTools = append(writeTools, tool.Name)
		} else if containsAny(combined, []string{"read", "get", "list", "search", "query", "find", "fetch", "show", "view"}) {
			readTools = append(readTools, tool.Name)
		}
	}

	// Generate policies for destructive tools
	if len(destructiveTools) > 0 {
		config.Policies = append(config.Policies, PolicyEntry{
			Name: "mcp-destructive-tools",
			Match: map[string]interface{}{
				"tool": destructiveTools,
			},
			Rules: []PolicyRule{
				{
					Action:  "deny",
					Message: "Destructive operation blocked (auto-generated)",
				},
			},
		})
	}

	// Generate policies for dangerous execution tools
	if len(dangerousTools) > 0 {
		config.Policies = append(config.Policies, PolicyEntry{
			Name: "mcp-dangerous-execution",
			Match: map[string]interface{}{
				"tool": dangerousTools,
			},
			Rules: []PolicyRule{
				{
					Action: "deny",
					When: map[string]interface{}{
						"command_matches": []string{"rm -rf *", "mkfs.*", "dd if=*", "format *"},
					},
					Message: "Dangerous command execution blocked (auto-generated)",
				},
				{
					Action:  "ask",
					Message: "Command execution requires approval (auto-generated)",
				},
			},
		})
	}

	// Generate policies for write tools (require approval)
	if len(writeTools) > 0 {
		config.Policies = append(config.Policies, PolicyEntry{
			Name: "mcp-write-operations",
			Match: map[string]interface{}{
				"tool": writeTools,
			},
			Rules: []PolicyRule{
				{
					Action:  "ask",
					Message: "Write operation requires approval (auto-generated)",
				},
			},
		})
	}

	// Add credential path blocks for file-related tools
	if hasFileTools(tools) {
		config.Policies = append(config.Policies, PolicyEntry{
			Name: "mcp-credential-protection",
			Match: map[string]interface{}{
				"any": true,
			},
			Rules: []PolicyRule{
				{
					Action: "deny",
					When: map[string]interface{}{
						"path_matches": []string{
							"*/.ssh/*",
							"*/.aws/*", 
							"*/.config/gcloud/*",
							"*/credentials*",
							"*/.env*",
							"*/secrets/*",
						},
					},
					Message: "Access to credential files blocked (auto-generated)",
				},
			},
		})
	}

	return config
}

func containsAny(text string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

func hasFileTools(tools []MCPTool) bool {
	for _, tool := range tools {
		combined := strings.ToLower(tool.Name + " " + tool.Description)
		if containsAny(combined, []string{"file", "path", "directory", "folder", "fs", "filesystem"}) {
			return true
		}
	}
	return false
}

func generatePolicyYAML(config PolicyConfig, serverCmd string, toolCount int) (string, error) {
	now := time.Now().UTC()
	
	yamlContent := fmt.Sprintf(`# Auto-generated by: rampart mcp scan
# MCP Server: %s
# Tools discovered: %d
# Generated: %s
#
# Review and customize before using in production.

version: "%s"
default_action: %s

`, serverCmd, toolCount, now.Format(time.RFC3339), config.Version, config.DefaultAction)

	if len(config.Policies) > 0 {
		yamlContent += "policies:\n"
		
		for _, policy := range config.Policies {
			yamlContent += fmt.Sprintf("  - name: %s\n", policy.Name)
			yamlContent += "    match:\n"
			
			// Handle match criteria
			for key, value := range policy.Match {
				switch v := value.(type) {
				case []string:
					yamlContent += fmt.Sprintf("      %s:\n", key)
					for _, item := range v {
						yamlContent += fmt.Sprintf("        - \"%s\"\n", item)
					}
				case string:
					yamlContent += fmt.Sprintf("      %s: \"%s\"\n", key, v)
				case bool:
					yamlContent += fmt.Sprintf("      %s: %t\n", key, v)
				}
			}
			
			yamlContent += "    rules:\n"
			for _, rule := range policy.Rules {
				yamlContent += fmt.Sprintf("      - action: %s\n", rule.Action)
				
				if rule.When != nil && len(rule.When) > 0 {
					yamlContent += "        when:\n"
					for key, value := range rule.When {
						switch v := value.(type) {
						case []string:
							yamlContent += fmt.Sprintf("          %s:\n", key)
							for _, item := range v {
								yamlContent += fmt.Sprintf("            - \"%s\"\n", item)
							}
						case string:
							yamlContent += fmt.Sprintf("          %s: \"%s\"\n", key, v)
						}
					}
				}
				
				if rule.Message != "" {
					yamlContent += fmt.Sprintf("        message: \"%s\"\n", rule.Message)
				}
			}
			yamlContent += "\n"
		}
	}

	return yamlContent, nil
}