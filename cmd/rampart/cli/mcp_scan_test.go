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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		keywords []string
		want     bool
	}{
		{"match first keyword", "delete_file", []string{"delete", "remove"}, true},
		{"match second keyword", "remove_item", []string{"delete", "remove"}, true},
		{"no match", "read_file", []string{"delete", "remove"}, false},
		{"empty keywords", "anything", []string{}, false},
		{"empty text", "", []string{"delete"}, false},
		{"substring match", "undelete_file", []string{"delete"}, true},
		{"case sensitive no match", "DELETE", []string{"delete"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, containsAny(tt.text, tt.keywords))
		})
	}
}

func TestHasFileTools(t *testing.T) {
	tests := []struct {
		name  string
		tools []MCPTool
		want  bool
	}{
		{"file in name", []MCPTool{{Name: "read_file"}}, true},
		{"filesystem in desc", []MCPTool{{Name: "foo", Description: "Access the filesystem"}}, true},
		{"directory in desc", []MCPTool{{Name: "ls", Description: "List directory contents"}}, true},
		{"no file tools", []MCPTool{{Name: "query_db", Description: "Run a SQL query"}}, false},
		{"empty list", []MCPTool{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasFileTools(tt.tools))
		})
	}
}

func TestGeneratePolicyFromTools_Categorization(t *testing.T) {
	tests := []struct {
		name               string
		tools              []MCPTool
		wantDestructive    []string
		wantDangerous      []string
		wantWrite          []string
		wantPolicyNames    []string
		wantNoPolicyNames  []string
	}{
		{
			name: "destructive tools denied",
			tools: []MCPTool{
				{Name: "delete_file", Description: "Delete a file"},
				{Name: "destroy_record", Description: "Destroy a database record"},
				{Name: "remove_user", Description: "Remove a user account"},
			},
			wantDestructive: []string{"delete_file", "destroy_record", "remove_user"},
			wantPolicyNames: []string{"mcp-destructive-tools"},
		},
		{
			name: "execution tools get deny+ask",
			tools: []MCPTool{
				{Name: "execute_command", Description: "Execute a shell command"},
				{Name: "run_script", Description: "Run a script"},
				{Name: "shell_exec", Description: "Execute in shell"},
			},
			wantDangerous:   []string{"execute_command", "run_script", "shell_exec"},
			wantPolicyNames: []string{"mcp-dangerous-execution"},
		},
		{
			name: "write tools get ask",
			tools: []MCPTool{
				{Name: "write_file", Description: "Write content to a file"},
				{Name: "create_record", Description: "Create a new record"},
				{Name: "update_config", Description: "Update configuration"},
			},
			wantWrite:       []string{"write_file", "create_record", "update_config"},
			wantPolicyNames: []string{"mcp-write-operations"},
		},
		{
			name: "read tools get no policy (default allow)",
			tools: []MCPTool{
				{Name: "read_file", Description: "Read a file"},
				{Name: "list_items", Description: "List all items"},
				{Name: "search_records", Description: "Search records"},
			},
			wantPolicyNames:   []string{},
			wantNoPolicyNames: []string{"mcp-destructive-tools", "mcp-dangerous-execution", "mcp-write-operations"},
		},
		{
			name:            "empty tool list",
			tools:           []MCPTool{},
			wantPolicyNames: []string{},
		},
		{
			name: "mixed signals - destructive wins over read",
			tools: []MCPTool{
				{Name: "read_and_delete", Description: "Read then delete a resource"},
			},
			wantDestructive: []string{"read_and_delete"},
			wantPolicyNames: []string{"mcp-destructive-tools"},
		},
		{
			name: "tool with no description categorized by name only",
			tools: []MCPTool{
				{Name: "delete_item"},
			},
			wantDestructive: []string{"delete_item"},
			wantPolicyNames: []string{"mcp-destructive-tools"},
		},
		{
			name: "description triggers categorization even with neutral name",
			tools: []MCPTool{
				{Name: "manage_data", Description: "This will destroy the old records"},
			},
			wantDestructive: []string{"manage_data"},
			wantPolicyNames: []string{"mcp-destructive-tools"},
		},
		{
			name: "uncategorized tool gets no policy",
			tools: []MCPTool{
				{Name: "do_stuff", Description: "Does some stuff"},
			},
			wantPolicyNames:   []string{},
			wantNoPolicyNames: []string{"mcp-destructive-tools", "mcp-dangerous-execution", "mcp-write-operations"},
		},
		{
			name: "file tools add credential protection",
			tools: []MCPTool{
				{Name: "read_file", Description: "Read file contents"},
			},
			wantPolicyNames: []string{"mcp-credential-protection"},
		},
		{
			name: "all categories present",
			tools: []MCPTool{
				{Name: "delete_file", Description: "Delete a file from the filesystem"},
				{Name: "execute_cmd", Description: "Execute a command"},
				{Name: "write_file", Description: "Write to a file"},
				{Name: "read_file", Description: "Read a file"},
			},
			wantPolicyNames: []string{
				"mcp-destructive-tools",
				"mcp-dangerous-execution",
				"mcp-write-operations",
				"mcp-credential-protection",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := generatePolicyFromTools(tt.tools, "test-server")

			assert.Equal(t, "1", policy.Version)
			assert.Equal(t, "allow", policy.DefaultAction)

			policyNames := make([]string, len(policy.Policies))
			for i, p := range policy.Policies {
				policyNames[i] = p.Name
			}

			for _, want := range tt.wantPolicyNames {
				assert.Contains(t, policyNames, want, "expected policy %q", want)
			}
			for _, notWant := range tt.wantNoPolicyNames {
				assert.NotContains(t, policyNames, notWant, "unexpected policy %q", notWant)
			}

			// Verify destructive tools matched
			if len(tt.wantDestructive) > 0 {
				p := findPolicy(policy.Policies, "mcp-destructive-tools")
				require.NotNil(t, p)
				matchedTools := p.Match["tool"].([]string)
				assert.Equal(t, tt.wantDestructive, matchedTools)
				require.Len(t, p.Rules, 1)
				assert.Equal(t, "deny", p.Rules[0].Action)
			}

			// Verify dangerous tools matched
			if len(tt.wantDangerous) > 0 {
				p := findPolicy(policy.Policies, "mcp-dangerous-execution")
				require.NotNil(t, p)
				matchedTools := p.Match["tool"].([]string)
				assert.Equal(t, tt.wantDangerous, matchedTools)
				require.Len(t, p.Rules, 2)
				assert.Equal(t, "deny", p.Rules[0].Action)
				assert.NotNil(t, p.Rules[0].When, "first rule should have When condition")
				assert.Equal(t, "ask", p.Rules[1].Action)
			}

			// Verify write tools matched
			if len(tt.wantWrite) > 0 {
				p := findPolicy(policy.Policies, "mcp-write-operations")
				require.NotNil(t, p)
				matchedTools := p.Match["tool"].([]string)
				assert.Equal(t, tt.wantWrite, matchedTools)
				require.Len(t, p.Rules, 1)
				assert.Equal(t, "ask", p.Rules[0].Action)
			}
		})
	}
}

func TestGeneratePolicyFromTools_CredentialProtection(t *testing.T) {
	tools := []MCPTool{
		{Name: "read_file", Description: "Read file contents from filesystem"},
	}
	policy := generatePolicyFromTools(tools, "test")

	p := findPolicy(policy.Policies, "mcp-credential-protection")
	require.NotNil(t, p)
	assert.Equal(t, true, p.Match["any"])
	require.Len(t, p.Rules, 1)
	assert.Equal(t, "deny", p.Rules[0].Action)

	paths := p.Rules[0].When["path_matches"].([]string)
	assert.Contains(t, paths, "*/.ssh/*")
	assert.Contains(t, paths, "*/.aws/*")
	assert.Contains(t, paths, "*/.env*")
}

func TestGeneratePolicyYAML_ValidStructure(t *testing.T) {
	tools := []MCPTool{
		{Name: "delete_file", Description: "Delete a file"},
		{Name: "write_file", Description: "Write to a file"},
		{Name: "read_file", Description: "Read a file"},
	}
	policy := generatePolicyFromTools(tools, "test-server arg1")
	yamlStr, err := generatePolicyYAML(policy, "test-server arg1", len(tools))
	require.NoError(t, err)

	// Check header comments
	assert.Contains(t, yamlStr, "# Auto-generated by: rampart mcp scan")
	assert.Contains(t, yamlStr, "# MCP Server: test-server arg1")
	assert.Contains(t, yamlStr, "# Tools discovered: 3")

	// Parse the YAML (strip comments first)
	var lines []string
	for _, line := range strings.Split(yamlStr, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
		}
	}
	cleanYAML := strings.Join(lines, "\n")

	var parsed map[string]interface{}
	err = yaml.Unmarshal([]byte(cleanYAML), &parsed)
	require.NoError(t, err, "generated YAML should be valid")

	assert.Equal(t, "1", parsed["version"])
	assert.Equal(t, "allow", parsed["default_action"])
	assert.NotNil(t, parsed["policies"])
}

func TestGeneratePolicyYAML_EmptyPolicies(t *testing.T) {
	policy := PolicyConfig{
		Version:       "1",
		DefaultAction: "allow",
		Policies:      []PolicyEntry{},
	}
	yamlStr, err := generatePolicyYAML(policy, "test", 0)
	require.NoError(t, err)
	assert.Contains(t, yamlStr, "version: \"1\"")
	assert.Contains(t, yamlStr, "default_action: allow")
	assert.NotContains(t, yamlStr, "policies:")
}

func TestGeneratePolicyFromTools_PriorityOrder(t *testing.T) {
	// "delete" should take priority over "execute" which takes priority over "write"
	t.Run("delete beats execute", func(t *testing.T) {
		tools := []MCPTool{{Name: "delete_and_exec", Description: "Delete then execute"}}
		policy := generatePolicyFromTools(tools, "test")
		p := findPolicy(policy.Policies, "mcp-destructive-tools")
		require.NotNil(t, p, "should be categorized as destructive, not dangerous")
		assert.Nil(t, findPolicy(policy.Policies, "mcp-dangerous-execution"))
	})

	t.Run("execute beats write", func(t *testing.T) {
		tools := []MCPTool{{Name: "run_and_write", Description: "Run command and write output"}}
		policy := generatePolicyFromTools(tools, "test")
		p := findPolicy(policy.Policies, "mcp-dangerous-execution")
		require.NotNil(t, p, "should be categorized as dangerous, not write")
		assert.Nil(t, findPolicy(policy.Policies, "mcp-write-operations"))
	})

	t.Run("write beats read", func(t *testing.T) {
		tools := []MCPTool{{Name: "read_write_file", Description: "Read and write files"}}
		policy := generatePolicyFromTools(tools, "test")
		p := findPolicy(policy.Policies, "mcp-write-operations")
		require.NotNil(t, p, "should be categorized as write, not just read")
	})
}

func TestGeneratePolicyFromTools_KeywordVariants(t *testing.T) {
	destructiveKeywords := []string{"delete", "destroy", "remove", "drop", "unlink", "rm"}
	for _, kw := range destructiveKeywords {
		t.Run("destructive_"+kw, func(t *testing.T) {
			tools := []MCPTool{{Name: kw + "_thing"}}
			policy := generatePolicyFromTools(tools, "test")
			require.NotNil(t, findPolicy(policy.Policies, "mcp-destructive-tools"),
				"keyword %q should trigger destructive policy", kw)
		})
	}

	dangerousKeywords := []string{"execute", "run", "shell", "bash", "command", "eval", "exec"}
	for _, kw := range dangerousKeywords {
		t.Run("dangerous_"+kw, func(t *testing.T) {
			tools := []MCPTool{{Name: kw + "_thing"}}
			policy := generatePolicyFromTools(tools, "test")
			require.NotNil(t, findPolicy(policy.Policies, "mcp-dangerous-execution"),
				"keyword %q should trigger dangerous policy", kw)
		})
	}

	writeKeywords := []string{"write", "create", "update", "modify", "edit", "save", "put", "post", "patch"}
	for _, kw := range writeKeywords {
		t.Run("write_"+kw, func(t *testing.T) {
			tools := []MCPTool{{Name: kw + "_thing"}}
			policy := generatePolicyFromTools(tools, "test")
			require.NotNil(t, findPolicy(policy.Policies, "mcp-write-operations"),
				"keyword %q should trigger write policy", kw)
		})
	}

	readKeywords := []string{"read", "get", "list", "search", "query", "find", "fetch", "show", "view"}
	for _, kw := range readKeywords {
		t.Run("read_"+kw, func(t *testing.T) {
			tools := []MCPTool{{Name: kw + "_thing"}}
			policy := generatePolicyFromTools(tools, "test")
			// Read tools should NOT generate any restrictive policy
			assert.Nil(t, findPolicy(policy.Policies, "mcp-destructive-tools"))
			assert.Nil(t, findPolicy(policy.Policies, "mcp-dangerous-execution"))
			assert.Nil(t, findPolicy(policy.Policies, "mcp-write-operations"))
		})
	}
}

// findPolicy returns the policy with the given name, or nil.
func findPolicy(policies []PolicyEntry, name string) *PolicyEntry {
	for i := range policies {
		if policies[i].Name == name {
			return &policies[i]
		}
	}
	return nil
}
