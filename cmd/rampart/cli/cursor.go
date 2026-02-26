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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newSetupCursorCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var remove bool

	cmd := &cobra.Command{
		Use:   "cursor",
		Short: "Wrap Cursor MCP servers with Rampart policy enforcement",
		Long: `Modifies Cursor's MCP configuration to route all MCP server tool calls
through Rampart's policy engine.

Cursor stores MCP configuration at:
  - macOS:   ~/.cursor/mcp.json
  - Linux:   ~/.cursor/mcp.json
  - Windows: %USERPROFILE%\.cursor\mcp.json

This command wraps each MCP server's command with 'rampart mcp --' so that
all tool calls are evaluated against your security policy before execution.

Safe to run multiple times — servers already wrapped are skipped.

Use --remove to unwrap MCP servers and restore original commands.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath := cursorMCPConfigPath()
			if remove {
				return unwrapMCPServers(cmd, configPath, "Cursor")
			}
			return wrapMCPServers(cmd, configPath, "Cursor", force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Re-wrap servers even if already wrapped")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove Rampart wrapping from MCP servers")
	return cmd
}

func cursorMCPConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cursor", "mcp.json")
}

// mcpConfig represents the MCP configuration file structure.
// Format: {"mcpServers": {"name": {"command": "...", "args": [...], "env": {...}}}}
type mcpConfig struct {
	MCPServers map[string]mcpServer `json:"mcpServers"`
}

type mcpServer struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	// URL is for SSE-based MCP servers (no command). These cannot be wrapped.
	URL string `json:"url,omitempty"`
}

// wrapMCPServers modifies an MCP config to wrap all servers with rampart mcp.
func wrapMCPServers(cmd *cobra.Command, configPath, appName string, force bool) error {
	// Check if config exists
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(cmd.OutOrStdout(), "No MCP configuration found at %s\n", configPath)
		fmt.Fprintf(cmd.OutOrStdout(), "\n%s MCP servers will be protected once you configure them.\n", appName)
		fmt.Fprintf(cmd.OutOrStdout(), "See: https://docs.rampart.sh/guides/securing-%s\n", strings.ToLower(appName))
		return nil
	}
	if err != nil {
		return fmt.Errorf("setup %s: read config: %w", strings.ToLower(appName), err)
	}

	// Parse config
	var config mcpConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("setup %s: invalid JSON in %s: %w", strings.ToLower(appName), configPath, err)
	}

	if config.MCPServers == nil || len(config.MCPServers) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No MCP servers configured in %s\n", configPath)
		return nil
	}

	// Find rampart binary
	rampartBin := "rampart"
	if exe, err := os.Executable(); err == nil {
		rampartBin = exe
	} else if p, err := execLookPath("rampart"); err == nil {
		rampartBin = p
	}

	// Track changes
	var wrapped, skipped, sseSkipped []string

	for name, server := range config.MCPServers {
		// Skip URL-based (SSE) servers — they can't be wrapped
		if server.URL != "" && server.Command == "" {
			sseSkipped = append(sseSkipped, name)
			continue
		}

		// Check if already wrapped
		if isRampartWrapped(server) {
			if !force {
				skipped = append(skipped, name)
				continue
			}
			// Force: unwrap first, then re-wrap
			server = unwrapServer(server)
		}

		// Wrap the server
		wrapped = append(wrapped, name)
		config.MCPServers[name] = wrapServer(server, rampartBin)
	}

	// Warn about SSE servers
	if len(sseSkipped) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "⚠️  Skipped %d SSE-based server(s) (URL-only, cannot be wrapped): %s\n",
			len(sseSkipped), strings.Join(sseSkipped, ", "))
	}

	if len(wrapped) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "All %d MCP server(s) already protected by Rampart.\n", len(skipped))
		return nil
	}

	// Write updated config
	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("setup %s: marshal config: %w", strings.ToLower(appName), err)
	}
	output = append(output, '\n')

	// Backup original (only if no backup exists — preserve the true original)
	backupPath := configPath + ".rampart-backup"
	if _, statErr := os.Stat(backupPath); os.IsNotExist(statErr) {
		if err := os.WriteFile(backupPath, data, 0o644); err != nil {
			return fmt.Errorf("setup %s: backup config: %w", strings.ToLower(appName), err)
		}
	}

	if err := os.WriteFile(configPath, output, 0o644); err != nil {
		return fmt.Errorf("setup %s: write config: %w", strings.ToLower(appName), err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "✓ Wrapped %d MCP server(s) with Rampart\n", len(wrapped))
	for _, name := range wrapped {
		fmt.Fprintf(cmd.OutOrStdout(), "  • %s\n", name)
	}
	if len(skipped) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  (%d already wrapped, skipped)\n", len(skipped))
	}
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "Original config backed up to: %s\n", backupPath)
	fmt.Fprintf(cmd.OutOrStdout(), "Restart %s for changes to take effect.\n", appName)

	return nil
}

// unwrapMCPServers restores original MCP server commands.
func unwrapMCPServers(cmd *cobra.Command, configPath, appName string) error {
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(cmd.OutOrStdout(), "No MCP configuration found at %s\n", configPath)
		return nil
	}
	if err != nil {
		return fmt.Errorf("setup %s: read config: %w", strings.ToLower(appName), err)
	}

	var config mcpConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("setup %s: invalid JSON: %w", strings.ToLower(appName), err)
	}

	if config.MCPServers == nil {
		fmt.Fprintln(cmd.OutOrStdout(), "No MCP servers configured. Nothing to unwrap.")
		return nil
	}

	var unwrapped []string
	for name, server := range config.MCPServers {
		if isRampartWrapped(server) {
			config.MCPServers[name] = unwrapServer(server)
			unwrapped = append(unwrapped, name)
		}
	}

	if len(unwrapped) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No Rampart-wrapped MCP servers found. Nothing to remove.")
		return nil
	}

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("setup %s: marshal config: %w", strings.ToLower(appName), err)
	}
	output = append(output, '\n')

	if err := os.WriteFile(configPath, output, 0o644); err != nil {
		return fmt.Errorf("setup %s: write config: %w", strings.ToLower(appName), err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "✓ Unwrapped %d MCP server(s)\n", len(unwrapped))
	for _, name := range unwrapped {
		fmt.Fprintf(cmd.OutOrStdout(), "  • %s\n", name)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nRestart %s for changes to take effect.\n", appName)

	return nil
}

// isRampartWrapped checks if a server is already wrapped with rampart mcp.
func isRampartWrapped(server mcpServer) bool {
	// Check if command ends with "rampart" (handles /usr/local/bin/rampart, rampart, etc.)
	// Also handle versioned binaries like rampart-new, rampart-0.6.0
	cmdBase := filepath.Base(server.Command)
	if cmdBase == "rampart" || strings.HasPrefix(cmdBase, "rampart-") {
		if len(server.Args) >= 2 && server.Args[0] == "mcp" && server.Args[1] == "--" {
			return true
		}
	}
	return false
}

// wrapServer wraps a server command with rampart mcp --.
func wrapServer(server mcpServer, rampartBin string) mcpServer {
	// New args: ["mcp", "--", original_command, original_args...]
	newArgs := []string{"mcp", "--", server.Command}
	newArgs = append(newArgs, server.Args...)

	return mcpServer{
		Command: rampartBin,
		Args:    newArgs,
		Env:     server.Env,
	}
}

// unwrapServer restores the original command from a wrapped server.
func unwrapServer(server mcpServer) mcpServer {
	// Expect: command=rampart, args=["mcp", "--", original_cmd, original_args...]
	if len(server.Args) < 3 || server.Args[0] != "mcp" || server.Args[1] != "--" {
		return server // Can't unwrap, return as-is
	}

	return mcpServer{
		Command: server.Args[2],
		Args:    server.Args[3:],
		Env:     server.Env,
	}
}

