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

	"github.com/spf13/cobra"
)

func newSetupWindsurfCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var remove bool

	cmd := &cobra.Command{
		Use:   "windsurf",
		Short: "Wrap Windsurf MCP servers with Rampart policy enforcement",
		Long: `Modifies Windsurf's MCP configuration to route all MCP server tool calls
through Rampart's policy engine.

Windsurf stores MCP configuration at:
  - macOS:   ~/.codeium/windsurf/mcp_config.json
  - Linux:   ~/.codeium/windsurf/mcp_config.json
  - Windows: %USERPROFILE%\.codeium\windsurf\mcp_config.json

This command wraps each MCP server's command with 'rampart mcp --' so that
all tool calls are evaluated against your security policy before execution.

Safe to run multiple times — servers already wrapped are skipped.

Use --remove to unwrap MCP servers and restore original commands.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath := windsurfMCPConfigPath()
			if remove {
				return unwrapMCPServers(cmd, configPath, "Windsurf")
			}
			return wrapMCPServers(cmd, configPath, "Windsurf", force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Re-wrap servers even if already wrapped")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove Rampart wrapping from MCP servers")
	return cmd
}

func windsurfMCPConfigPath() string {
	home, _ := os.UserHomeDir()
	// Windsurf uses ~/.codeium/windsurf/mcp_config.json
	return filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")
}
