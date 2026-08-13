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
	"errors"

	"github.com/spf13/cobra"
)

const mcpScanMigrationGuidance = `mcp scan is disabled: executing a server to generate policy is not supported; use "rampart init --profile mcp-server" to create a static policy, then review it before use`

func newMCPScanCmd(_ *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "scan -- <mcp-server-command> [args...]",
		Short: "Show static MCP policy migration guidance",
		Long:  mcpScanMigrationGuidance,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New(mcpScanMigrationGuidance)
		},
	}
}
