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
	"github.com/spf13/cobra"
)

func newBlockCmd(_ *rootOptions) *cobra.Command {
	opts := &allowBlockOptions{}

	cmd := &cobra.Command{
		Use:   "block <pattern>",
		Short: "Add a deny rule to your custom policy",
		Long: `Add a glob pattern as an explicit deny rule in your custom policy.

Patterns are matched against commands (exec tool) or file paths (read/write/edit).
Auto-detects path vs command based on whether the pattern contains a '/'.

Examples:
  rampart block "curl * | bash"        # block piped execution
  rampart block "rm -rf *"             # block all rm -rf commands
  rampart block "/etc/**"              # block writes to /etc
  rampart block "npm publish *"        # block npm publish

Changes take effect immediately if 'rampart serve' is running.`,
		Args: makePatternArgs("block"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAllowBlock(cmd, args[0], "deny", opts)
		},
	}

	addAllowBlockFlags(cmd, opts)
	return cmd
}
