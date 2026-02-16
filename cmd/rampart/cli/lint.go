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
	"fmt"
	"os"

	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

func newPolicyLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <file>",
		Short: "Lint a policy file for common mistakes",
		Long: `Lint a policy YAML file for errors, warnings, and suggestions.

Checks for:
  - Invalid YAML syntax
  - Unknown action values (with typo suggestions)
  - Unknown condition fields (with typo suggestions)
  - Rules with no conditions (matches everything)
  - Excessive glob depth (quadratic complexity)
  - Common field confusion (match/when, reason/message)
  - Shadowed rules that can never fire
  - Missing default_action

Exit code: 1 if errors found, 0 if only warnings/info.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			// Check file exists before linting.
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return fmt.Errorf("file not found: %s", path)
			}

			result := engine.LintPolicyFile(path)

			for _, f := range result.Findings {
				fmt.Fprintln(cmd.OutOrStdout(), f.String())
			}
			fmt.Fprintln(cmd.OutOrStdout(), result.Summary(path))

			if result.HasErrors() {
				os.Exit(1)
			}
			return nil
		},
	}
}
