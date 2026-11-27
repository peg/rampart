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
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func newUpgradeCmd(_ *rootOptions) *cobra.Command {
	var dryRun, policiesOnly bool
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Show how to upgrade Rampart, or refresh built-in policies",
		Long: "Print the command that upgrades Rampart for how it was installed.\n" +
			"After upgrading, run 'rampart upgrade --no-binary' to refresh unmodified\n" +
			"built-in policy profiles in ~/.rampart/policies.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if policiesOnly {
				if err := upgradeStandardPolicies(cmd.OutOrStdout(), dryRun); err != nil {
					return fmt.Errorf("policy refresh: %w", err)
				}
				return nil
			}
			exe, _ := os.Executable()
			fmt.Fprintf(cmd.OutOrStdout(), "To upgrade Rampart, run:\n  %s\n", upgradeInstruction(runtime.GOOS, exe))
			fmt.Fprintln(cmd.OutOrStdout(), "Then run 'rampart upgrade --no-binary' to refresh built-in policies and 'rampart protect' to refresh agent integrations.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&policiesOnly, "no-binary", false, "Refresh unmodified built-in policy profiles with this binary's versions")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "With --no-binary, show which policies would change")
	return cmd
}

// upgradeInstruction returns the command that upgrades Rampart for the
// installation that owns exe.
func upgradeInstruction(goos, exe string) string {
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	switch {
	case isHomebrewManagedPath(exe):
		return "brew upgrade peg/tap/rampart"
	case goos == "windows":
		return "irm https://rampart.sh/install.ps1 | iex"
	default:
		return "curl -fsSL https://rampart.sh/install | sh"
	}
}

func isHomebrewManagedPath(path string) bool {
	path = strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	return strings.HasPrefix(path, "/opt/homebrew/") ||
		strings.Contains(path, "/cellar/") ||
		strings.Contains(path, "/.linuxbrew/")
}
