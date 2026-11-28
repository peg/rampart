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
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

// builtInProfileDescriptions provides human-readable descriptions for each
// built-in policy profile, replacing the generic "Built-in profile" label
// in the policy list output.
var builtInProfileDescriptions = map[string]string{
	"standard":               "Balanced default policy for everyday use",
	"paranoid":               "Maximum restriction — blocks all unrecognized commands",
	"yolo":                   "Permissive — allows everything, logs only",
	"block-prompt-injection": "Blocks prompt injection attempts",
	"research-agent":         "Tuned for research and browsing workflows",
	"mcp-server":             "Policy for MCP server tool access",
	"production-guard":       "Opt-in approval for supported infrastructure, migration, and explicit production Kubernetes CLI mutations",
}

// policyListEntry is an internal type for the unified list command output.
type policyListEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Tags        string `json:"tags"`
	Source      string `json:"source,omitempty"`    // "built-in" (shown in --extended mode)
	Installed   bool   `json:"installed,omitempty"` // shown in --extended mode
}

func newPolicyListCmd(_ *rootOptions) *cobra.Command {
	var jsonOut bool
	var extended bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List built-in policy profiles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("policy: resolve home directory: %w", err)
			}
			policyDir := filepath.Join(home, ".rampart", "policies")

			// Collect built-in profiles.
			var entries []policyListEntry
			for _, name := range policies.ProfileNames {
				installed := false
				if _, err := os.Stat(filepath.Join(policyDir, name+".yaml")); err == nil {
					installed = true
				}
				desc := builtInProfileDescriptions[name]
				if desc == "" {
					desc = "Built-in profile"
				}
				entries = append(entries, policyListEntry{
					Name:        name,
					Description: desc,
					Source:      "built-in",
					Installed:   installed,
				})
			}

			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name < entries[j].Name
			})

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(entries)
			}

			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			if extended {
				// Extended format: NAME | DESCRIPTION | SOURCE | INSTALLED
				if _, err := fmt.Fprintln(tw, "NAME\tDESCRIPTION\tSOURCE\tINSTALLED"); err != nil {
					return fmt.Errorf("policy: write list header: %w", err)
				}
				for _, e := range entries {
					inst := ""
					if e.Installed {
						inst = "✓"
					}
					if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Name, e.Description, e.Source, inst); err != nil {
						return fmt.Errorf("policy: write list row: %w", err)
					}
				}
			} else {
				// Default format: NAME | DESCRIPTION | TAGS (backward-compatible)
				if _, err := fmt.Fprintln(tw, "NAME\tDESCRIPTION\tTAGS"); err != nil {
					return fmt.Errorf("policy: write list header: %w", err)
				}
				for _, e := range entries {
					if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.Description, e.Tags); err != nil {
						return fmt.Errorf("policy: write list row: %w", err)
					}
				}
			}
			if err := tw.Flush(); err != nil {
				return fmt.Errorf("policy: flush list output: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&extended, "extended", false, "Show extended columns (SOURCE, INSTALLED)")
	return cmd
}

func newPolicyShowCmd(_ *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Print full YAML of a built-in policy profile (no side effects)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])

			if !isSupportedProfile(name) {
				return fmt.Errorf("policy: %q is not a built-in profile. Run 'rampart policy list' to see available profiles", name)
			}
			content, err := policies.Profile(name)
			if err != nil {
				return fmt.Errorf("policy: read built-in profile %q: %w", name, err)
			}
			_, err = cmd.OutOrStdout().Write(content)
			return err
		},
	}

	return cmd
}

func newPolicyRemoveCmd(_ *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a policy file from ~/.rampart/policies",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if err := sanitizePolicyName(name); err != nil {
				return err
			}
			if isSupportedProfile(name) {
				return fmt.Errorf("policy: %q is a built-in profile and cannot be removed", name)
			}

			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("policy: resolve home directory: %w", err)
			}
			path := filepath.Join(home, ".rampart", "policies", name+".yaml")

			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("policy: %q is not installed at %s", name, path)
				}
				return fmt.Errorf("policy: remove %s: %w", path, err)
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", path); err != nil {
				return fmt.Errorf("policy: write remove output: %w", err)
			}
			return nil
		},
	}

	return cmd
}

// sanitizePolicyName rejects names containing path separators or traversal
// sequences that could escape the ~/.rampart/policies/ directory.
func sanitizePolicyName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("policy: invalid policy name %q", name)
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return fmt.Errorf("policy: invalid policy name %q: must not contain path separators or '..'", name)
	}
	// Ensure filepath.Base agrees — catches any edge cases filepath.Join might resolve
	if filepath.Base(name) != name {
		return fmt.Errorf("policy: invalid policy name %q", name)
	}
	return nil
}
