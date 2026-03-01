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
	"strings"
	"time"

	"github.com/peg/rampart/internal/detect"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

const projectPolicyTemplate = `# Rampart project policy
# Commit this file to enforce these rules for all team members.
# Rules here are applied on top of your global policy (~/.rampart/policies/).
# Global default_action always takes precedence; project rules can only ADD restrictions.
#
# Set RAMPART_NO_PROJECT_POLICY=1 to skip loading this file.
# Docs: https://docs.rampart.sh/features/policy-engine/#project-policies
version: "1"

policies:
  # Example: block destructive commands in this repo
  # - name: myproject-no-destructive
  #   match:
  #     tool: exec
  #   rules:
  #     - action: deny
  #       when:
  #         command_matches:
  #           - "rm -rf *"
  #           - "DROP TABLE *"
  #       message: "Destructive commands blocked by project policy"

  # Example: protect production secrets
  # - name: myproject-secrets-readonly
  #   match:
  #     tool: write
  #   rules:
  #     - action: deny
  #       when:
  #         path_matches:
  #           - "*.env.production"
  #           - "*/secrets/**"
  #       message: "Production secrets are read-only for AI agents"
`

func runInitProject(cmd *cobra.Command) error {
	dir := ".rampart"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cli: create %s directory: %w", dir, err)
	}

	dest := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("cli: %s already exists — delete it first if you want to regenerate", dest)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cli: check %s: %w", dest, err)
	}

	if err := os.WriteFile(dest, []byte(projectPolicyTemplate), 0o644); err != nil {
		return fmt.Errorf("cli: write %s: %w", dest, err)
	}

	_, err := fmt.Fprintln(cmd.OutOrStdout(), "Created .rampart/policy.yaml — commit this file to share rules with your team.")
	return err
}

func newInitCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var profile string
	var detectEnv bool
	var project bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Rampart configuration and default policies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if project {
				return runInitProject(cmd)
			}

			// Always ensure directories exist first
			rampartHome, err := ensureRampartDirs()
			if err != nil {
				return err
			}

			path := opts.configPath
			if path == "" {
				path = "rampart.yaml"
			}

			// Check if config exists - we'll skip writing it but continue with policies
			configExists := false
			if _, err := os.Stat(path); err == nil {
				configExists = true
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("cli: check config file %s: %w", path, err)
			}

			var content []byte

			if detectEnv {
				// Perform environment detection
				if _, err := fmt.Fprint(cmd.OutOrStdout(), "🔍 Detecting environment...\n"); err != nil {
					return fmt.Errorf("cli: write detect output: %w", err)
				}

				result, err := detect.Environment()
				if err != nil {
					return fmt.Errorf("cli: detect environment: %w", err)
				}

				// Print detection results
				if result.ClaudeCode {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✓ Claude Code found (~/.claude/settings.json)\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				} else {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✗ Claude Code not found\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				}

				if len(result.MCPServers) > 0 {
					serverList := strings.Join(result.MCPServers, ", ")
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %d MCP servers found: %s\n", len(result.MCPServers), serverList); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				} else {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✗ No MCP servers found\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				}

				if result.SSHKeys {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✓ SSH keys found — credential protection enabled\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				} else {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✗ SSH keys not found\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				}

				if result.HasKubectl {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✓ kubectl found — Kubernetes rules enabled\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				} else {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✗ kubectl not found\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				}

				if result.HasDocker {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✓ Docker found — container rules enabled\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				} else {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✗ Docker not found\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				}

				if result.AWSCredentials {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✓ AWS credentials found — credential protection enabled\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				} else {
					if _, err := fmt.Fprint(cmd.OutOrStdout(), "  ✗ AWS credentials not found\n"); err != nil {
						return fmt.Errorf("cli: write detect output: %w", err)
					}
				}

				if _, err := fmt.Fprint(cmd.OutOrStdout(), "\nGenerating tailored policy → rampart.yaml\n"); err != nil {
					return fmt.Errorf("cli: write detect output: %w", err)
				}

				// Generate tailored policy based on detection results
				content, err = generateTailoredPolicy(result)
				if err != nil {
					return fmt.Errorf("cli: generate tailored policy: %w", err)
				}
			} else {
				// Use selected profile
				selectedProfile := strings.TrimSpace(strings.ToLower(profile))
				if !isSupportedProfile(selectedProfile) {
					return fmt.Errorf("cli: invalid profile %q (valid: standard, paranoid, yolo, block-prompt-injection, research-agent, mcp-server)", profile)
				}

				var err error
				content, err = policies.FS.ReadFile(selectedProfile + ".yaml")
				if err != nil {
					return fmt.Errorf("cli: read embedded profile %s: %w", selectedProfile, err)
				}
			}

			// Write config file (skip if exists and no --force)
			configWritten := false
			if !configExists || force {
				if err := os.WriteFile(path, content, 0o644); err != nil {
					return fmt.Errorf("cli: write config file %s: %w", path, err)
				}
				configWritten = true
			}

			// Always write policies (unless they exist and no --force)
			policyWritten := false
			if !detectEnv {
				selectedProfile := strings.TrimSpace(strings.ToLower(profile))
				profilePath := filepath.Join(rampartHome, "policies", selectedProfile+".yaml")
				policyExists := false
				if _, err := os.Stat(profilePath); err == nil {
					policyExists = true
				} else if !os.IsNotExist(err) {
					return fmt.Errorf("cli: check profile file %s: %w", profilePath, err)
				}

				if !policyExists || force {
					if err := os.WriteFile(profilePath, content, 0o644); err != nil {
						return fmt.Errorf("cli: write profile file %s: %w", profilePath, err)
					}
					policyWritten = true
				}

				// Print summary of what was done
				switch {
				case configWritten && policyWritten:
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Created %s and ~/.rampart/policies/%s.yaml\n", path, selectedProfile); err != nil {
						return fmt.Errorf("cli: write init output: %w", err)
					}
				case configWritten:
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Created %s (policy already exists — use --force to overwrite)\n", path); err != nil {
						return fmt.Errorf("cli: write init output: %w", err)
					}
				case policyWritten:
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Created ~/.rampart/policies/%s.yaml (config already exists at %s — use --force to overwrite)\n", selectedProfile, path); err != nil {
						return fmt.Errorf("cli: write init output: %w", err)
					}
				default:
					if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Config and policies already exist."); err != nil {
						return fmt.Errorf("cli: write init output: %w", err)
					}
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "--force overwrites %s and ~/.rampart/policies/%s.yaml.\n", path, selectedProfile); err != nil {
						return fmt.Errorf("cli: write init output: %w", err)
					}
					if _, err := fmt.Fprintln(cmd.OutOrStdout(), "It preserves ~/.rampart/token and does not touch custom policy files (including ~/.rampart/policies/custom.yaml)."); err != nil {
						return fmt.Errorf("cli: write init output: %w", err)
					}
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "To update just your %s policy: rampart policy fetch %s --force\n", selectedProfile, selectedProfile); err != nil {
						return fmt.Errorf("cli: write init output: %w", err)
					}
					if _, err := fmt.Fprintln(cmd.OutOrStdout(), "To reset everything: rampart init --force"); err != nil {
						return fmt.Errorf("cli: write init output: %w", err)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing config/profile files")
	cmd.Flags().BoolVar(&force, "defaults", false, "Use default settings and overwrite existing files (alias for --force)")
	cmd.Flags().StringVar(&profile, "profile", "standard", "Default policy profile: standard, paranoid, yolo, block-prompt-injection, research-agent, or mcp-server")
	cmd.Flags().BoolVar(&detectEnv, "detect", false, "Auto-detect installed tools and generate tailored policy")
	cmd.Flags().BoolVar(&project, "project", false, "Create .rampart/policy.yaml in the current directory for team-shared project rules")

	return cmd
}

func ensureRampartDirs() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cli: resolve home directory: %w", err)
	}

	rampartHome := filepath.Join(home, ".rampart")
	for _, dir := range []string{"config", "audit", "policies"} {
		fullPath := filepath.Join(rampartHome, dir)
		if err := os.MkdirAll(fullPath, 0o755); err != nil {
			return "", fmt.Errorf("cli: create directory %s: %w", fullPath, err)
		}
	}

	return rampartHome, nil
}

func isSupportedProfile(profile string) bool {
	for _, name := range policies.ProfileNames {
		if name == profile {
			return true
		}
	}
	return false
}

// generateTailoredPolicy creates a tailored policy based on detection results.
func generateTailoredPolicy(result *detect.DetectResult) ([]byte, error) {
	// Start with the standard profile as base
	baseContent, err := policies.FS.ReadFile("standard.yaml")
	if err != nil {
		return nil, fmt.Errorf("read base standard profile: %w", err)
	}

	// Create header comment
	header := fmt.Sprintf("# Generated by rampart init --detect on %s\n", time.Now().UTC().Format("2006-01-02"))

	policyContent := string(baseContent)

	// Add additional rules based on detection results
	if result.HasKubectl {
		kubectlRules := `
  - name: block-kubectl-dangerous
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "kubectl delete * --namespace=production"
            - "kubectl delete * --namespace=prod"  
            - "kubectl delete * -n production"
            - "kubectl delete * -n prod"
            - "kubectl delete * --all-namespaces"
            - "kubectl delete * -A"
            - "kubectl delete namespace *"
        message: "Dangerous kubectl command blocked - production namespace or cluster-wide deletion"`

		// Insert before the last closing bracket or at the end
		policyContent = strings.TrimSuffix(policyContent, "\n") + kubectlRules + "\n"
	}

	if result.HasDocker {
		dockerRules := `
  - name: block-docker-dangerous
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "docker rm -f *"
            - "docker system prune *"
            - "docker container prune *"
            - "docker image prune -a"
            - "docker volume prune *"
            - "docker network prune *"
        message: "Dangerous Docker command blocked - forced removal or system cleanup"`

		policyContent = strings.TrimSuffix(policyContent, "\n") + dockerRules + "\n"
	}

	// Add header to the final content
	finalContent := header + policyContent

	return []byte(finalContent), nil
}
