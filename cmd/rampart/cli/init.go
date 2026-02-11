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

func newInitCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var profile string
	var detectEnv bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Rampart configuration and default policies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := opts.configPath
			if path == "" {
				path = "rampart.yaml"
			}

			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("cli: config file already exists at %s (use --force to overwrite)", path)
			} else if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("cli: check config file %s: %w", path, err)
			}

			rampartHome, err := ensureRampartDirs()
			if err != nil {
				return err
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
					return fmt.Errorf("cli: invalid profile %q (valid: standard, paranoid, yolo)", profile)
				}
				
				var err error
				content, err = policies.FS.ReadFile(selectedProfile + ".yaml")
				if err != nil {
					return fmt.Errorf("cli: read embedded profile %s: %w", selectedProfile, err)
				}
			}

			if err := os.WriteFile(path, content, 0o644); err != nil {
				return fmt.Errorf("cli: write config file %s: %w", path, err)
			}

			if !detectEnv {
				selectedProfile := strings.TrimSpace(strings.ToLower(profile))
				profilePath := filepath.Join(rampartHome, "policies", selectedProfile+".yaml")
				if _, err := os.Stat(profilePath); err == nil && !force {
					if _, writeErr := fmt.Fprintf(cmd.OutOrStdout(), "Created %s with %s profile\n", path, selectedProfile); writeErr != nil {
						return fmt.Errorf("cli: write init output: %w", writeErr)
					}
					return nil
				} else if err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("cli: check profile file %s: %w", profilePath, err)
				}

				if err := os.WriteFile(profilePath, content, 0o644); err != nil {
					return fmt.Errorf("cli: write profile file %s: %w", profilePath, err)
				}

				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Created %s with %s profile\n", path, selectedProfile); err != nil {
					return fmt.Errorf("cli: write init output: %w", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing config/profile files")
	cmd.Flags().StringVar(&profile, "profile", "standard", "Default policy profile: standard, paranoid, or yolo")
	cmd.Flags().BoolVar(&detectEnv, "detect", false, "Auto-detect installed tools and generate tailored policy")

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
