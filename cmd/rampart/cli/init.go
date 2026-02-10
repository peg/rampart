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

	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

func newInitCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var profile string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Rampart configuration and default policies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			selectedProfile := strings.TrimSpace(strings.ToLower(profile))
			if !isSupportedProfile(selectedProfile) {
				return fmt.Errorf("cli: invalid profile %q (valid: standard, paranoid, yolo)", profile)
			}
			content, err := policies.FS.ReadFile(selectedProfile + ".yaml")
			if err != nil {
				return fmt.Errorf("cli: read embedded profile %s: %w", selectedProfile, err)
			}

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

			if err := os.WriteFile(path, content, 0o644); err != nil {
				return fmt.Errorf("cli: write config file %s: %w", path, err)
			}

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
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing config/profile files")
	cmd.Flags().StringVar(&profile, "profile", "standard", "Default policy profile: standard, paranoid, or yolo")

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
