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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/peg/rampart/internal/generate"
	"github.com/spf13/cobra"
)

// destProject is the project-level policy path.
const destProject = ".rampart/policy.yaml"

// destGlobalTemplate is a printf template for the global policy path.
// %s is replaced with the preset ID.
const destGlobalTemplate = ".rampart/policies/%s.yaml"

// newPolicyGeneratePresetCmd builds the `rampart policy generate preset`
// command which walks the user through an interactive preset selector and
// writes a ready-to-use policy YAML file.
func newPolicyGeneratePresetCmd(_ *rootOptions) *cobra.Command {
	var (
		presetFlag string
		destFlag   string
		forceFlag  bool
		printFlag  bool
	)

	cmd := &cobra.Command{
		Use:   "preset",
		Short: "Generate a policy from a built-in template",
		Long: `Interactively select a preset policy template and write it to disk.

Presets:
  coding-agent    File edits, git, build tools, block credentials
  research-agent  Web fetch, file read, no writes
  ci-agent        Build/test only, no network, no secrets
  devops-agent    Docker, kubectl, ssh (with approval)

Examples:
  rampart policy generate preset
  rampart policy generate preset --preset coding-agent
  rampart policy generate preset --preset ci-agent --dest .rampart/policy.yaml
  rampart policy generate preset --preset research-agent --print
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// --print: just dump YAML to stdout regardless of dest
			if printFlag {
				preset, err := resolvePreset(presetFlag)
				if err != nil {
					return err
				}
				data, err := preset.RenderYAML()
				if err != nil {
					return err
				}
				_, err = fmt.Fprint(cmd.OutOrStdout(), string(data))
				return err
			}

			preset, dest, err := runPresetForm(cmd, presetFlag, destFlag)
			if err != nil {
				if errors.Is(err, huh.ErrUserAborted) {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
					return nil
				}
				return err
			}

			if err := preset.WriteToFile(dest, forceFlag); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"\n✓ Policy written to %s\n\nNext steps:\n  rampart serve --config %s\n  rampart policy check --config %s\n",
				dest, dest, dest,
			)
			return nil
		},
	}

	cmd.Flags().StringVar(&presetFlag, "preset", "", "Preset ID to use without prompting (coding-agent|research-agent|ci-agent|devops-agent)")
	cmd.Flags().StringVar(&destFlag, "dest", "", "Output path (skips destination prompt)")
	cmd.Flags().BoolVar(&forceFlag, "force", false, "Overwrite existing file")
	cmd.Flags().BoolVar(&printFlag, "print", false, "Print generated YAML to stdout instead of writing to a file")

	return cmd
}

// resolvePreset returns the preset for the given ID, or errors if unknown.
func resolvePreset(id string) (generate.Preset, error) {
	if strings.TrimSpace(id) == "" {
		return generate.Preset{}, fmt.Errorf("preset: no preset selected")
	}
	return generate.FindPreset(id)
}

// runPresetForm drives the interactive huh form (or non-interactive path when
// both --preset and --dest are supplied).
func runPresetForm(cmd *cobra.Command, presetFlag, destFlag string) (generate.Preset, string, error) {
	// Non-interactive fast path: both preset and dest are already known.
	if presetFlag != "" && destFlag != "" {
		preset, err := resolvePreset(presetFlag)
		if err != nil {
			return generate.Preset{}, "", err
		}
		return preset, destFlag, nil
	}

	// Build selector options.
	presetOptions := make([]huh.Option[string], 0, len(generate.Presets)+1)
	for _, p := range generate.Presets {
		// Pad description for alignment.
		label := fmt.Sprintf("%-18s %s", p.ID, p.Description)
		presetOptions = append(presetOptions, huh.NewOption(label, p.ID))
	}
	presetOptions = append(presetOptions, huh.NewOption("custom              Start from scratch", "custom"))

	selectedPreset := presetFlag
	selectedDest := destFlag

	// Determine home dir for global path label.
	home, _ := os.UserHomeDir()
	var globalPath string

	destOptions := []huh.Option[string]{
		huh.NewOption(fmt.Sprintf("Project  (%s)", destProject), "project"),
		huh.NewOption(fmt.Sprintf("Global   (~/%s)", destGlobalTemplate), "global"),
	}

	// Build the form groups.
	var groups []*huh.Group

	// Group 1: preset selector (only if not already provided via flag).
	if selectedPreset == "" {
		groups = append(groups, huh.NewGroup(
			huh.NewSelect[string]().
				Title("What kind of work will your agent do?").
				Options(presetOptions...).
				Value(&selectedPreset),
		))
	}

	// Group 2: destination selector (only if not already provided via flag).
	destChoice := "project"
	if selectedDest == "" {
		groups = append(groups, huh.NewGroup(
			huh.NewSelect[string]().
				Title("Save to:").
				Options(destOptions...).
				Value(&destChoice),
		))
	}

	if len(groups) > 0 {
		f := huh.NewForm(groups...).
			WithOutput(cmd.OutOrStdout())
		if err := f.Run(); err != nil {
			return generate.Preset{}, "", err
		}
	}

	// "custom" is a special case: tell the user to start with rampart init.
	if selectedPreset == "custom" {
		return generate.Preset{}, "", fmt.Errorf(
			"preset: custom not yet supported interactively — use 'rampart init' to bootstrap a blank policy",
		)
	}

	// Resolve the final preset.
	preset, err := resolvePreset(selectedPreset)
	if err != nil {
		return generate.Preset{}, "", err
	}

	// Resolve dest from choice or flag.
	if selectedDest == "" {
		switch destChoice {
		case "global":
			globalPath = filepath.Join(home, fmt.Sprintf(destGlobalTemplate, preset.ID))
			selectedDest = globalPath
		default: // "project"
			selectedDest = destProject
		}
	}

	return preset, selectedDest, nil
}
