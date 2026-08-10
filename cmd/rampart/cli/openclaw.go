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

	"github.com/peg/rampart/internal/engine"
	clawintegration "github.com/peg/rampart/internal/openclaw"
	"github.com/spf13/cobra"
)

func newOpenClawCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "openclaw",
		Short: "OpenClaw integration commands",
	}

	cmd.AddCommand(newOpenClawSyncCmd(opts))
	return cmd
}

func newOpenClawSyncCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:        "sync",
		Short:      "Generate an advisory OpenClaw migration reference",
		Hidden:     true,
		Deprecated: "use `rampart protect openclaw`; native plugin enforcement cannot be reproduced losslessly as OpenClaw configuration",
		Long: `Read your Rampart policy YAML and generate an advisory OpenClaw migration reference.

The output is not equivalent enforcement. OpenClaw's native configuration
cannot represent Rampart's command-deny and file-path policy semantics
losslessly. Standard-profile deny patterns are emitted as documentation only.

Use 'rampart protect openclaw' for the supported native plugin boundary.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath := opts.configPath

			store := engine.NewFileStore(configPath)
			cfg, err := store.Load()
			if err != nil {
				return fmt.Errorf("openclaw sync: load policy %s: %w", configPath, err)
			}
			result := clawintegration.SyncFromConfig(cfg, configPath)
			output := clawintegration.FormatOpenClawConfig(result)

			fmt.Fprint(cmd.OutOrStdout(), output)
			return nil
		},
	}

	return cmd
}
