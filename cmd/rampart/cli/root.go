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
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

type rootOptions struct {
	configPath string
	verbose    bool
}

// Execute runs the rampart CLI command tree.
func Execute() error {
	cmd := NewRootCmd(context.Background(), os.Stdout, os.Stderr)
	if err := cmd.Execute(); err != nil {
		var ec interface{ ExitCode() int }
		if !errors.As(err, &ec) {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		return err
	}
	return nil
}

// ExitCode returns the process exit code implied by err.
// Non-nil errors default to exit code 1 unless they expose ExitCode().
func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		code := ec.ExitCode()
		if code > 0 {
			return code
		}
	}

	return 1
}

// NewRootCmd builds the rampart root command.
func NewRootCmd(ctx context.Context, outWriter, errWriter io.Writer) *cobra.Command {
	opts := &rootOptions{}
	if ctx == nil {
		ctx = context.Background()
	}

	cmd := &cobra.Command{
		Use:           "rampart",
		Short:         "Runtime defense for AI agents",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.SetContext(ctx)
	cmd.SetOut(outWriter)
	cmd.SetErr(errWriter)

	cmd.PersistentFlags().StringVar(&opts.configPath, "config", "rampart.yaml", "Path to policy config file")
	cmd.PersistentFlags().BoolVar(&opts.verbose, "verbose", false, "Enable debug logging")

	cmd.AddCommand(newVersionCmd())
	cmd.AddCommand(newInitCmd(opts))
	cmd.AddCommand(newServeCmd(opts, nil))
	cmd.AddCommand(newPolicyCmd(opts))
	cmd.AddCommand(newAuditCmd(opts))
	cmd.AddCommand(newReportCmd(opts))
	cmd.AddCommand(newWatchCmd(opts))
	cmd.AddCommand(newOpenClawCmd(opts))
	cmd.AddCommand(newDaemonCmd(opts))
	cmd.AddCommand(newApproveCmd(opts))
	cmd.AddCommand(newDenyCmd(opts))
	cmd.AddCommand(newPendingCmd(opts))
	cmd.AddCommand(newWrapCmd(opts, nil))
	cmd.AddCommand(newPreloadCmd(opts))
	cmd.AddCommand(newMCPCmd(opts, nil))
	cmd.AddCommand(newHookCmd(opts))
	cmd.AddCommand(newLogCmd(opts))
	cmd.AddCommand(newSetupCmd(opts))
	cmd.AddCommand(newDoctorCmd())
	cmd.AddCommand(newStatusCmd())
	cmd.AddCommand(newTokenShowCmd())
	cmd.AddCommand(newTestCmd(opts))
	cmd.AddCommand(newQuickstartCmd())
	cmd.AddCommand(newUpgradeCmd(opts))

	return cmd
}
