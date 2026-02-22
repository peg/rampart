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
	var showVersion bool
	if ctx == nil {
		ctx = context.Background()
	}

	cmd := &cobra.Command{
		Use:           "rampart",
		Short:         "Runtime defense for AI agents",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if showVersion {
				return writeVersion(cmd.OutOrStdout())
			}
			return cmd.Help()
		},
	}
	cmd.SetContext(ctx)
	cmd.SetOut(outWriter)
	cmd.SetErr(errWriter)

	cmd.PersistentFlags().StringVar(&opts.configPath, "config", "rampart.yaml", "Path to policy config file")
	cmd.PersistentFlags().BoolVar(&opts.verbose, "verbose", false, "Enable debug logging")
	cmd.PersistentFlags().BoolVar(&showVersion, "version", false, "Print version information and exit")

	const (
		groupSetup     = "setup"
		groupPolicy    = "policy"
		groupRuntime   = "runtime"
		groupApprovals = "approvals"
		groupHooks     = "hooks"
	)
	cmd.AddGroup(
		&cobra.Group{ID: groupSetup, Title: "Setup"},
		&cobra.Group{ID: groupPolicy, Title: "Policy"},
		&cobra.Group{ID: groupRuntime, Title: "Runtime"},
		&cobra.Group{ID: groupApprovals, Title: "Approvals"},
		&cobra.Group{ID: groupHooks, Title: "Hooks"},
	)

	versionCmd := newVersionCmd()
	initCmd := newInitCmd(opts)
	serveCmd := newServeCmd(opts, nil)
	policyCmd := newPolicyCmd(opts)
	auditCmd := newAuditCmd(opts)
	reportCmd := newReportCmd(opts)
	watchCmd := newWatchCmd(opts)
	openClawCmd := newOpenClawCmd(opts)
	daemonCmd := newDaemonCmd(opts)
	approveCmd := newApproveCmd(opts)
	denyCmd := newDenyCmd(opts)
	pendingCmd := newPendingCmd(opts)
	wrapCmd := newWrapCmd(opts, nil)
	preloadCmd := newPreloadCmd(opts)
	mcpCmd := newMCPCmd(opts, nil)
	hookCmd := newHookCmd(opts)
	logCmd := newLogCmd(opts)
	setupCmd := newSetupCmd(opts)
	doctorCmd := newDoctorCmd()
	statusCmd := newStatusCmd()
	tokenCmd := newTokenShowCmd()
	testCmd := newTestCmd(opts)
	quickstartCmd := newQuickstartCmd()
	upgradeCmd := newUpgradeCmd(opts)

	setupCmd.GroupID = groupSetup
	quickstartCmd.GroupID = groupSetup
	upgradeCmd.GroupID = groupSetup
	doctorCmd.GroupID = groupSetup

	policyCmd.GroupID = groupPolicy
	testCmd.GroupID = groupPolicy
	watchCmd.GroupID = groupPolicy

	serveCmd.GroupID = groupRuntime
	tokenCmd.GroupID = groupRuntime
	statusCmd.GroupID = groupRuntime
	logCmd.GroupID = groupRuntime

	approveCmd.GroupID = groupApprovals
	denyCmd.GroupID = groupApprovals
	pendingCmd.GroupID = groupApprovals

	hookCmd.GroupID = groupHooks
	preloadCmd.GroupID = groupHooks
	wrapCmd.GroupID = groupHooks

	cmd.AddCommand(versionCmd)
	cmd.AddCommand(initCmd)
	cmd.AddCommand(serveCmd)
	cmd.AddCommand(policyCmd)
	cmd.AddCommand(auditCmd)
	cmd.AddCommand(reportCmd)
	cmd.AddCommand(watchCmd)
	cmd.AddCommand(openClawCmd)
	cmd.AddCommand(daemonCmd)
	cmd.AddCommand(approveCmd)
	cmd.AddCommand(denyCmd)
	cmd.AddCommand(pendingCmd)
	cmd.AddCommand(wrapCmd)
	cmd.AddCommand(preloadCmd)
	cmd.AddCommand(mcpCmd)
	cmd.AddCommand(hookCmd)
	cmd.AddCommand(logCmd)
	cmd.AddCommand(setupCmd)
	cmd.AddCommand(doctorCmd)
	cmd.AddCommand(statusCmd)
	cmd.AddCommand(tokenCmd)
	cmd.AddCommand(testCmd)
	cmd.AddCommand(quickstartCmd)
	cmd.AddCommand(upgradeCmd)

	return cmd
}
