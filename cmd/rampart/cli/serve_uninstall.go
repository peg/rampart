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
	"runtime"

	"github.com/spf13/cobra"
)

func newServeUninstallCmd(runner commandRunner) *cobra.Command {
	if runner == nil {
		runner = defaultRunner
	}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the rampart serve system service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if runtime.GOOS == "windows" {
				fmt.Fprintln(cmd.ErrOrStderr(), "Windows is not yet supported.")
				return nil
			}

			switch runtime.GOOS {
			case "darwin":
				return uninstallDarwin(cmd, runner)
			case "linux":
				return uninstallLinux(cmd, runner)
			default:
				fmt.Fprintf(cmd.ErrOrStderr(), "Unsupported platform: %s\n", runtime.GOOS)
				return nil
			}
		},
	}
	return cmd
}

func uninstallDarwin(cmd *cobra.Command, runner commandRunner) error {
	path, err := plistPath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintln(cmd.ErrOrStderr(), "Service is not installed.")
		return nil
	}

	// Best-effort unload; ignore errors (service may not be running).
	_ = runner("launchctl", "unload", path).Run()

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove plist: %w", err)
	}

	fmt.Fprintln(cmd.ErrOrStderr(), "✅ Rampart service uninstalled.")
	return nil
}

func uninstallLinux(cmd *cobra.Command, runner commandRunner) error {
	path, err := systemdUnitPath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintln(cmd.ErrOrStderr(), "Service is not installed.")
		return nil
	}

	// Best-effort stop+disable.
	_ = runner("systemctl", "--user", "disable", "--now", "rampart-serve.service").Run()

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove unit: %w", err)
	}

	_ = runner("systemctl", "--user", "daemon-reload").Run()

	fmt.Fprintln(cmd.ErrOrStderr(), "✅ Rampart service uninstalled.")
	return nil
}
