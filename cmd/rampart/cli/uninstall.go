// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func newUninstallCmd(opts *rootOptions) *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove Rampart from this system",
		Long: `Uninstall Rampart by removing hooks, services, and PATH entries.

This command:
  1. Removes hooks from Claude Code, Cline, and other configured agents
  2. Stops and removes the rampart serve service (if installed)
  3. Removes Rampart from your PATH (Windows only — Unix users should edit shell rc)
  4. Prints instructions to delete the ~/.rampart directory

Use --yes to skip confirmation prompts.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUninstall(cmd, opts, yes)
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompts")
	return cmd
}

func runUninstall(cmd *cobra.Command, opts *rootOptions, yes bool) error {
	w := cmd.OutOrStdout()
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("uninstall: get home dir: %w", err)
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "🗑️  Rampart Uninstall")
	fmt.Fprintln(w, "")

	if !yes {
		fmt.Fprint(w, "This will remove Rampart from your system. Continue? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if !strings.HasPrefix(strings.ToLower(answer), "y") {
			fmt.Fprintln(w, "Aborted.")
			return nil
		}
		fmt.Fprintln(w, "")
	}

	var removed []string
	var failed []string

	// Remove every Rampart-managed agent boundary in-process so the same
	// ownership checks used by each setup --remove command protect unrelated
	// agent configuration and state.
	integrationRemoved, integrationFailed := removeManagedAgentIntegrations(cmd, opts, home)
	removed = append(removed, integrationRemoved...)
	failed = append(failed, integrationFailed...)

	// Stop and remove service
	fmt.Fprintln(w, "Stopping rampart serve...")
	switch runtime.GOOS {
	case "darwin":
		// Kill any running rampart serve process
		_ = runSilent("pkill", "-f", "rampart serve")

		// Remove the current serve label, the managed proxy label, and the
		// legacy serve label used by older installations.
		for _, plistPath := range rampartLaunchdServicePaths(home) {
			if _, err := os.Stat(plistPath); err == nil {
				_ = runSilent("launchctl", "unload", plistPath)
				if err := os.Remove(plistPath); err == nil {
					removed = append(removed, "LaunchAgent service")
				}
			}
		}
	case "linux":
		// Kill any running rampart serve process
		_ = runSilent("pkill", "-f", "rampart serve")

		// Try user service first
		_ = runSilent("systemctl", "--user", "stop", "rampart-serve")
		_ = runSilent("systemctl", "--user", "disable", "rampart-serve")
		_ = runSilent("systemctl", "--user", "stop", "rampart-proxy")
		_ = runSilent("systemctl", "--user", "disable", "rampart-proxy")

		serviceFiles := []string{
			filepath.Join(home, ".config", "systemd", "user", "rampart-serve.service"),
			filepath.Join(home, ".config", "systemd", "user", "rampart-proxy.service"),
		}
		for _, sf := range serviceFiles {
			if _, err := os.Stat(sf); err == nil {
				if err := os.Remove(sf); err == nil {
					removed = append(removed, "systemd service")
				}
			}
		}
		_ = runSilent("systemctl", "--user", "daemon-reload")
	case "windows":
		// Kill any running rampart.exe serve process
		// taskkill /F /IM rampart.exe only kills by image name, which would kill
		// the uninstall process too. Query Win32_Process so CommandLine is
		// actually available (Get-Process does not expose it reliably).
		_ = runSilent("powershell", "-Command",
			windowsStopServeScript(os.Getpid()))
		removed = append(removed, "running serve process (if any)")
	}

	// Remove from PATH (Windows only)
	if runtime.GOOS == "windows" {
		fmt.Fprintln(w, "Removing from PATH...")
		if removeFromWindowsPath(home) {
			removed = append(removed, "PATH entry")
		}
	}

	// Remove a legacy shell shim if present.
	shimPath := filepath.Join(home, ".local", "bin", "rampart-shim")
	if _, err := os.Stat(shimPath); err == nil {
		if err := os.Remove(shimPath); err == nil {
			removed = append(removed, "shell shim")
		}
	}

	// Summary
	fmt.Fprintln(w, "")
	if len(removed) > 0 {
		fmt.Fprintln(w, "✓ Removed:")
		for _, r := range removed {
			fmt.Fprintf(w, "    • %s\n", r)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "⚠ Failed to remove (try manually):")
		for _, f := range failed {
			fmt.Fprintf(w, "    • %s\n", f)
		}
	}

	// Final instructions
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Almost done! To complete uninstallation, delete the Rampart directory:")
	fmt.Fprintln(w, "")

	rampartDir := filepath.Join(home, ".rampart")
	switch runtime.GOOS {
	case "windows":
		fmt.Fprintf(w, "    Remove-Item -Recurse %s\n", rampartDir)
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Then restart your terminal to update PATH.")
	default:
		fmt.Fprintf(w, "    rm -rf %s\n", rampartDir)
		if runtime.GOOS != "windows" {
			fmt.Fprintln(w, "")
			fmt.Fprintln(w, "If you added Rampart to your shell profile, remove that line from:")
			fmt.Fprintln(w, "    ~/.bashrc, ~/.zshrc, or ~/.profile")
		}
	}

	// Note about binary
	if exe, err := os.Executable(); err == nil {
		if !strings.Contains(exe, ".rampart") {
			fmt.Fprintln(w, "")
			fmt.Fprintf(w, "The rampart binary at %s can also be deleted.\n", exe)
		}
	}

	fmt.Fprintln(w, "")
	if len(failed) > 0 {
		return fmt.Errorf("uninstall incomplete: %d Rampart-managed integration(s) could not be removed", len(failed))
	}
	return nil
}

func rampartLaunchdServicePaths(home string) []string {
	services := rampartLaunchdServices(home)
	paths := make([]string, 0, len(services))
	for _, service := range services {
		paths = append(paths, service.PlistPath)
	}
	return paths
}

func windowsStopServeScript(uninstallPID int) string {
	return fmt.Sprintf(
		`$uninstallPid=%d; Get-CimInstance Win32_Process -Filter "Name = 'rampart.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -ne $uninstallPid -and $_.CommandLine -like '*serve*' } | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction SilentlyContinue | Out-Null }`,
		uninstallPID,
	)
}

// removeFromWindowsPath removes ~/.rampart/bin from the user PATH on Windows.
func removeFromWindowsPath(home string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	rampartBin := filepath.Join(home, ".rampart", "bin")

	// Get current user PATH
	cmd := exec.Command("powershell", "-Command",
		"[Environment]::GetEnvironmentVariable('PATH', 'User')")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	currentPath := strings.TrimSpace(string(out))
	paths := strings.Split(currentPath, ";")

	// Filter out rampart bin
	var newPaths []string
	found := false
	for _, p := range paths {
		if strings.EqualFold(strings.TrimSpace(p), rampartBin) {
			found = true
			continue
		}
		if strings.TrimSpace(p) != "" {
			newPaths = append(newPaths, p)
		}
	}

	if !found {
		return false
	}

	// Set new PATH (escape single quotes to prevent PowerShell injection)
	newPath := strings.Join(newPaths, ";")
	escapedPath := strings.ReplaceAll(newPath, "'", "''")
	cmd = exec.Command("powershell", "-Command",
		fmt.Sprintf("[Environment]::SetEnvironmentVariable('PATH', '%s', 'User')", escapedPath))
	return cmd.Run() == nil
}

// runSilent runs a command and returns any error, suppressing output.
func runSilent(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
