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
			return runUninstall(cmd, yes)
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompts")
	return cmd
}

func runUninstall(cmd *cobra.Command, yes bool) error {
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

	// Get current executable path (don't resolve "rampart" from PATH — could be malicious)
	exe, err := os.Executable()
	if err != nil {
		exe = "rampart" // fallback, but prefer current binary
	}

	// 1. Remove hooks from Claude Code
	claudeSettings := filepath.Join(home, ".claude", "settings.json")
	if _, err := os.Stat(claudeSettings); err == nil {
		fmt.Fprintln(w, "Removing Claude Code hooks...")
		if err := runSilent(exe, "setup", "claude-code", "--remove"); err == nil {
			removed = append(removed, "Claude Code hooks")
		} else {
			failed = append(failed, "Claude Code hooks")
		}
	}

	// 2. Remove hooks from Cline
	clineDir := filepath.Join(home, "Documents", "Cline", "Hooks")
	if _, err := os.Stat(clineDir); err == nil {
		fmt.Fprintln(w, "Removing Cline hooks...")
		if err := runSilent(exe, "setup", "cline", "--remove"); err == nil {
			removed = append(removed, "Cline hooks")
		} else {
			failed = append(failed, "Cline hooks")
		}
	}

	// 3. Stop and remove service
	fmt.Fprintln(w, "Stopping rampart serve...")
	switch runtime.GOOS {
	case "darwin":
		// Kill any running rampart serve process
		_ = runSilent("pkill", "-f", "rampart serve")
		
		plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.rampart.serve.plist")
		if _, err := os.Stat(plistPath); err == nil {
			_ = runSilent("launchctl", "unload", plistPath)
			if err := os.Remove(plistPath); err == nil {
				removed = append(removed, "LaunchAgent service")
			}
		}
		// Also try the proxy plist name
		proxyPlist := filepath.Join(home, "Library", "LaunchAgents", "com.rampart.proxy.plist")
		if _, err := os.Stat(proxyPlist); err == nil {
			_ = runSilent("launchctl", "unload", proxyPlist)
			if err := os.Remove(proxyPlist); err == nil {
				removed = append(removed, "LaunchAgent proxy service")
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
		// the uninstall process too. Use wmic to find serve processes.
		_ = runSilent("powershell", "-Command",
			"Get-Process rampart -ErrorAction SilentlyContinue | Where-Object {$_.CommandLine -like '*serve*'} | Stop-Process -Force")
		removed = append(removed, "running serve process (if any)")
	}

	// 4. Remove from PATH (Windows only)
	if runtime.GOOS == "windows" {
		fmt.Fprintln(w, "Removing from PATH...")
		if removeFromWindowsPath(home) {
			removed = append(removed, "PATH entry")
		}
	}

	// 5. Remove shell shim if present
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
	return nil
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
