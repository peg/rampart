// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
		confirmed, err := confirmUninstall(cmd.InOrStdin(), w)
		if err != nil {
			return err
		}
		if !confirmed {
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

	// A surviving fail-closed hook or plugin still depends on Rampart. Preserve
	// the runtime when any integration could not be removed so uninstall cannot
	// turn a recoverable cleanup error into a completely unusable agent.
	serviceRemoved, serviceFailed, runtimePreserved := teardownManagedRuntime(
		w,
		home,
		runtime.GOOS,
		defaultRunner,
		len(integrationFailed) > 0,
		stopBackgroundServe,
		removeManagedServeServices,
	)
	removed = append(removed, serviceRemoved...)
	failed = append(failed, serviceFailed...)

	// Remove from PATH (Windows only)
	if !runtimePreserved && runtime.GOOS == "windows" {
		fmt.Fprintln(w, "Removing from PATH...")
		if removeFromWindowsPath(home) {
			removed = append(removed, "PATH entry")
		}
	}

	// Remove a legacy shell shim if present.
	if !runtimePreserved {
		shimPath := filepath.Join(home, ".local", "bin", "rampart-shim")
		if _, err := os.Stat(shimPath); err == nil {
			if err := os.Remove(shimPath); err == nil {
				removed = append(removed, "shell shim")
			}
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
	if runtimePreserved {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Uninstall paused before removing the Rampart runtime.")
		fmt.Fprintln(w, "Repair the cleanup errors above, then rerun `rampart uninstall`.")
		fmt.Fprintln(w, "Do not delete ~/.rampart or the Rampart binary while a managed integration or runtime remains installed.")
		return fmt.Errorf("uninstall incomplete: %d Rampart-managed item(s) could not be removed; runtime preserved", len(failed))
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
		fmt.Fprintf(w, "    Remove-Item -LiteralPath %s -Recurse -Force\n", powershellQuoteClineArg(rampartDir))
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Then restart your terminal to update PATH.")
	default:
		fmt.Fprintf(w, "    rm -rf -- %s\n", shellQuoteCodexHookArg(rampartDir))
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
			fmt.Fprintf(w, "The rampart binary at %q can also be deleted.\n", exe)
		}
	}

	fmt.Fprintln(w, "")
	if len(failed) > 0 {
		return fmt.Errorf("uninstall incomplete: %d Rampart-managed item(s) could not be removed", len(failed))
	}
	return nil
}

type stopBackgroundServeFunc func(io.Writer, bool) error
type removeManagedServeServicesFunc func(string, string, commandRunner) ([]string, []string)

func teardownManagedRuntime(
	w io.Writer,
	home, goos string,
	runner commandRunner,
	preserve bool,
	stopBackground stopBackgroundServeFunc,
	removeServices removeManagedServeServicesFunc,
) (removed, failed []string, preserved bool) {
	if preserve {
		fmt.Fprintln(w, "Preserving rampart serve because one or more agent integrations could not be removed safely.")
		return nil, nil, true
	}

	// The background fallback is the only unmanaged-by-service process the
	// uninstaller stops directly. stopBackgroundServe authenticates the PID
	// file against a Rampart `serve` process immediately before signaling, so a
	// stale or reused PID can never turn into a broad process kill.
	fmt.Fprintln(w, "Stopping rampart serve...")
	if err := stopBackground(w, true); err != nil {
		failed = append(failed, fmt.Sprintf("background serve process: %v", err))
	}
	removed, serviceFailed := removeServices(home, goos, runner)
	failed = append(failed, serviceFailed...)
	// A partial runtime teardown is not a successful uninstall. Keep the binary,
	// PATH entry, and compatibility shim available so any surviving service or
	// hook can still call Rampart and a retry can repair the remaining state.
	return removed, failed, len(failed) > 0
}

func confirmUninstall(in io.Reader, out io.Writer) (bool, error) {
	fmt.Fprint(out, "This will remove Rampart from your system. Continue? [y/N] ")
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("uninstall: read confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return strings.HasPrefix(answer, "y"), nil
}

func removeManagedServeServices(home, goos string, runner commandRunner) (removed, failed []string) {
	switch goos {
	case "darwin":
		for _, service := range rampartLaunchdServices(home) {
			managed, err := managedLaunchdServiceFile(service.PlistPath, service.Label)
			if err != nil {
				failed = append(failed, err.Error())
				continue
			}
			if !managed {
				continue
			}

			// Only remove a loaded job after both its fixed path and contents
			// establish Rampart ownership. A missing job is a normal stale-file
			// case; an inspection failure is not proof that it is safe to leave a
			// running job behind while deleting its definition.
			loaded, err := launchctlLabelLoaded(runner, service.Label)
			if err != nil {
				failed = append(failed, fmt.Sprintf("inspect managed LaunchAgent %s: %v", service.Label, err))
				continue
			}
			if loaded {
				if err := runner("launchctl", "remove", service.Label).Run(); err != nil {
					failed = append(failed, fmt.Sprintf("stop managed LaunchAgent %s: %v", service.Label, err))
					continue
				}
			}
			if err := os.Remove(service.PlistPath); err != nil {
				failed = append(failed, fmt.Sprintf("remove managed LaunchAgent %q: %v", service.PlistPath, err))
				continue
			}
			removed = append(removed, "LaunchAgent service "+service.Label)
		}

	case "linux":
		serviceDir := filepath.Join(home, ".config", "systemd", "user")
		services := []struct {
			name string
			path string
		}{
			{name: "rampart-serve.service", path: filepath.Join(serviceDir, "rampart-serve.service")},
			{name: "rampart-proxy.service", path: filepath.Join(serviceDir, "rampart-proxy.service")},
		}
		removedAny := false
		for _, service := range services {
			managed, err := managedSystemdServiceFile(service.path)
			if err != nil {
				failed = append(failed, err.Error())
				continue
			}
			if !managed {
				continue
			}

			if err := runner("systemctl", "--user", "stop", service.name).Run(); err != nil {
				failed = append(failed, fmt.Sprintf("stop managed systemd service %s: %v", service.name, err))
				continue
			}
			if err := runner("systemctl", "--user", "disable", service.name).Run(); err != nil {
				failed = append(failed, fmt.Sprintf("disable managed systemd service %s: %v", service.name, err))
				continue
			}
			if err := os.Remove(service.path); err != nil {
				failed = append(failed, fmt.Sprintf("remove managed systemd service %q: %v", service.path, err))
				continue
			}
			removedAny = true
			removed = append(removed, "systemd service "+service.name)
		}
		if removedAny {
			if err := runner("systemctl", "--user", "daemon-reload").Run(); err != nil {
				failed = append(failed, fmt.Sprintf("reload systemd user manager: %v", err))
			}
		}
	}
	return removed, failed
}

func managedLaunchdServiceFile(path, label string) (bool, error) {
	data, exists, err := readRegularServiceFile(path)
	if err != nil || !exists {
		return false, err
	}
	actualLabel, args, err := launchdServiceIdentity(data)
	if err != nil {
		return false, fmt.Errorf("parse LaunchAgent %q: %w", path, err)
	}
	if actualLabel != label || !isRampartServeArguments(args) {
		return false, fmt.Errorf("refusing to remove unrecognized LaunchAgent at %q", path)
	}
	return true, nil
}

func launchdServiceIdentity(data []byte) (label string, programArguments []string, err error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	lastKey := ""
	inProgramArguments := false
	labelSeen := false
	programArgumentsSeen := false
	for {
		token, decodeErr := decoder.Token()
		if errors.Is(decodeErr, io.EOF) {
			return label, programArguments, nil
		}
		if decodeErr != nil {
			return "", nil, decodeErr
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "key":
				var key string
				if err := decoder.DecodeElement(&key, &element); err != nil {
					return "", nil, err
				}
				lastKey = strings.TrimSpace(key)
			case "array":
				inProgramArguments = lastKey == "ProgramArguments"
				if inProgramArguments {
					if programArgumentsSeen {
						return "", nil, fmt.Errorf("duplicate ProgramArguments key")
					}
					programArgumentsSeen = true
				}
				lastKey = ""
			case "string":
				var value string
				if err := decoder.DecodeElement(&value, &element); err != nil {
					return "", nil, err
				}
				if inProgramArguments {
					programArguments = append(programArguments, value)
				} else if lastKey == "Label" {
					if labelSeen {
						return "", nil, fmt.Errorf("duplicate Label key")
					}
					labelSeen = true
					label = value
				}
				lastKey = ""
			}
		case xml.EndElement:
			if element.Name.Local == "array" {
				inProgramArguments = false
			}
		}
	}
}

func isRampartServeArguments(args []string) bool {
	if len(args) < 2 {
		return false
	}
	name := strings.ToLower(filepath.Base(strings.TrimSpace(args[0])))
	if name != "rampart" && name != "rampart.exe" {
		return false
	}
	// Managed definitions generated by Rampart put `serve` in the first
	// argument position. Finding that word later could claim an unrelated
	// command such as `rampart doctor --output serve`.
	return strings.TrimSpace(args[1]) == "serve"
}

func managedSystemdServiceFile(path string) (bool, error) {
	data, exists, err := readRegularServiceFile(path)
	if err != nil || !exists {
		return false, err
	}
	var execStarts []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= len("ExecStart=") && strings.EqualFold(line[:len("ExecStart=")], "ExecStart=") {
			execStarts = append(execStarts, strings.TrimSpace(line[len("ExecStart="):]))
		}
	}
	if len(execStarts) != 1 {
		return false, fmt.Errorf("refusing to remove systemd service with %d ExecStart directives at %q", len(execStarts), path)
	}
	binary, args, ok := splitServiceCommand(execStarts[0])
	if !ok || !isRampartServeArguments(append([]string{binary}, args...)) {
		return false, fmt.Errorf("refusing to remove unrecognized systemd service at %q", path)
	}
	return true, nil
}

func splitServiceCommand(command string) (binary string, args []string, ok bool) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", nil, false
	}
	remaining := ""
	if command[0] == '"' {
		end := 1
		escaped := false
		for ; end < len(command); end++ {
			if escaped {
				escaped = false
				continue
			}
			if command[end] == '\\' {
				escaped = true
				continue
			}
			if command[end] == '"' {
				break
			}
		}
		if end >= len(command) {
			return "", nil, false
		}
		decoded, err := strconv.Unquote(command[:end+1])
		if err != nil {
			return "", nil, false
		}
		binary = decoded
		remaining = command[end+1:]
	} else {
		fields := strings.Fields(command)
		if len(fields) == 0 {
			return "", nil, false
		}
		binary = fields[0]
		remaining = strings.TrimSpace(strings.TrimPrefix(command, binary))
	}
	return binary, strings.Fields(remaining), true
}

func readRegularServiceFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("inspect service file %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("refusing to remove non-regular service file at %q", path)
	}
	if info.Size() > maxServiceStateFileBytes {
		return nil, false, fmt.Errorf("refusing to read service file larger than %d bytes at %q", maxServiceStateFileBytes, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read service file %q: %w", path, err)
	}
	return data, true, nil
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
