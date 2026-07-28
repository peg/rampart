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
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const clineManagedHookMarker = "# Managed by Rampart: Cline hook v2"

var clineHookEvents = []string{"PreToolUse", "PostToolUse"}

func newSetupClineCmd(_ *rootOptions) *cobra.Command {
	var workspace bool
	var force bool
	var remove bool
	var hooksDirFlag string
	var dataDirFlag string

	cmd := &cobra.Command{
		Use:   "cline",
		Short: "Install Rampart native hooks for Cline",
		Long: `Installs Cline's platform-native PreToolUse and PostToolUse files.

By default Rampart uses Cline's shared user hook directory:
  ~/Documents/Cline/Hooks/

Use --workspace for the current workspace's .clinerules/hooks directory or
--hooks-dir for an explicit runtime hook directory. Cline's --data-dir and
CLINE_DATA_DIR relocate state, not hook discovery, in current Cline builds.

On Linux and macOS Cline discovers executable, extensionless hook files. On
Windows it discovers .ps1 files and launches them with PowerShell. Rampart
never overwrites or removes a hook file it does not own.

Use --remove to uninstall Rampart-managed hook files.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if workspace && strings.TrimSpace(hooksDirFlag) != "" {
				return fmt.Errorf("setup cline: --workspace and --hooks-dir are mutually exclusive")
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup cline: resolve home: %w", err)
			}
			if strings.TrimSpace(home) == "" {
				return fmt.Errorf("setup cline: resolved home directory is empty")
			}

			hookDir, installScope, err := resolveClineSetupHookDir(home, workspace, hooksDirFlag)
			if err != nil {
				return err
			}
			if remove {
				return removeClineHooksFromDir(cmd, hookDir)
			}

			rampartBin := resolveRampartHookBinary()
			paths, migrated, err := installClineHooks(hookDir, rampartBin, runtime.GOOS, force)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Cline hooks installed (%s)\n", installScope)
			fmt.Fprintf(cmd.OutOrStdout(), "  PreToolUse:  %s\n", paths[0])
			fmt.Fprintf(cmd.OutOrStdout(), "  PostToolUse: %s\n", paths[1])
			if migrated {
				fmt.Fprintln(cmd.OutOrStdout(), "✓ Migrated the legacy Rampart directory layout used by earlier releases.")
			}
			if runtime.GOOS == "windows" {
				fmt.Fprintln(cmd.OutOrStdout(), "  Cline activates Windows .ps1 hooks by file presence and requires PowerShell.")
				fmt.Fprintln(cmd.OutOrStdout(), "  Physical Windows host E2E is still pending; run `rampart verify cline` on the target host.")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "  Rampart enabled both hook files with executable permissions.")
				fmt.Fprintln(cmd.OutOrStdout(), "  Keep hooks enabled in Cline's Hooks UI; disabling a hook removes its executable bit.")
			}
			if strings.TrimSpace(hooksDirFlag) != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "  This is an explicit hook directory. Pass the same --hooks-dir to Cline and confirm host discovery.")
				fmt.Fprintln(cmd.OutOrStdout(), "  Current upstream Cline advertises --hooks-dir, but its CLI loader does not consume that override reliably.")
			}
			if strings.TrimSpace(dataDirFlag) != "" || strings.TrimSpace(os.Getenv("CLINE_DATA_DIR")) != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "  Note: Cline's current --data-dir/CLINE_DATA_DIR does not relocate hook directories.")
			}
			fmt.Fprintln(cmd.OutOrStdout(), "  Do not run Cline CLI with legacy --yolo: current Cline disables runtime hooks in that mode.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Cline CLI currently continues after hook errors/timeouts and treats post-tool hooks as asynchronous audit only.")

			printFirstRunTest(cmd.OutOrStdout())
			return nil
		},
	}

	cmd.Flags().BoolVar(&workspace, "workspace", false, "Install hooks in .clinerules/hooks for the current workspace")
	cmd.Flags().StringVar(&hooksDirFlag, "hooks-dir", "", "Install hooks in an explicit Cline runtime hook directory")
	cmd.Flags().StringVar(&dataDirFlag, "data-dir", "", "Cline data directory (accepted for parity; does not relocate hooks)")
	cmd.Flags().BoolVar(&force, "force", false, "Refresh Rampart-managed hooks (never overwrites another hook)")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove Rampart-managed Cline hook files")
	return cmd
}

func resolveClineSetupHookDir(home string, workspace bool, explicit string) (string, string, error) {
	if value := strings.TrimSpace(explicit); value != "" {
		expanded, err := expandClineHomePath(value, home)
		if err != nil {
			return "", "", err
		}
		return filepath.Clean(expanded), "explicit", nil
	}
	if workspace {
		return filepath.Join(".clinerules", "hooks"), "workspace-level", nil
	}
	return clineUserHooksDir(home), "user-level", nil
}

func expandClineHomePath(value, home string) (string, error) {
	if value == "~" {
		return home, nil
	}
	if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		relative := strings.TrimLeft(value[1:], `/\`)
		return filepath.Join(home, filepath.FromSlash(strings.ReplaceAll(relative, `\`, "/"))), nil
	}
	if strings.HasPrefix(value, "~") {
		return "", fmt.Errorf("setup cline: only the current user's ~ path is supported: %s", value)
	}
	return value, nil
}

func clineUserHooksDir(home string) string {
	return filepath.Join(home, "Documents", "Cline", "Hooks")
}

func clineCLIHooksDir(home string) string {
	clineDir := strings.TrimSpace(os.Getenv("CLINE_DIR"))
	if clineDir == "" {
		clineDir = filepath.Join(home, ".cline")
	} else if expanded, err := expandClineHomePath(clineDir, home); err == nil {
		clineDir = expanded
	}
	return filepath.Join(filepath.Clean(clineDir), "hooks")
}

func clineKnownHookDirs(home string) []string {
	candidates := []string{clineUserHooksDir(home), clineCLIHooksDir(home)}
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		candidates = append(candidates,
			filepath.Join(cwd, ".clinerules", "hooks"),
			filepath.Join(cwd, ".cline", "hooks"),
		)
	}
	seen := make(map[string]struct{}, len(candidates))
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func clineHookFileName(event, goos string) string {
	if goos == "windows" {
		return event + ".ps1"
	}
	return event
}

func clineHookPath(hookDir, event, goos string) string {
	return filepath.Join(hookDir, clineHookFileName(event, goos))
}

func createClineHookScript(rampartBin, event, goos string) string {
	if goos == "windows" {
		return fmt.Sprintf(`%s
# Rampart %s policy hook for Cline
$ErrorActionPreference = "Stop"
$inputJson = [Console]::In.ReadToEnd()
$inputJson | & %s hook --format cline
exit $LASTEXITCODE
`, clineManagedHookMarker, event, powershellQuoteClineArg(rampartBin))
	}
	return fmt.Sprintf(`#!/bin/sh
%s
# Rampart %s policy hook for Cline
set -eu
exec %s hook --format cline
`, clineManagedHookMarker, event, shellQuoteCodexHookArg(rampartBin))
}

func powershellQuoteClineArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

type clineDestinationState int

const (
	clineDestinationMissing clineDestinationState = iota
	clineDestinationManagedFile
	clineDestinationManagedLegacyDir
)

func inspectClineDestination(path, event string) (clineDestinationState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return clineDestinationMissing, nil
		}
		return clineDestinationMissing, fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return clineDestinationMissing, fmt.Errorf("refusing Cline hook symlink at %s", path)
	}
	if info.Mode().IsRegular() {
		data, err := os.ReadFile(path)
		if err != nil {
			return clineDestinationMissing, fmt.Errorf("read %s: %w", path, err)
		}
		if !clineHookScriptManaged(data) {
			return clineDestinationMissing, fmt.Errorf("existing Cline %s hook at %s is not managed by Rampart", event, path)
		}
		return clineDestinationManagedFile, nil
	}
	if !info.IsDir() {
		return clineDestinationMissing, fmt.Errorf("refusing non-file Cline hook destination at %s", path)
	}

	legacyName := "rampart-policy"
	if event == "PostToolUse" {
		legacyName = "rampart-audit"
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return clineDestinationMissing, fmt.Errorf("read legacy Cline hook directory %s: %w", path, err)
	}
	if len(entries) != 1 || entries[0].Name() != legacyName || entries[0].Type()&os.ModeSymlink != 0 {
		return clineDestinationMissing, fmt.Errorf("existing Cline %s directory at %s contains non-Rampart content", event, path)
	}
	legacyPath := filepath.Join(path, legacyName)
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return clineDestinationMissing, fmt.Errorf("read legacy Cline hook %s: %w", legacyPath, err)
	}
	if !clineHookScriptManaged(data) {
		return clineDestinationMissing, fmt.Errorf("legacy Cline hook at %s is not managed by Rampart", legacyPath)
	}
	return clineDestinationManagedLegacyDir, nil
}

func installClineHooks(hookDir, rampartBin, goos string, force bool) ([2]string, bool, error) {
	var paths [2]string
	var states [2]clineDestinationState
	legacyWindowsDirs := make([]string, 0, len(clineHookEvents))
	for index, event := range clineHookEvents {
		paths[index] = clineHookPath(hookDir, event, goos)
		state, err := inspectClineDestination(paths[index], event)
		if err != nil {
			if force {
				return paths, false, fmt.Errorf("setup cline: %w; --force never overwrites hooks Rampart does not own", err)
			}
			return paths, false, fmt.Errorf("setup cline: %w", err)
		}
		states[index] = state
		if goos == "windows" {
			legacyPath := filepath.Join(hookDir, event)
			legacyState, legacyErr := inspectClineDestination(legacyPath, event)
			if legacyErr == nil && legacyState == clineDestinationManagedLegacyDir {
				legacyWindowsDirs = append(legacyWindowsDirs, legacyPath)
			}
			// A non-Rampart extensionless file/directory does not collide with
			// Windows' .ps1 discovery and must be preserved.
		}
	}

	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		return paths, false, fmt.Errorf("setup cline: create hook directory: %w", err)
	}
	migrated := false
	for index, event := range clineHookEvents {
		path := paths[index]
		if states[index] == clineDestinationManagedLegacyDir {
			legacyName := "rampart-policy"
			if event == "PostToolUse" {
				legacyName = "rampart-audit"
			}
			if err := os.Remove(filepath.Join(path, legacyName)); err != nil {
				return paths, migrated, fmt.Errorf("setup cline: remove legacy hook: %w", err)
			}
			if err := os.Remove(path); err != nil {
				return paths, migrated, fmt.Errorf("setup cline: remove legacy hook directory: %w", err)
			}
			migrated = true
		}
		content := createClineHookScript(rampartBin, event, goos)
		if err := atomicWritePrivateFile(path, []byte(content)); err != nil {
			return paths, migrated, fmt.Errorf("setup cline: install %s hook: %w", event, err)
		}
		if goos != "windows" {
			if err := os.Chmod(path, 0o755); err != nil {
				return paths, migrated, fmt.Errorf("setup cline: enable %s hook: %w", event, err)
			}
		}
	}
	for _, legacyPath := range legacyWindowsDirs {
		event := filepath.Base(legacyPath)
		legacyName := "rampart-policy"
		if event == "PostToolUse" {
			legacyName = "rampart-audit"
		}
		if err := os.Remove(filepath.Join(legacyPath, legacyName)); err != nil {
			return paths, migrated, fmt.Errorf("setup cline: remove legacy hook: %w", err)
		}
		if err := os.Remove(legacyPath); err != nil {
			return paths, migrated, fmt.Errorf("setup cline: remove legacy hook directory: %w", err)
		}
		migrated = true
	}
	return paths, migrated, nil
}

func removeClineHooksFromDir(cmd *cobra.Command, hookDir string) error {
	var removed []string
	var skipped []string
	for _, event := range clineHookEvents {
		for _, goos := range []string{"linux", "windows"} {
			path := clineHookPath(hookDir, event, goos)
			info, err := os.Lstat(path)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return fmt.Errorf("setup cline: inspect %s: %w", path, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				skipped = append(skipped, path)
				continue
			}
			if info.IsDir() {
				legacyName := "rampart-policy"
				if event == "PostToolUse" {
					legacyName = "rampart-audit"
				}
				legacyPath := filepath.Join(path, legacyName)
				legacyInfo, statErr := os.Lstat(legacyPath)
				if statErr != nil || !legacyInfo.Mode().IsRegular() || legacyInfo.Mode()&os.ModeSymlink != 0 {
					skipped = append(skipped, path)
					continue
				}
				data, readErr := os.ReadFile(legacyPath)
				if readErr != nil || !clineHookScriptManaged(data) {
					skipped = append(skipped, path)
					continue
				}
				if err := os.Remove(legacyPath); err != nil {
					return fmt.Errorf("setup cline: remove %s: %w", legacyPath, err)
				}
				_ = os.Remove(path) // Only succeeds if no user-owned entries remain.
				removed = append(removed, legacyPath)
				continue
			}
			if !info.Mode().IsRegular() {
				skipped = append(skipped, path)
				continue
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return fmt.Errorf("setup cline: read %s: %w", path, readErr)
			}
			if !clineHookScriptManaged(data) {
				skipped = append(skipped, path)
				continue
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("setup cline: remove %s: %w", path, err)
			}
			removed = append(removed, path)
		}
	}

	for _, path := range removed {
		fmt.Fprintf(cmd.OutOrStdout(), "  Removed: %s\n", path)
	}
	for _, path := range skipped {
		fmt.Fprintf(cmd.OutOrStdout(), "  Skipped non-Rampart hook: %s\n", path)
	}
	if len(removed) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No Rampart Cline hooks found. Nothing to remove.")
		return nil
	}
	if len(skipped) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Non-Rampart hooks were preserved.")
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Removed %d Rampart Cline hook(s)\n", len(removed))
	return nil
}

func clineHookScriptManaged(content []byte) bool {
	script := string(content)
	current := strings.Contains(script, clineManagedHookMarker) && strings.Contains(script, "hook --format cline")
	legacy := (strings.Contains(script, "# Rampart PreToolUse hook for Cline") ||
		strings.Contains(script, "# Rampart PostToolUse hook for Cline")) &&
		strings.Contains(script, "hook --format cline")
	return current || legacy
}

func clineHookPairConfigured(hookDir, goos string) bool {
	return validateClineHookPair(hookDir, goos) == nil
}

func validateClineHookPair(hookDir, goos string) error {
	for _, event := range clineHookEvents {
		path := clineHookPath(hookDir, event, goos)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%s is missing: %w", path, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a regular, non-symlink hook file", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if !clineHookScriptManaged(data) {
			return fmt.Errorf("%s is not a Rampart-managed Cline hook", path)
		}
		if goos != "windows" && info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("%s is disabled because it is not executable", path)
		}
	}
	return nil
}

func clineHooksConfiguredForHome(home string) bool {
	for _, hookDir := range clineKnownHookDirs(home) {
		if clineHookPairConfigured(hookDir, runtime.GOOS) {
			return true
		}
	}
	return false
}
