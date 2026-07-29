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
	return installClineHooksWithRename(hookDir, rampartBin, goos, force, os.Rename)
}

func installClineHooksWithRename(
	hookDir, rampartBin, goos string,
	force bool,
	rename func(string, string) error,
) ([2]string, bool, error) {
	var paths [2]string
	hookDir = filepath.Clean(hookDir)
	if info, err := os.Lstat(hookDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return paths, false, fmt.Errorf("setup cline: refusing linked or non-directory hook root %s", hookDir)
		}
	} else if !os.IsNotExist(err) {
		return paths, false, fmt.Errorf("setup cline: inspect hook root %s: %w", hookDir, err)
	}
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
	migrated := len(legacyWindowsDirs) > 0
	for _, state := range states {
		migrated = migrated || state == clineDestinationManagedLegacyDir
	}

	// Missing and regular managed hooks can be replaced atomically in place.
	// Install those first so a routine refresh never removes both live hooks.
	for index, event := range clineHookEvents {
		if states[index] == clineDestinationManagedLegacyDir {
			continue
		}
		content := createClineHookScript(rampartBin, event, goos)
		if err := writeClineHookFile(paths[index], content, goos); err != nil {
			return paths, migrated, fmt.Errorf("setup cline: install %s hook: %w", event, err)
		}
	}

	// A legacy directory and its replacement file cannot coexist at the same
	// path. Migrate only that one event through a same-filesystem backup, leaving
	// the other lifecycle hook live throughout the migration.
	for index, event := range clineHookEvents {
		if states[index] != clineDestinationManagedLegacyDir {
			continue
		}
		content := createClineHookScript(rampartBin, event, goos)
		if err := migrateClineLegacyHook(paths[index], event, content, goos, rename); err != nil {
			return paths, migrated, err
		}
	}

	if err := validateClineHookPair(hookDir, goos); err != nil {
		return paths, migrated, fmt.Errorf("setup cline: validate installed hooks: %w", err)
	}

	// Windows discovers the .ps1 pair. Retire an owned extensionless legacy
	// layout only after the complete active pair has validated successfully.
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
	}
	return paths, migrated, nil
}

func writeClineHookFile(path, content, goos string) error {
	mode := os.FileMode(0o600)
	if goos != "windows" {
		mode = 0o755
	}
	// Set the executable mode on the staged inode before the atomic replace;
	// a crash can therefore never leave a newly refreshed hook disabled.
	if err := atomicWritePrivateFileWithMode(path, []byte(content), mode); err != nil {
		return err
	}
	return validateClineHookFile(path, goos)
}

func migrateClineLegacyHook(path, event, content, goos string, rename func(string, string) error) error {
	txnDir, err := os.MkdirTemp(filepath.Dir(path), ".rampart-cline-migrate-*")
	if err != nil {
		return fmt.Errorf("setup cline: create %s migration: %w", event, err)
	}
	preserveTxn := false
	defer func() {
		if !preserveTxn {
			_ = os.RemoveAll(txnDir)
		}
	}()

	stagedPath := filepath.Join(txnDir, "replacement")
	if err := writeClineHookFile(stagedPath, content, goos); err != nil {
		return fmt.Errorf("setup cline: stage %s hook: %w", event, err)
	}
	backupPath := filepath.Join(txnDir, "legacy")
	if err := rename(path, backupPath); err != nil {
		return fmt.Errorf("setup cline: back up legacy %s hook: %w", event, err)
	}
	if err := rename(stagedPath, path); err != nil {
		if restoreErr := rename(backupPath, path); restoreErr != nil {
			preserveTxn = true
			return fmt.Errorf("setup cline: activate %s hook: %w (restore failed: %v; backup preserved at %s)", event, err, restoreErr, txnDir)
		}
		return fmt.Errorf("setup cline: activate %s hook: %w", event, err)
	}
	if err := validateClineHookFile(path, goos); err != nil {
		if removeErr := removeManagedClineHookFile(path); removeErr != nil {
			preserveTxn = true
			return fmt.Errorf("setup cline: validate %s hook: %w (remove replacement failed: %v; backup preserved at %s)", event, err, removeErr, txnDir)
		}
		if restoreErr := rename(backupPath, path); restoreErr != nil {
			preserveTxn = true
			return fmt.Errorf("setup cline: validate %s hook: %w (restore failed: %v; backup preserved at %s)", event, err, restoreErr, txnDir)
		}
		return fmt.Errorf("setup cline: validate %s hook: %w", event, err)
	}
	if err := os.RemoveAll(txnDir); err != nil {
		preserveTxn = true
		return fmt.Errorf("setup cline: %s hook migrated but transaction cleanup failed at %s: %w", event, txnDir, err)
	}
	return nil
}

func removeManagedClineHookFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove changed replacement %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !clineHookScriptManaged(data) {
		return fmt.Errorf("refusing to remove unowned replacement %s", path)
	}
	return os.Remove(path)
}

func removeClineHooksFromDir(cmd *cobra.Command, hookDir string) error {
	info, err := os.Lstat(hookDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(cmd.OutOrStdout(), "No Rampart Cline hooks found. Nothing to remove.")
			return nil
		}
		return fmt.Errorf("setup cline: inspect hook root %s: %w", hookDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("setup cline: refusing linked or non-directory hook root %s", hookDir)
	}
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

func validateClineHookPair(hookDir, goos string) error {
	for _, event := range clineHookEvents {
		path := clineHookPath(hookDir, event, goos)
		if err := validateClineHookFile(path, goos); err != nil {
			return err
		}
	}
	return nil
}

func validateClineHookFile(path, goos string) error {
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
	return nil
}

func clineHooksConfiguredForHome(home string) bool {
	for _, hookDir := range clineKnownHookDirs(home) {
		if validateCurrentClineHookPair(hookDir, runtime.GOOS) == nil {
			return true
		}
	}
	return false
}

func validateCurrentClineHookPair(hookDir, goos string) error {
	if err := validateClineHookPair(hookDir, goos); err != nil {
		return err
	}
	rampartBin := resolveRampartHookBinary()
	for _, event := range clineHookEvents {
		path := clineHookPath(hookDir, event, goos)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		expected := createClineHookScript(rampartBin, event, goos)
		if string(data) != expected {
			return fmt.Errorf("%s invokes a stale or non-current Rampart binary", path)
		}
	}
	return nil
}
