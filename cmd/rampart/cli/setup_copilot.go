// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const copilotRampartHookFile = "rampart.json"

func newSetupCopilotCmd() *cobra.Command {
	var force bool
	var remove bool
	var policy bool

	cmd := &cobra.Command{
		Use:   "copilot",
		Short: "Install Rampart hooks for Copilot CLI and VS Code",
		Long: `Installs user-level PreToolUse and PostToolUse hooks in Copilot's
hooks directory. The same hook file is loaded by Copilot CLI and the VS Code
Copilot agent host.

Use --policy from an elevated shell to install Copilot CLI's administrator-owned,
machine-wide policy hook. Copilot CLI policy hooks do not apply to VS Code.
Run 'rampart setup copilot --remove' to uninstall the user hook.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup copilot: resolve home: %w", err)
			}
			path := filepath.Join(copilotHomeDir(home), "hooks", copilotRampartHookFile)
			if policy {
				path = copilotPolicyHookPath()
			}

			if remove {
				removed, err := removeCopilotHooks(path)
				if err != nil {
					return err
				}
				if !removed {
					fmt.Fprintln(cmd.OutOrStdout(), "No Rampart Copilot integration found. Nothing to remove.")
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart Copilot hook removed from %s\n", path)
				return nil
			}

			hookBin := resolveRampartHookBinary()
			bashCommand := shellQuoteCodexHookArg(hookBin) + " hook --format copilot"
			powershellCommand := "& " + windowsQuoteCodexHookArg(hookBin) + " hook --format copilot"
			if err := installCopilotHooks(path, bashCommand, powershellCommand, force); err != nil {
				if policy && os.IsPermission(err) {
					return fmt.Errorf("setup copilot: install machine policy: %w (rerun from an elevated shell)", err)
				}
				return err
			}

			if policy {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart Copilot CLI machine policy installed at %s\n", path)
				fmt.Fprintln(cmd.OutOrStdout(), "  Administrator policy hooks load before user hooks and cannot be disabled by Copilot CLI users.")
				fmt.Fprintln(cmd.OutOrStdout(), "  This policy boundary is Copilot CLI-only; deploy the user hook plus VS Code enterprise policies for editor sessions.")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart Copilot hooks installed at %s\n", path)
				fmt.Fprintln(cmd.OutOrStdout(), "  Covers Copilot CLI and VS Code agent tool calls exposed through PreToolUse and PostToolUse.")
			}
			fmt.Fprintln(cmd.OutOrStdout(), "  Allowed calls still pass through Copilot's own permission and sandbox checks.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Copilot CLI hook timeouts are fail-open; `rampart verify copilot` reports this limitation.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Uninstall: rampart setup copilot --remove")
			printFirstRunTest(cmd.OutOrStdout())
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Replace an existing non-Rampart rampart.json hook file")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove the Rampart Copilot hook file")
	cmd.Flags().BoolVar(&policy, "policy", false, "Install or remove the machine-wide Copilot CLI administrator policy hook")
	return cmd
}

func copilotHomeDir(home string) string {
	if configured := strings.TrimSpace(os.Getenv("COPILOT_HOME")); configured != "" {
		expanded := os.ExpandEnv(configured)
		if expanded == "~" {
			expanded = home
		} else if strings.HasPrefix(expanded, "~/") || strings.HasPrefix(expanded, `~\`) {
			// Accept either separator because COPILOT_HOME is commonly copied
			// between shell profiles and Windows environments.
			relative := strings.TrimLeft(expanded[1:], `/\`)
			relative = filepath.FromSlash(strings.ReplaceAll(relative, `\`, "/"))
			expanded = filepath.Join(home, relative)
		}
		return filepath.Clean(expanded)
	}
	return filepath.Join(home, ".copilot")
}

func copilotPolicyHookPath() string {
	if runtime.GOOS == "windows" {
		programData := strings.TrimSpace(os.Getenv("ProgramData"))
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "GitHub", "Copilot", "policy.d", "50-rampart.json")
	}
	return filepath.Join(string(os.PathSeparator), "etc", "github-copilot", "policy.d", "50-rampart.json")
}

func installCopilotHooks(path, bashCommand, powershellCommand string, force bool) error {
	if data, err := os.ReadFile(path); err == nil {
		if !copilotHookDataManaged(data) && !force {
			return fmt.Errorf("setup copilot: existing %s is not managed by Rampart (use --force to replace)", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("setup copilot: read %s: %w", path, err)
	}

	handler := func() map[string]any {
		return map[string]any{
			"type":       "command",
			"bash":       bashCommand,
			"powershell": powershellCommand,
			"timeoutSec": 30,
		}
	}
	config := map[string]any{
		"version": 1,
		"hooks": map[string]any{
			// PascalCase selects the VS Code-compatible payload in Copilot CLI,
			// allowing one adapter and one hook file to cover both local hosts.
			"PreToolUse":  []any{handler()},
			"PostToolUse": []any{handler()},
		},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("setup copilot: marshal hooks: %w", err)
	}
	data = append(data, '\n')
	if err := atomicWritePrivateFile(path, data); err != nil {
		return fmt.Errorf("setup copilot: write %s: %w", path, err)
	}
	return nil
}

func copilotHookDataManaged(data []byte) bool {
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		return false
	}
	hooks, ok := config["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		entries, ok := hooks[event].([]any)
		if !ok || len(entries) == 0 {
			return false
		}
		found := false
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			for _, key := range []string{"command", "bash", "powershell"} {
				value, _ := entry[key].(string)
				if strings.Contains(value, "hook --format copilot") {
					found = true
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func copilotHooksConfiguredForHome(home string) bool {
	data, err := os.ReadFile(filepath.Join(copilotHomeDir(home), "hooks", copilotRampartHookFile))
	return err == nil && copilotHookDataManaged(data)
}

func removeCopilotHooks(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("setup copilot: read %s: %w", path, err)
	}
	if !copilotHookDataManaged(data) {
		return false, fmt.Errorf("setup copilot: refusing to remove non-Rampart hook file %s", path)
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("setup copilot: remove %s: %w", path, err)
	}
	return true, nil
}

func copilotInstalledForHome(home string) bool {
	if integrationBinaryOrPathInstalled("copilot", copilotHomeDir(home)) {
		return true
	}
	for _, root := range []string{filepath.Join(home, ".vscode", "extensions"), filepath.Join(home, ".vscode-insiders", "extensions")} {
		matches, _ := filepath.Glob(filepath.Join(root, "github.copilot-chat-*"))
		if len(matches) > 0 {
			return true
		}
	}
	return false
}
