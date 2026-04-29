// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

var execLookPath = osexec.LookPath

func newSetupCmd(opts *rootOptions) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up Rampart integrations with AI agents",
		Long: `Set up Rampart integrations with supported AI agents.

Run without a subcommand to launch the interactive setup wizard.

Supported AI Agents:
  • Claude Code (Anthropic)   - Native hook integration
  • Cline (VS Code)           - Native hook integration
  • OpenClaw                  - Shell wrapper integration`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractiveSetup(cmd, opts)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmations during interactive setup")

	cmd.AddCommand(newSetupClaudeCodeCmd(opts))
	cmd.AddCommand(newSetupClineCmd(opts))
	cmd.AddCommand(newSetupOpenClawCmd(opts))
	cmd.AddCommand(newSetupCodexCmd(opts))

	return cmd
}

// claudeSettings represents the Claude Code settings.json structure.
// We use a flexible map to preserve existing settings.
type claudeSettings map[string]any

func newSetupClaudeCodeCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var remove bool

	cmd := &cobra.Command{
		Use:   "claude-code",
		Short: "Install Rampart hook into Claude Code settings",
		Long: `Adds a PreToolUse hook to ~/.claude/settings.json that routes ALL
tool calls through Rampart's policy engine before execution.

This includes Bash, Read, Write, Edit, Fetch, Task, and any future tools.

Safe to run multiple times — will not duplicate hooks or overwrite
other settings.

Use --remove to uninstall the Rampart hooks from Claude Code settings.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if remove {
				return removeClaudeCodeHooks(cmd)
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup: resolve home: %w", err)
			}

			settingsPath := filepath.Join(home, ".claude", "settings.json")

			// Load existing settings or start fresh
			settings := make(claudeSettings)
			if data, err := os.ReadFile(settingsPath); err == nil {
				if err := json.Unmarshal(data, &settings); err != nil {
					if !force {
						return fmt.Errorf("setup: existing %s has invalid JSON (use --force to overwrite): %w", settingsPath, err)
					}
					settings = make(claudeSettings)
				}
			}

			// Check if Rampart hook already exists
			if hasRampartHook(settings) && !force {
				fmt.Fprintln(cmd.OutOrStdout(), "Rampart hook already configured in Claude Code settings.")
				return nil
			}

			// Build the hook config — no --serve-url needed, hook auto-discovers on localhost:9090.
			// Use absolute path so the hook works regardless of Claude Code's PATH.
			// The hook reads RAMPART_TOKEN from ~/.rampart/token automatically, so
			// settings.json never needs to contain credentials.
			hookBin := "rampart"
			if exe, err := os.Executable(); err == nil {
				hookBin = exe
			} else if p, err := execLookPath("rampart"); err == nil {
				hookBin = p
			}
			// Convert Windows paths to Git Bash format. Claude Code on Windows runs
			// hooks through Git Bash which doesn't understand backslash paths.
			hookBin = toGitBashPath(hookBin)
			hookCommand := hookBin + " hook"

			rampartHook := map[string]any{
				"type":    "command",
				"command": hookCommand,
			}

			// Use wildcard matcher to intercept ALL tools (Bash, Read, Write, Edit, Fetch, Task, etc.)
			// This ensures comprehensive coverage as Claude Code adds new tools.
			allToolsMatcher := map[string]any{
				"matcher": ".*",
				"hooks":   []any{rampartHook},
			}

			// PostToolUseFailure: fires when Claude Code denies a tool after PreToolUse.
			// Matcher ".*" catches all tools so Rampart can inject additionalContext
			// telling Claude to stop retrying instead of burning turns on workarounds.
			postToolUseFailureMatcher := map[string]any{
				"matcher": ".*",
				"hooks":   []any{rampartHook},
			}

			// Get or create hooks section
			hooks, ok := settings["hooks"].(map[string]any)
			if !ok {
				hooks = make(map[string]any)
			}

			// Get or create PreToolUse array (dedup existing rampart entries)
			var preToolUse []any
			if existing, ok := hooks["PreToolUse"].([]any); ok {
				// Filter out any existing rampart hooks
				for _, h := range existing {
					if m, ok := h.(map[string]any); ok {
						if hasRampartInMatcher(m) {
							continue
						}
					}
					preToolUse = append(preToolUse, h)
				}
			}
			preToolUse = append(preToolUse, allToolsMatcher)

			// Get or create PostToolUseFailure array (dedup existing rampart entries)
			var postToolUseFailure []any
			if existing, ok := hooks["PostToolUseFailure"].([]any); ok {
				for _, h := range existing {
					if m, ok := h.(map[string]any); ok {
						if hasRampartInMatcher(m) {
							continue
						}
					}
					postToolUseFailure = append(postToolUseFailure, h)
				}
			}
			postToolUseFailure = append(postToolUseFailure, postToolUseFailureMatcher)

			hooks["PreToolUse"] = preToolUse
			hooks["PostToolUseFailure"] = postToolUseFailure
			settings["hooks"] = hooks

			// Ensure directory exists
			if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
				return fmt.Errorf("setup: create .claude dir: %w", err)
			}

			// Write settings
			data, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return fmt.Errorf("setup: marshal settings: %w", err)
			}
			data = append(data, '\n')

			if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
				return fmt.Errorf("setup: write settings: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart hook installed in %s\n", settingsPath)
			fmt.Fprintf(cmd.OutOrStdout(), "  Hook command: %s\n", hookCommand)
			fmt.Fprintln(cmd.OutOrStdout(), "  Claude Code will now route ALL tool calls through Rampart.")
			fmt.Fprintln(cmd.OutOrStdout(), "  (Bash, Read, Write, Edit, Fetch, Task, and any new tools)")
			fmt.Fprintln(cmd.OutOrStdout(), "  Run 'claude' normally — no wrapper needed.")
			fmt.Fprintln(cmd.OutOrStdout(), "")

			// Tell the user whether dashboard auth is wired up.
			if tok, _ := readPersistedToken(); tok != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "  Dashboard: token auto-detected from ~/.rampart/token ✓")
				fmt.Fprintln(cmd.OutOrStdout(), "  Events will appear in the dashboard automatically.")
			} else if os.Getenv("RAMPART_TOKEN") != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "  Dashboard: token detected from RAMPART_TOKEN env ✓")
				fmt.Fprintln(cmd.OutOrStdout(), "  Events will appear in the dashboard automatically.")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "  Dashboard: no token found — running in local-only mode.")
				fmt.Fprintln(cmd.OutOrStdout(), "  Run 'rampart serve install' first to enable the dashboard.")
			}

			fmt.Fprintln(cmd.OutOrStdout(), "Tip: export RAMPART_SESSION=my-project in your shell profile to tag audit events with a project name.")
			if !hasInstalledPolicy() {
				fmt.Fprintln(cmd.OutOrStdout(), "💡 No policy found — run 'rampart init --profile openclaw' to install the OpenClaw-optimized policy")
			}

			// Check if rampart is in system PATH.
			if _, err := execLookPath("rampart"); err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "")
				fmt.Fprintln(cmd.ErrOrStderr(), "⚠ Warning: 'rampart' is not in your system PATH.")
				fmt.Fprintln(cmd.ErrOrStderr(), "  Claude Code hooks won't work until it is.")
				if runtime.GOOS == "windows" {
					w := cmd.ErrOrStderr()
					_, _ = w.Write([]byte("  Fix with: $env:PATH += \";$env:USERPROFILE\\.rampart\\bin\"\n"))
					_, _ = w.Write([]byte("  Or add %USERPROFILE%\\.rampart\\bin to your system PATH permanently.\n"))
				} else {
					fmt.Fprintln(cmd.ErrOrStderr(), "  Fix with: sudo ln -sf $(go env GOPATH)/bin/rampart /usr/local/bin/rampart")
				}
			}

			printFirstRunTest(cmd.OutOrStdout())
			if isServeRunningLocal() {
				printNextStep(cmd.OutOrStdout(), "rampart status")
			} else {
				printNextStep(cmd.OutOrStdout(), "rampart serve")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing Rampart hook config")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove Rampart hooks from Claude Code settings")
	return cmd
}

func removeClaudeCodeHooks(cmd *cobra.Command) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("setup: resolve home: %w", err)
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(cmd.OutOrStdout(), "No Claude Code settings found. Nothing to remove.")
			return nil
		}
		return fmt.Errorf("setup: read settings: %w", err)
	}

	settings := make(claudeSettings)
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("setup: parse settings: %w", err)
	}

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		fmt.Fprintln(cmd.OutOrStdout(), "No hooks found in Claude Code settings. Nothing to remove.")
		return nil
	}

	var removedCount int

	// Remove from PreToolUse
	if preToolUse, ok := hooks["PreToolUse"].([]any); ok {
		var kept []any
		for _, h := range preToolUse {
			if m, ok := h.(map[string]any); ok && hasRampartInMatcher(m) {
				removedCount++
				matcher, _ := m["matcher"].(string)
				fmt.Fprintf(cmd.OutOrStdout(), "  Removed PreToolUse hook: matcher=%s\n", matcher)
				continue
			}
			kept = append(kept, h)
		}
		if len(kept) == 0 {
			delete(hooks, "PreToolUse")
		} else {
			hooks["PreToolUse"] = kept
		}
	}

	// Remove from PostToolUseFailure
	if postToolUseFailure, ok := hooks["PostToolUseFailure"].([]any); ok {
		var kept []any
		for _, h := range postToolUseFailure {
			if m, ok := h.(map[string]any); ok && hasRampartInMatcher(m) {
				removedCount++
				matcher, _ := m["matcher"].(string)
				fmt.Fprintf(cmd.OutOrStdout(), "  Removed PostToolUseFailure hook: matcher=%s\n", matcher)
				continue
			}
			kept = append(kept, h)
		}
		if len(kept) == 0 {
			delete(hooks, "PostToolUseFailure")
		} else {
			hooks["PostToolUseFailure"] = kept
		}
	}

	if removedCount == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No Rampart hooks found in Claude Code settings. Nothing to remove.")
		return nil
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("setup: marshal settings: %w", err)
	}
	out = append(out, '\n')

	if err := os.WriteFile(settingsPath, out, 0o644); err != nil {
		return fmt.Errorf("setup: write settings: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "✓ Removed %d Rampart hook(s) from %s\n", removedCount, settingsPath)
	return nil
}

// newSetupClineCmd is defined in cline.go

func newSetupOpenClawCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var remove bool
	var port int
	var patchTools bool
	var patchToolsOnly bool
	var noPreload bool
	var shimOnly bool
	var plugin bool
	var migrate bool

	cmd := &cobra.Command{
		Use:   "openclaw",
		Short: "Set up Rampart to protect an OpenClaw agent",
		Long: `Protects OpenClaw with Rampart.

Default behavior on current OpenClaw builds (>= 2026.3.28):
  - Installs the native Rampart plugin via "openclaw plugins install"
  - Ensures rampart serve is available for policy evaluation and approvals
  - Adds rampart to plugins.allow and installs the OpenClaw policy profile
  - Preserves OpenClaw's native approval UI while Rampart evaluates policy

Legacy compatibility options still exist for older OpenClaw setups:
  - --shim-only uses the legacy shell shim path
  - --no-preload / --patch-tools keep the older bridge and dist-patching flow

Use --remove to uninstall (preserves policies and audit logs).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if plugin {
				return runSetupOpenClawPlugin(cmd.OutOrStdout(), cmd.ErrOrStderr())
			}
			if migrate {
				return runSetupOpenClawMigrate(cmd.OutOrStdout(), cmd.ErrOrStderr())
			}
			if remove {
				return removeOpenClaw(cmd)
			}
			// Auto-detect: if OpenClaw >= 2026.3.28 is installed and --plugin/--migrate
			// weren't explicitly requested, use the native plugin path automatically.
			// Skip in test environments (RAMPART_TEST=1) to avoid running openclaw binary.
			if !patchTools && !patchToolsOnly && !shimOnly && !noPreload && os.Getenv("RAMPART_TEST") != "1" {
				if ver, err := detectOpenClawVersion(); err == nil {
					if ok, _ := openclawVersionAtLeast(ver, openclawMinVersion); ok {
						fmt.Fprintf(cmd.OutOrStdout(), "✓ OpenClaw %s detected — using native plugin integration\n", ver)
						return runSetupOpenClawPlugin(cmd.OutOrStdout(), cmd.ErrOrStderr())
					}
				}
			}
			// --patch-tools-only: used by ExecStartPre to re-patch file tools
			// without writing drop-ins or starting services (avoids systemd deadlock).
			if patchToolsOnly {
				url := fmt.Sprintf("http://127.0.0.1:%d", port)
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				tokenPath := filepath.Join(home, ".rampart", "token")
				token := ""
				if data, err := os.ReadFile(tokenPath); err == nil {
					token = strings.TrimSpace(string(data))
				}
				return patchOpenClawTools(cmd, url, token)
			}
			if runtime.GOOS == "windows" {
				return fmt.Errorf("setup openclaw: not supported on Windows")
			}

			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup: resolve home: %w", err)
			}

			out := cmd.OutOrStdout()
			errOut := cmd.ErrOrStderr()

			// Check for existing configuration
			dropinDir := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d")
			dropinPath := filepath.Join(dropinDir, "rampart.conf")
			shimPath := filepath.Join(home, ".local", "bin", "rampart-shim")
			alreadyConfigured := false
			if _, err := os.Stat(dropinPath); err == nil {
				alreadyConfigured = true
			}
			if _, err := os.Stat(shimPath); err == nil {
				alreadyConfigured = true
			}
			// macOS: check if OpenClaw plist is already patched
			if runtime.GOOS == "darwin" {
				for _, plistName := range []string{"com.openclaw.gateway.plist", "openclaw-gateway.plist"} {
					plistPath := filepath.Join(home, "Library", "LaunchAgents", plistName)
					if data, err := os.ReadFile(plistPath); err == nil && strings.Contains(string(data), "RAMPART_URL") {
						alreadyConfigured = true
						break
					}
				}
			}
			if alreadyConfigured && !force {
				fmt.Fprintln(out, "✓ Already configured (pass --force to reconfigure)")
				return nil
			}

			// Detect real shell
			realShell := os.Getenv("SHELL")
			if realShell == "" || strings.Contains(realShell, "rampart") {
				realShell = "/bin/bash"
			}

			// Read or generate token
			tokenPath := filepath.Join(home, ".rampart", "token")
			var token string
			if info, err := os.Stat(tokenPath); err == nil {
				if perm := info.Mode().Perm(); perm&0o077 != 0 {
					fmt.Fprintf(errOut, "⚠ %s has insecure permissions (%04o) — should be 0600\n", tokenPath, perm)
				}
				if data, err := os.ReadFile(tokenPath); err == nil && len(data) > 0 {
					token = strings.TrimSpace(string(data))
				}
			}
			if token == "" {
				tokenBytes := make([]byte, 24)
				if _, err := rand.Read(tokenBytes); err != nil {
					return fmt.Errorf("setup: generate token: %w", err)
				}
				token = "rampart_" + hex.EncodeToString(tokenBytes)
			}

			// Ensure directories
			dirs := []string{
				filepath.Join(home, ".rampart", "audit"),
				filepath.Join(home, ".rampart", "policies"),
				filepath.Join(home, ".local", "bin"),
			}
			for _, d := range dirs {
				if err := os.MkdirAll(d, 0o700); err != nil {
					return fmt.Errorf("setup: create dir %s: %w", d, err)
				}
			}

			// Copy default policy if none exists
			policyPath := filepath.Join(home, ".rampart", "policies", "standard.yaml")
			if _, err := os.Stat(policyPath); os.IsNotExist(err) {
				if err := os.WriteFile(policyPath, []byte(defaultPolicyContent()), 0o600); err != nil {
					return fmt.Errorf("setup: write default policy: %w", err)
				}
				fmt.Fprintf(out, "✓ Default policy written to %s\n", policyPath)
			}

			// Create user-overrides.yaml if it doesn't exist.
			// This file holds allow-always rules and is never overwritten by upgrades.
			overridesPath := filepath.Join(home, ".rampart", "policies", "user-overrides.yaml")
			if _, err := os.Stat(overridesPath); os.IsNotExist(err) {
				header := "# Rampart user override policies\n# Allow-always rules are written here automatically.\n# This file is never overwritten by upgrades or rampart setup.\npolicies:\n"
				if err := os.WriteFile(overridesPath, []byte(header), 0o600); err != nil {
					return fmt.Errorf("setup: write user-overrides policy: %w", err)
				}
			}

			// Find rampart binary path
			rampartBin, err := os.Executable()
			if err != nil {
				rampartBin = "rampart"
				if p, e := execLookPath("rampart"); e == nil {
					rampartBin = p
				}
			}
			// Resolve symlinks so path survives PATH changes
			if resolved, err := filepath.EvalSymlinks(rampartBin); err == nil {
				rampartBin = resolved
			}

			// Create Rampart proxy service (rampart serve)
			if err := installService(cmd, home, rampartBin, policyPath, token, port); err != nil {
				return err
			}

			// ── Preload enforcement (default) ──
			// Detect OpenClaw service and install LD_PRELOAD drop-in
			preloadInstalled := false
			if !shimOnly {
				preloadInstalled, err = installOpenClawPreload(cmd, home, rampartBin, token, port, noPreload, force)
				if err != nil {
					fmt.Fprintf(errOut, "⚠ LD_PRELOAD not available — falling back to shell shim.\n")
					fmt.Fprintf(errOut, "  Sub-agents (Codex, Claude Code) will NOT be intercepted.\n")
					fmt.Fprintf(errOut, "  Reason: %v\n", err)
				}
			}

			// ── Shell shim (fallback or --shim-only) ──
			if !preloadInstalled || shimOnly {
				shimContent := generateShimContent(realShell, port, token)
				if err := os.WriteFile(shimPath, []byte(shimContent), 0o700); err != nil {
					return fmt.Errorf("setup: write shim: %w", err)
				}
				fmt.Fprintf(out, "✓ Shell shim installed at %s\n", shimPath)
			}

			// Start service (OS-specific)
			if err := startService(cmd); err != nil {
				fmt.Fprintf(errOut, "⚠ Could not start service: %v\n", err)
			} else {
				fmt.Fprintln(out, "✓ Rampart proxy service started")
			}

			// Patch file tools immediately (also runs on every restart via ExecStartPre)
			if patchTools || preloadInstalled {
				if err := patchOpenClawTools(cmd, fmt.Sprintf("http://127.0.0.1:%d", port), token); err != nil {
					fmt.Fprintf(errOut, "⚠ Could not patch file tools: %v\n", err)
					fmt.Fprintln(errOut, "  File tools will be patched on next OpenClaw restart.")
				}
			}

			// Print coverage summary
			fmt.Fprintln(out, "")
			if preloadInstalled {
				fmt.Fprintln(out, "Coverage:")
				fmt.Fprintln(out, "  [P] Shell commands (OpenClaw + all sub-agents)  — LD_PRELOAD")
				if openclawDistPatched() {
					fmt.Fprintln(out, "  [P] File operations (read/write/edit/grep)       — dist patched")
				} else if patchTools && openclawToolsPatched() {
					fmt.Fprintln(out, "  [P] File operations (read/write/edit/grep)       — patched")
				} else if patchTools {
					fmt.Fprintln(out, "  [!] File operations (read/write/edit/grep)       — patch failed (check warnings above)")
				} else {
					fmt.Fprintln(out, "  [ ] File operations (read/write/edit/grep)       — use --patch-tools")
				}
				if openclawWebFetchPatched() {
				fmt.Fprintln(out, "  [P] Network fetch (web_fetch)                    — dist patched")
			} else {
				fmt.Fprintln(out, "  [ ] Network fetch (web_fetch tool)               — use --patch-tools")
			}
			if openclawBrowserPatched() {
				fmt.Fprintln(out, "  [P] Browser automation (browser)                 — dist patched")
			} else {
				fmt.Fprintln(out, "  [ ] Browser automation (browser tool)            — use --patch-tools")
			}
			if openclawMessagePatched() {
				fmt.Fprintln(out, "  [P] Outbound messaging (message)                 — dist patched")
			} else {
				fmt.Fprintln(out, "  [ ] Outbound messaging (message tool)            — use --patch-tools")
			}
				fmt.Fprintln(out, "")
				fmt.Fprintln(out, "Restart the OpenClaw gateway to activate:")
				fmt.Fprintln(out, "  systemctl --user restart openclaw-gateway.service")
			} else {
				fmt.Fprintln(out, "Next steps:")
				fmt.Fprintf(out, "  1. Set SHELL=%s in your OpenClaw gateway config\n", shimPath)
				fmt.Fprintln(out, "  2. Restart the OpenClaw gateway")
				fmt.Fprintln(out, "  3. Every command will now go through Rampart's policy engine")
				if !patchTools {
					fmt.Fprintln(out, "")
					fmt.Fprintln(out, "  Optional: Run with --patch-tools to also protect file reads/writes/edits.")
				}
			}
			fmt.Fprintln(out, "")
			fmt.Fprintf(out, "Policy: %s\n", policyPath)
			fmt.Fprintf(out, "Audit:  %s\n", filepath.Join(home, ".rampart", "audit"))
			fmt.Fprintf(out, "Watch:  rampart watch\n")
			if !hasInstalledPolicy() {
				fmt.Fprintln(out, "")
				fmt.Fprintln(out, "💡 No policy installed yet. For OpenClaw, the openclaw profile is recommended:")
				fmt.Fprintln(out, "   rampart init --profile openclaw")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing configuration")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove Rampart integration (preserves policies and audit logs)")
	cmd.Flags().BoolVar(&patchTools, "patch-tools", false, "Patch file tools even in shim-only mode")
	cmd.Flags().BoolVar(&patchToolsOnly, "patch-tools-only", false, "Only re-patch file tools (used internally by ExecStartPre)")
	_ = cmd.Flags().MarkHidden("patch-tools-only")
	cmd.Flags().BoolVar(&noPreload, "no-preload", false, "Skip LD_PRELOAD but still auto-patch file tools via systemd drop-in")
	cmd.Flags().BoolVar(&shimOnly, "shim-only", false, "Use legacy shell shim only (no systemd drop-in, no sub-agent coverage)")
	cmd.Flags().IntVar(&port, "port", defaultServePort, "Port for Rampart policy server")
	cmd.Flags().BoolVar(&plugin, "plugin", false, "Install the Rampart native OpenClaw plugin (requires OpenClaw >= "+openclawMinVersion+")")
	cmd.Flags().BoolVar(&migrate, "migrate", false, "Migrate from legacy dist-patch/bridge integration to native plugin")
	return cmd
}

// installOpenClawPreload creates a systemd drop-in (Linux) or patches the
// launchd plist (macOS) to wrap the OpenClaw gateway with LD_PRELOAD/DYLD
// syscall interception. Returns true if preload was successfully installed.
func installOpenClawPreload(cmd *cobra.Command, home, rampartBin, token string, port int, noPreload, force bool) (bool, error) {
	out := cmd.OutOrStdout()

	// Resolve the preload library path (only required when preload is enabled)
	var libPath string
	if !noPreload {
		var resolveErr error
		_, libPath, resolveErr = resolvePreloadLibrary()
		if resolveErr != nil {
			return false, fmt.Errorf("librampart not found: %w\n  Install it to ~/.rampart/lib/ or /usr/local/lib/\n  Or use --no-preload to skip LD_PRELOAD and only patch file tools", resolveErr)
		}
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	if runtime.GOOS == "darwin" {
		return installOpenClawPreloadDarwin(cmd, home, rampartBin, libPath, token, url, noPreload, force)
	}

	// ── Linux: systemd drop-in ──
	serviceFile := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service")
	if _, err := os.Stat(serviceFile); os.IsNotExist(err) {
		return false, fmt.Errorf("OpenClaw service not found at %s — is OpenClaw installed as a systemd service?", serviceFile)
	}

	dropinDir := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d")
	if err := os.MkdirAll(dropinDir, 0o700); err != nil {
		return false, fmt.Errorf("create drop-in dir: %w", err)
	}

	// Build drop-in content
	var lines []string
	lines = append(lines, "# Rampart enforcement drop-in — managed by 'rampart setup openclaw'")
	lines = append(lines, "# Survives OpenClaw upgrades (npm install -g openclaw does not touch this file)")
	lines = append(lines, "[Service]")

	// ExecStartPre: re-patch file tools on every restart (survives upgrades).
	// Uses --patch-tools-only to avoid writing drop-ins or starting services
	// during an active systemd unit transition (which could deadlock).
	// The - prefix means failure is non-fatal (OpenClaw still starts).
	lines = append(lines, fmt.Sprintf("ExecStartPre=-\"%s\" setup openclaw --patch-tools-only --port %d", systemdEnvEscape(rampartBin), port))

	if !noPreload {
		// LD_PRELOAD enforcement — hooks execve/execvp/system/popen for all child processes
		lines = append(lines, fmt.Sprintf("Environment=LD_PRELOAD=\"%s\"", systemdEnvEscape(libPath)))
	}

	// Rampart connection env vars (inherited by all child processes via LD_PRELOAD)
	lines = append(lines, fmt.Sprintf("Environment=RAMPART_URL=\"%s\"", systemdEnvEscape(url)))
	lines = append(lines, fmt.Sprintf("Environment=RAMPART_TOKEN=\"%s\"", systemdEnvEscape(token)))
	lines = append(lines, "Environment=RAMPART_MODE=enforce")
	lines = append(lines, "Environment=RAMPART_FAIL_OPEN=1")
	lines = append(lines, "Environment=RAMPART_AGENT=openclaw")
	lines = append(lines, "")

	dropinPath := filepath.Join(dropinDir, "rampart.conf")
	content := strings.Join(lines, "\n")
	if err := os.WriteFile(dropinPath, []byte(content), 0o600); err != nil {
		return false, fmt.Errorf("write drop-in: %w", err)
	}

	if noPreload {
		fmt.Fprintf(out, "✓ Systemd drop-in installed (file tool patching only)\n")
		fmt.Fprintf(out, "  %s\n", dropinPath)
	} else {
		fmt.Fprintf(out, "✓ Systemd drop-in installed (LD_PRELOAD + file tool patching)\n")
		fmt.Fprintf(out, "  %s\n", dropinPath)
		fmt.Fprintf(out, "  Library: %s\n", libPath)
	}

	// Note: daemon-reload is called by startService() which runs after us.
	return true, nil
}

// installOpenClawPreloadDarwin patches the OpenClaw launchd plist to add
// DYLD_INSERT_LIBRARIES for preload enforcement on macOS.
func installOpenClawPreloadDarwin(cmd *cobra.Command, home, rampartBin, libPath, token, url string, noPreload, force bool) (bool, error) {
	out := cmd.OutOrStdout()
	plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.openclaw.gateway.plist")

	// Try alternative names
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		alt := filepath.Join(home, "Library", "LaunchAgents", "openclaw-gateway.plist")
		if _, err := os.Stat(alt); err == nil {
			plistPath = alt
		} else {
			return false, fmt.Errorf("OpenClaw LaunchAgent not found — is OpenClaw installed as a launchd service?")
		}
	}

	content, err := os.ReadFile(plistPath)
	if err != nil {
		return false, fmt.Errorf("read plist: %w", err)
	}

	plistStr := string(content)

	// Check if already patched
	if strings.Contains(plistStr, "RAMPART_URL") && !force {
		fmt.Fprintln(out, "✓ LaunchAgent already patched with Rampart environment")
		return true, nil
	}

	// Build environment dict entries to inject
	var envEntries string
	if !noPreload {
		envEntries += fmt.Sprintf(`        <key>DYLD_INSERT_LIBRARIES</key>
        <string>%s</string>
        <key>DYLD_FORCE_FLAT_NAMESPACE</key>
        <string>1</string>
`, plistXMLEscape(libPath))
	}
	envEntries += fmt.Sprintf(`        <key>RAMPART_URL</key>
        <string>%s</string>
        <key>RAMPART_TOKEN</key>
        <string>%s</string>
        <key>RAMPART_MODE</key>
        <string>enforce</string>
        <key>RAMPART_FAIL_OPEN</key>
        <string>1</string>
        <key>RAMPART_AGENT</key>
        <string>openclaw</string>
`, plistXMLEscape(url), plistXMLEscape(token))

	// Inject into existing EnvironmentVariables dict, or create one
	original := plistStr
	if strings.Contains(plistStr, "<key>EnvironmentVariables</key>") {
		// Insert after the <dict> that follows EnvironmentVariables
		plistStr = strings.Replace(plistStr,
			"<key>EnvironmentVariables</key>\n    <dict>\n",
			"<key>EnvironmentVariables</key>\n    <dict>\n"+envEntries, 1)
	} else {
		// Insert before </dict></plist>
		plistStr = strings.Replace(plistStr,
			"</dict>\n</plist>",
			"    <key>EnvironmentVariables</key>\n    <dict>\n"+envEntries+"    </dict>\n</dict>\n</plist>", 1)
	}

	if plistStr == original {
		return false, fmt.Errorf("could not inject Rampart environment into plist %s — unexpected XML formatting. Patch it manually or use --shim-only", plistPath)
	}

	// Backup original
	backupPath := plistPath + ".rampart-backup"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		_ = os.WriteFile(backupPath, content, 0o600)
	}

	if err := os.WriteFile(plistPath, []byte(plistStr), 0o600); err != nil {
		return false, fmt.Errorf("write plist: %w", err)
	}

	fmt.Fprintf(out, "✓ LaunchAgent patched with Rampart environment\n")
	fmt.Fprintf(out, "  %s\n", plistPath)
	return true, nil
}

// generateShimContent produces the shell shim script for the legacy approach.
func generateShimContent(realShell string, port int, token string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
REAL_SHELL="%s"
RAMPART_URL="http://127.0.0.1:%d"
RAMPART_TOKEN="%s"
RAMPART_MODE="enforce"
APPROVAL_POLL_INTERVAL=3
APPROVAL_TIMEOUT=300

if [ "$1" = "-c" ]; then
    shift
    CMD="$1"
    shift

    if ! command -v curl >/dev/null 2>&1; then
        exec "$REAL_SHELL" -c "$CMD" "$@"
    fi

    ENCODED=$(printf '%%s' "$CMD" | base64 | tr -d '\n\r')
    SESSION="${RAMPART_SESSION:-main}"
    if [ -z "$RAMPART_SESSION" ] && [ -n "$OPENCLAW_SESSION_KIND" ]; then
        SESSION="$OPENCLAW_SESSION_KIND"
    fi

    PAYLOAD=$(printf '{"agent":"openclaw","session":"%%s","params":{"command_b64":"%%s"}}' "$SESSION" "$ENCODED")
    RESP_FILE=$(mktemp /tmp/.rampart-resp.XXXXXX)
    HTTP_CODE=$(curl -sS -o "$RESP_FILE" -w "%%{http_code}" -X POST "${RAMPART_URL}/v1/tool/exec" \
        -H "Authorization: Bearer ${RAMPART_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" 2>/dev/null)
    DECISION=$(cat "$RESP_FILE" 2>/dev/null)
    rm -f "$RESP_FILE"

    if [ -z "$DECISION" ]; then
        exec "$REAL_SHELL" -c "$CMD" "$@"
    fi

    if [ "$RAMPART_MODE" = "enforce" ] && [ "$HTTP_CODE" = "403" ]; then
        MSG=$(printf '%%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="policy denied"; fi
        echo "rampart: blocked — ${MSG}" >&2
        exit 126
    fi

    DENIED=$(printf '%%s' "$DECISION" | sed -n 's/.*"decision":"\(deny\)".*/\1/p' | head -n 1)
    if [ "$RAMPART_MODE" = "enforce" ] && [ "$DENIED" = "deny" ]; then
        MSG=$(printf '%%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="policy denied"; fi
        echo "rampart: blocked — ${MSG}" >&2
        exit 126
    fi

    APPROVAL_ID=$(printf '%%s' "$DECISION" | sed -n 's/.*"approval_id":"\([^"]*\)".*/\1/p' | head -n 1)
    if [ -n "$APPROVAL_ID" ]; then
        MSG=$(printf '%%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="approval required"; fi
        echo "rampart: waiting for approval — ${MSG}" >&2
        echo "rampart: approval id: ${APPROVAL_ID}" >&2

        ELAPSED=0
        while [ "$ELAPSED" -lt "$APPROVAL_TIMEOUT" ]; do
            sleep "$APPROVAL_POLL_INTERVAL"
            ELAPSED=$((ELAPSED + APPROVAL_POLL_INTERVAL))

            POLL_RESP=$(curl -sS "${RAMPART_URL}/v1/approvals/${APPROVAL_ID}" \
                -H "Authorization: Bearer ${RAMPART_TOKEN}" 2>/dev/null)
            STATUS=$(printf '%%s' "$POLL_RESP" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -n 1)

            case "$STATUS" in
                approved)
                    echo "rampart: approved" >&2
                    exec "$REAL_SHELL" -c "$CMD" "$@"
                    ;;
                denied|expired)
                    echo "rampart: ${STATUS}" >&2
                    exit 126
                    ;;
            esac
        done

        echo "rampart: approval timed out after ${APPROVAL_TIMEOUT}s" >&2
        exit 126
    fi

    exec "$REAL_SHELL" -c "$CMD" "$@"
fi

exec "$REAL_SHELL" "$@"
`, realShell, port, token)
}

func removeOpenClaw(cmd *cobra.Command) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("setup openclaw: not supported on Windows")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("setup: resolve home: %w", err)
	}

	var removed []string

	// Stop and disable service
	if runtime.GOOS == "darwin" {
		plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.rampart.proxy.plist")
		if _, err := os.Stat(plistPath); err == nil {
			unload := osexec.Command("launchctl", "unload", plistPath)
			if err := unload.Run(); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Could not unload launchd agent: %v\n", err)
			}
			if err := os.Remove(plistPath); err == nil {
				removed = append(removed, plistPath)
			}
		}

		// Restore patched OpenClaw plist from backup
		for _, plistName := range []string{"com.openclaw.gateway.plist", "openclaw-gateway.plist"} {
			orig := filepath.Join(home, "Library", "LaunchAgents", plistName)
			bak := orig + ".rampart-backup"
			if data, err := os.ReadFile(bak); err == nil {
				if err := os.WriteFile(orig, data, 0o600); err == nil {
					_ = os.Remove(bak)
					removed = append(removed, orig+" (restored)")
				}
			}
		}
	} else {
		stop := osexec.Command("systemctl", "--user", "stop", "rampart-proxy")
		_ = stop.Run()
		disable := osexec.Command("systemctl", "--user", "disable", "rampart-proxy")
		_ = disable.Run()

		servicePath := filepath.Join(home, ".config", "systemd", "user", "rampart-proxy.service")
		if _, err := os.Stat(servicePath); err == nil {
			if err := os.Remove(servicePath); err == nil {
				removed = append(removed, servicePath)
			}
		}

		// Remove preload drop-in
		dropinPath := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d", "rampart.conf")
		if _, err := os.Stat(dropinPath); err == nil {
			if err := os.Remove(dropinPath); err == nil {
				removed = append(removed, dropinPath)
			}
			// Remove dir if empty
			dropinDir := filepath.Dir(dropinPath)
			if entries, err := os.ReadDir(dropinDir); err == nil && len(entries) == 0 {
				_ = os.Remove(dropinDir)
			}
		}

		reload := osexec.Command("systemctl", "--user", "daemon-reload")
		_ = reload.Run()
	}

	// Restore patched file tools
	candidates := openclawToolsCandidates()
	for _, d := range candidates {
		for _, tool := range []string{"read", "write", "edit", "grep"} {
			backup := filepath.Join(d, tool+".js.rampart-backup")
			target := filepath.Join(d, tool+".js")
			if data, err := os.ReadFile(backup); err == nil {
				if err := os.WriteFile(target, data, 0o644); err == nil {
					_ = os.Remove(backup)
					removed = append(removed, target+" (restored)")
				}
			}
		}
	}

	// Remove shell shim
	shimPath := filepath.Join(home, ".local", "bin", "rampart-shim")
	if _, err := os.Stat(shimPath); err == nil {
		if err := os.Remove(shimPath); err == nil {
			removed = append(removed, shimPath)
		}
	}

	if len(removed) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No OpenClaw integration found. Nothing to remove.")
		return nil
	}

	for _, p := range removed {
		fmt.Fprintf(cmd.OutOrStdout(), "  Removed: %s\n", p)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Removed %d file(s). Policies and audit logs were preserved.\n", len(removed))
	return nil
}

func installService(cmd *cobra.Command, home, rampartBin, policyPath, token string, port int) error {
	if runtime.GOOS == "darwin" {
		return installLaunchd(cmd, home, rampartBin, policyPath, token, port)
	}
	return installSystemd(cmd, home, rampartBin, policyPath, token, port)
}

// plistXMLEscape escapes a string for safe embedding inside a plist <string>
// element. Unescaped '<' or '&' in a value would break the XML structure or
// allow a crafted path/token to inject arbitrary plist keys.
func plistXMLEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// systemdEnvEscape strips characters that would break a systemd
// Environment= line (newlines introduce new directives).
func systemdEnvEscape(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func installSystemd(cmd *cobra.Command, home, rampartBin, policyPath, token string, port int) error {
	serviceDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		return fmt.Errorf("setup: create systemd dir: %w", err)
	}
	servicePath := filepath.Join(serviceDir, "rampart-proxy.service")
	serviceContent := fmt.Sprintf(`[Unit]
Description=Rampart Policy Proxy
Before=openclaw-gateway.service

[Service]
ExecStart=%s serve --port %d --config %s
Restart=always
RestartSec=3
Environment=HOME="%s"
Environment=RAMPART_TOKEN="%s"

[Install]
WantedBy=default.target
`, rampartBin, port, policyPath, home, systemdEnvEscape(token))

	// 0o600: unit file contains RAMPART_TOKEN — must not be world-readable.
	// Chmod after write because os.WriteFile only applies the mode on creation.
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0o600); err != nil {
		return fmt.Errorf("setup: write service file: %w", err)
	}
	_ = os.Chmod(servicePath, 0o600)
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Systemd service written to %s\n", servicePath)
	return nil
}

func installLaunchd(cmd *cobra.Command, home, rampartBin, policyPath, token string, port int) error {
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		return fmt.Errorf("setup: create LaunchAgents dir: %w", err)
	}
	plistPath := filepath.Join(agentDir, "com.rampart.proxy.plist")
	logPath := filepath.Join(home, ".rampart", "rampart-proxy.log")
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rampart.proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>serve</string>
        <string>--port</string>
        <string>%d</string>
        <string>--config</string>
        <string>%s</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>%s</string>
        <key>RAMPART_TOKEN</key>
        <string>%s</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
</dict>
</plist>
`,
		plistXMLEscape(rampartBin),
		port,
		plistXMLEscape(policyPath),
		plistXMLEscape(home),
		plistXMLEscape(token),
		plistXMLEscape(logPath),
		plistXMLEscape(logPath),
	)

	// 0o600: plist contains RAMPART_TOKEN — must not be world-readable.
	// Chmod after write because os.WriteFile only applies the mode on creation.
	if err := os.WriteFile(plistPath, []byte(plistContent), 0o600); err != nil {
		return fmt.Errorf("setup: write plist: %w", err)
	}
	_ = os.Chmod(plistPath, 0o600)
	fmt.Fprintf(cmd.OutOrStdout(), "✓ LaunchAgent written to %s\n", plistPath)
	return nil
}

func startService(cmd *cobra.Command) error {
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.rampart.proxy.plist")
		// Unload first in case it's already loaded (ignore errors)
		unload := osexec.Command("launchctl", "unload", plistPath)
		_ = unload.Run()
		load := osexec.Command("launchctl", "load", plistPath)
		load.Stderr = cmd.ErrOrStderr()
		return load.Run()
	}

	reload := osexec.Command("systemctl", "--user", "daemon-reload")
	reload.Stderr = cmd.ErrOrStderr()
	if err := reload.Run(); err != nil {
		return err
	}
	enable := osexec.Command("systemctl", "--user", "enable", "--now", "rampart-proxy")
	enable.Stderr = cmd.ErrOrStderr()
	return enable.Run()
}

func defaultPolicyContent() string {
	b, err := policies.Profile("standard")
	if err != nil {
		panic("embedded standard policy missing: " + err.Error())
	}
	return string(b)
}

// toGitBashPath converts a Windows path to Git Bash compatible format.
// Claude Code on Windows runs hooks through Git Bash (/usr/bin/bash), which
// doesn't understand Windows backslash paths. Without this conversion, paths
// like 'C:\Users\trev\.rampart\bin\rampart.exe' are mangled to
// 'C:Userstrev.rampartbinrampart.exe' causing 'command not found' errors.
//
// Examples:
//   - C:\Users\trev\.rampart\bin\rampart.exe -> /c/Users/trev/.rampart/bin/rampart.exe
//   - D:\Program Files\rampart.exe -> /d/Program Files/rampart.exe
//   - /usr/local/bin/rampart -> /usr/local/bin/rampart (unchanged)
func toGitBashPath(windowsPath string) string {
	if runtime.GOOS != "windows" {
		return windowsPath
	}

	// Already a Unix-style path (starts with / or ./)
	if strings.HasPrefix(windowsPath, "/") || strings.HasPrefix(windowsPath, "./") {
		return windowsPath
	}

	// Check for Windows drive letter pattern (e.g., C:\, D:\)
	if len(windowsPath) >= 3 && windowsPath[1] == ':' && (windowsPath[2] == '\\' || windowsPath[2] == '/') {
		driveLetter := strings.ToLower(string(windowsPath[0]))
		restOfPath := windowsPath[3:]
		// Replace backslashes with forward slashes
		restOfPath = strings.ReplaceAll(restOfPath, "\\", "/")
		return "/" + driveLetter + "/" + restOfPath
	}

	// Just convert backslashes for relative paths
	return strings.ReplaceAll(windowsPath, "\\", "/")
}

func hasRampartHook(settings claudeSettings) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}

	// Check PreToolUse
	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return false
	}
	hasPreToolUse := false
	for _, h := range preToolUse {
		if m, ok := h.(map[string]any); ok {
			if hasRampartInMatcher(m) {
				hasPreToolUse = true
				break
			}
		}
	}
	if !hasPreToolUse {
		return false
	}

	// Also require PostToolUseFailure to be registered; if it's missing,
	// return false so setup re-runs and adds it (dedup handles PreToolUse).
	postToolUseFailure, ok := hooks["PostToolUseFailure"].([]any)
	if !ok {
		return false
	}
	for _, h := range postToolUseFailure {
		if m, ok := h.(map[string]any); ok {
			if hasRampartInMatcher(m) {
				return true
			}
		}
	}
	return false
}

// openclawToolsCandidates returns possible paths for OpenClaw's pi-coding-agent tools directory.
func openclawToolsCandidates() []string {
	home, _ := os.UserHomeDir()
	return []string{
		// User-local install (npm install -g --prefix ~/.local) — check first
		filepath.Join(home, ".local/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools"),
		// System-wide installs
		"/usr/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools",
		"/usr/local/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools",
		filepath.Join(home, ".npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools"),
	}
}

func patchOpenClawTools(cmd *cobra.Command, url, token string) error {
	// Try bundled dist files first (works for modern OpenClaw with webpack/esbuild output).
	if patched, err := patchOpenClawDistTools(cmd, url, token); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ dist patch failed: %v\n", err)
	} else if patched {
		return nil
	}

	// Fall back to patching source files in node_modules.
	candidates := openclawToolsCandidates()

	var toolsDir string
	for _, d := range candidates {
		if _, err := os.Stat(filepath.Join(d, "read.js")); err == nil {
			toolsDir = d
			break
		}
	}
	if toolsDir == "" {
		return fmt.Errorf("could not find OpenClaw's pi-coding-agent tools directory")
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Found tools: %s\n", toolsDir)

	// Check if already patched
	readFile := filepath.Join(toolsDir, "read.js")
	data, err := os.ReadFile(readFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", readFile, err)
	}
	if strings.Contains(string(data), "RAMPART_") {
		fmt.Fprintln(cmd.OutOrStdout(), "✓ File tools already patched")
		return nil
	}

	// Check if we can write to the tools directory before attempting patches.
	// Global npm installs (sudo npm i -g) create root-owned files.
	testFile := filepath.Join(toolsDir, ".rampart-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("cannot patch file tools: %s is not writable (owned by root?)\n"+
				"  Run with sudo:  sudo %s setup openclaw --patch-tools --force\n"+
				"  Or fix ownership: sudo chown -R $(whoami) %s",
				toolsDir, os.Args[0], toolsDir)
		}
		return fmt.Errorf("cannot write to tools directory %s: %w", toolsDir, err)
	}
	defer os.Remove(testFile)

	tokenExpr := `process.env.RAMPART_TOKEN`
	if token != "" {
		tokenExpr = fmt.Sprintf(`process.env.RAMPART_TOKEN || "%s"`, token)
	}

	type toolPatch struct {
		name      string
		endpoint  string
		origStart string
		nextLine  string
		paramVar  string // variable name containing path
	}

	patches := []toolPatch{
		{
			name:      "read",
			endpoint:  "/v1/tool/read",
			origStart: `execute: async (_toolCallId, { path, offset, limit }, signal) => {`,
			nextLine:  `const absolutePath = resolveReadPath(path, cwd);`,
			paramVar:  "path",
		},
		{
			name:      "write",
			endpoint:  "/v1/tool/write",
			origStart: `execute: async (_toolCallId, { path, content }, signal) => {`,
			nextLine:  `const absolutePath = resolveToCwd(path, cwd);`,
			paramVar:  "path",
		},
		{
			name:      "edit",
			endpoint:  "/v1/tool/edit",
			origStart: `execute: async (_toolCallId, { path, oldText, newText }, signal) => {`,
			nextLine:  `const absolutePath = resolveToCwd(path, cwd);`,
			paramVar:  "path",
		},
	}

	for _, p := range patches {
		file := filepath.Join(toolsDir, p.name+".js")
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s.js: %v\n", p.name, err)
			continue
		}

		// Backup
		backupPath := file + ".rampart-backup"
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, content, 0o600); err != nil {
				return fmt.Errorf("backup %s: %w", file, err)
			}
		}

		orig := p.origStart + "\n            " + p.nextLine
		check := fmt.Sprintf(`%s
            /* RAMPART_%s_CHECK */ try {
                const __rr = await fetch((process.env.RAMPART_URL || "%s") + "%s", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
                    body: JSON.stringify({ agent: "openclaw", session: "main", params: { %s } }),
                    signal: AbortSignal.timeout(3000)
                });
                if (__rr.status === 403) {
                    const __rd = await __rr.json().catch(() => ({}));
                    return { content: [{ type: "text", text: "rampart: " + (__rd.message || "policy denied") }] };
                }
            } catch (__re) { /* fail-open */ }
            %s`, p.origStart, strings.ToUpper(p.name), url, p.endpoint, tokenExpr, p.paramVar, p.nextLine)

		newContent := strings.Replace(string(content), orig, check, 1)
		if newContent == string(content) {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s.js: injection point not found (version mismatch?)\n", p.name)
			continue
		}

		if err := os.WriteFile(file, []byte(newContent), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", file, err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s.js patched\n", p.name)
	}

	// Grep has a different signature
	grepFile := filepath.Join(toolsDir, "grep.js")
	if grepContent, err := os.ReadFile(grepFile); err == nil {
		backupPath := grepFile + ".rampart-backup"
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, grepContent, 0o600); err != nil {
				return fmt.Errorf("backup %s: %w", grepFile, err)
			}
		}

		grepOrig := `execute: async (_toolCallId, { pattern, path: searchDir, glob, ignoreCase, literal, context, limit, }, signal) => {
            return new Promise((resolve, reject) => {`

		grepCheck := fmt.Sprintf(`execute: async (_toolCallId, { pattern, path: searchDir, glob, ignoreCase, literal, context, limit, }, signal) => {
            /* RAMPART_GREP_CHECK */ try {
                const __gp = searchDir || ".";
                const __rr = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/grep", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
                    body: JSON.stringify({ agent: "openclaw", session: "main", params: { path: __gp, pattern } }),
                    signal: AbortSignal.timeout(3000)
                });
                if (__rr.status === 403) {
                    const __rd = await __rr.json().catch(() => ({}));
                    return { content: [{ type: "text", text: "rampart: " + (__rd.message || "policy denied") }] };
                }
            } catch (__re) { /* fail-open */ }
            return new Promise((resolve, reject) => {`, url, tokenExpr)

		newGrep := strings.Replace(string(grepContent), grepOrig, grepCheck, 1)
		if newGrep != string(grepContent) {
			if err := os.WriteFile(grepFile, []byte(newGrep), 0o644); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ grep.js: write failed: %v\n", err)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "  ✓ grep.js patched\n")
			}
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ grep.js: injection point not found (skipping)\n")
		}
	}

	fmt.Fprintln(cmd.OutOrStdout(), "")
	fmt.Fprintln(cmd.OutOrStdout(), "⚠ File tool patches modify node_modules — re-run after OpenClaw upgrades.")
	return nil
}

// openclawDistCandidates returns candidate directories for OpenClaw's bundled dist files.
func openclawDistCandidates() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, ".local", "lib", "node_modules", "openclaw", "dist"),
		"/usr/lib/node_modules/openclaw/dist",
		"/usr/local/lib/node_modules/openclaw/dist",
		filepath.Join(home, ".npm-global", "lib", "node_modules", "openclaw", "dist"),
		filepath.Join(home, "node_modules", "openclaw", "dist"),
	}
}

// patchOpenClawDistTools patches OpenClaw's bundled dist files (pi-embedded-*.js)
// to inject Rampart policy checks into the tool execution wrappers.
// Returns (true, nil) if dist files were found and patched.
func patchOpenClawDistTools(cmd *cobra.Command, url, token string) (bool, error) {
	var distDir string
	for _, d := range openclawDistCandidates() {
		// Accept dist dir if it has pi-embedded-*.js OR auth-profiles-*.js (newer OpenClaw)
		piMatches, _ := filepath.Glob(filepath.Join(d, "pi-embedded-*.js"))
		authMatches, _ := filepath.Glob(filepath.Join(d, "auth-profiles-*.js"))
		if len(piMatches) > 0 || len(authMatches) > 0 {
			distDir = d
			break
		}
	}
	if distDir == "" {
		return false, nil
	}

	// Check write permissions
	testFile := filepath.Join(distDir, ".rampart-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		if os.IsPermission(err) {
			return false, fmt.Errorf("cannot patch dist files: %s is not writable (owned by root?)\n"+
				"  Run with sudo:  sudo %s setup openclaw --patch-tools --force\n"+
				"  Or fix ownership: sudo chown -R $(whoami) %s",
				distDir, os.Args[0], distDir)
		}
		return false, fmt.Errorf("cannot write to dist directory: %w", err)
	}
	defer os.Remove(testFile)

	tokenExpr := `process.env.RAMPART_TOKEN`
	if token != "" {
		tokenExpr = fmt.Sprintf(`process.env.RAMPART_TOKEN || "%s"`, token)
	}

	matches, _ := filepath.Glob(filepath.Join(distDir, "pi-embedded-*.js"))
	patched := 0

	for _, file := range matches {
		// Skip helper files — only patch main bundles that contain tool wrappers
		if strings.Contains(filepath.Base(file), "helpers") {
			continue
		}

		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		text := string(content)

		// Skip files that don't contain the tool wrappers we need to patch
		if !strings.Contains(text, "createOpenClawReadTool") && !strings.Contains(text, "wrapToolParamNormalization") {
			continue
		}

		// Skip already-patched files
		if strings.Contains(text, "RAMPART_DIST_CHECK") {
			fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s already patched\n", filepath.Base(file))
			patched++
			continue
		}

		modified := text

		// Patch read tool: inject before executeReadWithAdaptivePaging
		readOrig := `const result = await executeReadWithAdaptivePaging({`
		readCheck := fmt.Sprintf(`/* RAMPART_DIST_CHECK_READ */ try {
				const __rp = typeof record?.path === "string" ? String(record.path) : "";
				const __rr = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/read", {
					method: "POST",
					headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
					body: JSON.stringify({ agent: "openclaw", session: "main", params: { path: __rp } }),
					signal: AbortSignal.timeout(3000)
				});
				if (__rr.status === 403) {
					const __rd = await __rr.json().catch(() => ({}));
					return { content: [{ type: "text", text: "rampart: " + (__rd.message || "policy denied") }] };
				}
			} catch (__re) { /* fail-open */ }
			const result = await executeReadWithAdaptivePaging({`, url, tokenExpr)

		modified = strings.Replace(modified, readOrig, readCheck, 1)

		// Patch write/edit tools: inject before tool.execute in wrapToolParamNormalization
		wrapOrig := `return tool.execute(toolCallId, normalized`
		wrapCheck := fmt.Sprintf(`/* RAMPART_DIST_CHECK_WRITE */ try {
				const __wp = record?.path || record?.file_path || "";
				const __wt = tool.name === "Edit" ? "edit" : "write";
				const __wr = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/" + __wt, {
					method: "POST",
					headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
					body: JSON.stringify({ agent: "openclaw", session: "main", params: { path: __wp } }),
					signal: AbortSignal.timeout(3000)
				});
				if (__wr.status === 403) {
					const __wd = await __wr.json().catch(() => ({}));
					return { content: [{ type: "text", text: "rampart: " + (__wd.message || "policy denied") }] };
				}
			} catch (__we) { /* fail-open */ }
			return tool.execute(toolCallId, normalized`, url, tokenExpr)

		modified = strings.Replace(modified, wrapOrig, wrapCheck, 1)

		if modified == text {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: injection points not found (version mismatch?)\n", filepath.Base(file))
			continue
		}

		// Backup original
		backupPath := file + ".rampart-backup"
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, content, 0o644); err != nil {
				return false, fmt.Errorf("backup %s: %w", filepath.Base(file), err)
			}
		}

		if err := os.WriteFile(file, []byte(modified), 0o644); err != nil {
			return false, fmt.Errorf("write %s: %w", filepath.Base(file), err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s patched (read + write/edit)\n", filepath.Base(file))
		patched++
	}

	// Patch web_fetch, browser, message, and exec tools in dist files
	webFetchPatched := patchWebFetchInDist(cmd, distDir, url, tokenExpr)
	browserPatched := patchBrowserInDist(cmd, distDir, url, tokenExpr)
	messagePatched := patchMessageInDist(cmd, distDir, url, tokenExpr)
	execPatched := patchExecInDist(cmd, distDir, url, tokenExpr)

	if patched == 0 && !webFetchPatched && !browserPatched && !messagePatched && !execPatched {
		return false, nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), "")
	fmt.Fprintln(cmd.OutOrStdout(), "⚠ Dist file patches are overwritten by OpenClaw upgrades — re-run after updates.")
	return true, nil
}

// patchWebFetchInDist scans all *.js files in distDir for the web_fetch execute
// handler and injects a Rampart preflight check. Returns true if any file was patched.
func patchWebFetchInDist(cmd *cobra.Command, distDir, url, tokenExpr string) bool {
	allJS, _ := filepath.Glob(filepath.Join(distDir, "*.js"))
	patched := false

	for _, file := range allJS {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		text := string(content)

		// Skip files without web_fetch handler — check both old and new bundle patterns
		hasWebFetch := strings.Contains(text, `const url = readStringParam(params, "url", { required: true`) ||
			strings.Contains(text, `const url = readStringParam$1(rawParams, "url", { required: true`)
		if !hasWebFetch {
			continue
		}

		// Skip already-patched files
		if strings.Contains(text, "RAMPART_DIST_CHECK_WEBFETCH") {
			fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s web_fetch already patched\n", filepath.Base(file))
			patched = true
			continue
		}

		// Try both old and new bundle patterns (OpenClaw 2026.3.x renamed readStringParam → readStringParam$1)
		webFetchOrig := `const url = readStringParam(params, "url", { required: true });`
		if !strings.Contains(text, webFetchOrig) {
			webFetchOrig = `const url = readStringParam$1(rawParams, "url", { required: true });`
		}
		webFetchCheck := fmt.Sprintf(`const url = readStringParam(params, "url", { required: true });
        /* RAMPART_DIST_CHECK_WEBFETCH */ try {
            const __wfu = typeof url === "string" ? url : "";
            const __wfr = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/web_fetch", {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
                body: JSON.stringify({ agent: "openclaw", session: "main", params: { url: __wfu } }),
                signal: AbortSignal.timeout(3000)
            });
            if (__wfr.status === 403) {
                const __wfd = await __wfr.json().catch(() => ({}));
                return { content: [{ type: "text", text: "rampart: " + (__wfd.message || "policy denied") }] };
            }
        } catch (__wfe) { /* fail-open */ }`, url, tokenExpr)

		modified := strings.Replace(text, webFetchOrig, webFetchCheck, 1)
		if modified == text {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: web_fetch injection point not found (skipping)\n", filepath.Base(file))
			continue
		}

		// Backup original (if not already backed up by pi-embedded patch)
		backupPath := file + ".rampart-backup"
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, content, 0o644); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: backup failed: %v\n", filepath.Base(file), err)
				continue
			}
		}

		if err := os.WriteFile(file, []byte(modified), 0o644); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: write failed: %v\n", filepath.Base(file), err)
			continue
		}

		fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s patched (web_fetch)\n", filepath.Base(file))
		patched = true
	}

	return patched
}

// patchBrowserInDist patches OpenClaw's browser tool to intercept navigate and open
// actions and check URLs against Rampart policy. Closes #220.
func patchBrowserInDist(cmd *cobra.Command, distDir, url, tokenExpr string) bool {
	allJS, _ := filepath.Glob(filepath.Join(distDir, "*.js"))
	patched := false

	for _, file := range allJS {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		text := string(content)

		if !strings.Contains(text, `case "navigate": {`) {
			continue
		}
		if strings.Contains(text, "RAMPART_DIST_CHECK_BROWSER") {
			fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s browser already patched\n", filepath.Base(file))
			patched = true
			continue
		}

		navigateOrig := `case "navigate": {
					const targetUrl = readTargetUrlParam(params);`
		navigateCheck := fmt.Sprintf(`case "navigate": {
					const targetUrl = readTargetUrlParam(params);
					/* RAMPART_DIST_CHECK_BROWSER_NAVIGATE */ try {
						const __bnu = typeof targetUrl === "string" ? targetUrl : "";
						const __bnr = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/browser", {
							method: "POST",
							headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
							body: JSON.stringify({ agent: "openclaw", session: "main", params: { action: "navigate", url: __bnu } }),
							signal: AbortSignal.timeout(3000)
						});
						if (__bnr.status === 403) {
							const __bnd = await __bnr.json().catch(() => ({}));
							return { content: [{ type: "text", text: "rampart: " + (__bnd.message || "policy denied") }] };
						}
					} catch (__bne) { /* fail-open */ }`, url, tokenExpr)

		openOrig := `case "open": {
					const targetUrl = readTargetUrlParam(params);`
		openCheck := fmt.Sprintf(`case "open": {
					const targetUrl = readTargetUrlParam(params);
					/* RAMPART_DIST_CHECK_BROWSER_OPEN */ try {
						const __bou = typeof targetUrl === "string" ? targetUrl : "";
						const __bor = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/browser", {
							method: "POST",
							headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
							body: JSON.stringify({ agent: "openclaw", session: "main", params: { action: "open", url: __bou } }),
							signal: AbortSignal.timeout(3000)
						});
						if (__bor.status === 403) {
							const __bod = await __bor.json().catch(() => ({}));
							return { content: [{ type: "text", text: "rampart: " + (__bod.message || "policy denied") }] };
						}
					} catch (__boe) { /* fail-open */ }`, url, tokenExpr)

		modified := strings.Replace(text, navigateOrig, navigateCheck, 1)
		modified = strings.Replace(modified, openOrig, openCheck, 1)
		if modified == text {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: browser injection point not found (skipping)\n", filepath.Base(file))
			continue
		}

		backupPath := file + ".rampart-backup"
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, content, 0o644); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: backup failed: %v\n", filepath.Base(file), err)
				continue
			}
		}

		if err := os.WriteFile(file, []byte(modified), 0o644); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: write failed: %v\n", filepath.Base(file), err)
			continue
		}

		fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s patched (browser navigate+open)\n", filepath.Base(file))
		patched = true
	}

	return patched
}

// patchMessageInDist patches OpenClaw's message tool to intercept outbound sends
// and check them against Rampart policy. Closes #221.
func patchMessageInDist(cmd *cobra.Command, distDir, url, tokenExpr string) bool {
	allJS, _ := filepath.Glob(filepath.Join(distDir, "*.js"))
	patched := false

	for _, file := range allJS {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		text := string(content)

		if !strings.Contains(text, "runMessageAction({") {
			continue
		}
		if strings.Contains(text, "RAMPART_DIST_CHECK_MESSAGE") {
			fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s message already patched\n", filepath.Base(file))
			patched = true
			continue
		}

		// Try both old and new dist bundle patterns for runMessageAction.
		// OpenClaw 2026.3.x changed from `const result = await runMessageAction({`
		// to `= async () => await runMessageAction({`.
		messagePatterns := []struct{ orig, replacement string }{
			{
				orig: `const result = await runMessageAction({`,
				replacement: fmt.Sprintf(`/* RAMPART_DIST_CHECK_MESSAGE */ try {
				const __maa = typeof params.action === "string" ? params.action : "send";
				const __mat = typeof params.target === "string" ? params.target : (typeof params.to === "string" ? params.to : (typeof params.channelId === "string" ? params.channelId : ""));
				const __mac = typeof params.message === "string" ? params.message : (typeof params.text === "string" ? params.text : (typeof params.content === "string" ? params.content : ""));
				const __mar = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/message", {
					method: "POST",
					headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
					body: JSON.stringify({ agent: "openclaw", session: "main", params: { action: __maa, target: __mat, message: __mac } }),
					signal: AbortSignal.timeout(3000)
				});
				if (__mar.status === 403) {
					const __mad = await __mar.json().catch(() => ({}));
					return { content: [{ type: "text", text: "rampart: " + (__mad.message || "policy denied") }] };
				}
			} catch (__mae) { /* fail-open */ }
			const result = await runMessageAction({`, url, tokenExpr),
			},
			{
				orig: `= async () => await runMessageAction({`,
				replacement: fmt.Sprintf(`= async () => { /* RAMPART_DIST_CHECK_MESSAGE */ try {
				const __maa = typeof params.action === "string" ? params.action : "send";
				const __mat = typeof params.target === "string" ? params.target : (typeof params.to === "string" ? params.to : (typeof params.channelId === "string" ? params.channelId : ""));
				const __mac = typeof params.message === "string" ? params.message : (typeof params.text === "string" ? params.text : (typeof params.content === "string" ? params.content : ""));
				const __mar = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/message", {
					method: "POST",
					headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
					body: JSON.stringify({ agent: "openclaw", session: "main", params: { action: __maa, target: __mat, message: __mac } }),
					signal: AbortSignal.timeout(3000)
				});
				if (__mar.status === 403) {
					const __mad = await __mar.json().catch(() => ({}));
					return { content: [{ type: "text", text: "rampart: " + (__mad.message || "policy denied") }] };
				}
			} catch (__mae) { /* fail-open */ } return await runMessageAction({`, url, tokenExpr),
			},
			{
				orig: `const sendResult = await runMessageAction({`,
				replacement: fmt.Sprintf(`/* RAMPART_DIST_CHECK_MESSAGE */ try {
				const __maa = typeof params.action === "string" ? params.action : "send";
				const __mat = typeof params.target === "string" ? params.target : (typeof params.to === "string" ? params.to : (typeof params.channelId === "string" ? params.channelId : ""));
				const __mac = typeof params.message === "string" ? params.message : (typeof params.text === "string" ? params.text : (typeof params.content === "string" ? params.content : ""));
				const __mar = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/message", {
					method: "POST",
					headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
					body: JSON.stringify({ agent: "openclaw", session: "main", params: { action: __maa, target: __mat, message: __mac } }),
					signal: AbortSignal.timeout(3000)
				});
				if (__mar.status === 403) {
					const __mad = await __mar.json().catch(() => ({}));
					return { content: [{ type: "text", text: "rampart: " + (__mad.message || "policy denied") }] };
				}
			} catch (__mae) { /* fail-open */ }
			const sendResult = await runMessageAction({`, url, tokenExpr),
			},
			{
				orig: "const { runMessageAction } = await loadMessageActionRuntime();\n\t\t\tawait runMessageAction({",
				replacement: "const { runMessageAction } = await loadMessageActionRuntime();\n\t\t\t" + fmt.Sprintf(`/* RAMPART_DIST_CHECK_MESSAGE */ try {
				const __maa = typeof params.action === "string" ? params.action : "send";
				const __mat = typeof params.target === "string" ? params.target : (typeof params.to === "string" ? params.to : (typeof params.channelId === "string" ? params.channelId : ""));
				const __mac = typeof params.message === "string" ? params.message : (typeof params.text === "string" ? params.text : (typeof params.content === "string" ? params.content : ""));
				const __mar = await fetch((process.env.RAMPART_URL || "%s") + "/v1/tool/message", {
					method: "POST",
					headers: { "Content-Type": "application/json", "Authorization": "Bearer " + (%s) },
					body: JSON.stringify({ agent: "openclaw", session: "main", params: { action: __maa, target: __mat, message: __mac } }),
					signal: AbortSignal.timeout(3000)
				});
				if (__mar.status === 403) {
					const __mad = await __mar.json().catch(() => ({}));
					return { content: [{ type: "text", text: "rampart: " + (__mad.message || "policy denied") }] };
				}
			} catch (__mae) { /* fail-open */ }
			await runMessageAction({`, url, tokenExpr),
			},
		}

		modified := text
		injected := false
		for _, mp := range messagePatterns {
			if strings.Contains(modified, mp.orig) {
				modified = strings.Replace(modified, mp.orig, mp.replacement, 1)
				injected = true
				break
			}
		}
		if !injected {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: message injection point not found (skipping)\n", filepath.Base(file))
			continue
		}

		backupPath := file + ".rampart-backup"
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, content, 0o644); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: backup failed: %v\n", filepath.Base(file), err)
				continue
			}
		}

		if err := os.WriteFile(file, []byte(modified), 0o644); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠ %s: write failed: %v\n", filepath.Base(file), err)
			continue
		}

		fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s patched (message send)\n", filepath.Base(file))
		patched = true
	}

	return patched
}

// patchExecInDist previously short-circuited OpenClaw's native exec approval
// manager by calling Rampart's /v1/tool/exec directly from processGatewayAllowlist.
//
// That design worked before native Discord approvals became the primary UX, but
// it breaks modern OpenClaw approval delivery because no exec.approval.requested
// event is ever created and the Discord runtime sees an empty approval queue.
//
// The correct integration path is now:
//   OpenClaw exec ask -> exec.approval.requested -> Rampart bridge evaluates ->
//   Rampart auto-resolves allow/deny or escalates human review -> Discord sees
//   the native OpenClaw approval request.
//
// So we intentionally no-op this dist patch for exec and rely on the bridge.
func patchExecInDist(cmd *cobra.Command, distDir, url, tokenExpr string) bool {
	_ = distDir
	_ = url
	_ = tokenExpr
	fmt.Fprintln(cmd.OutOrStdout(), "  ✓ exec dist patch skipped (use native OpenClaw approval flow via Rampart bridge)")
	return true
}

func hasRampartInMatcher(matcher map[string]any) bool {
	hooks, ok := matcher["hooks"].([]any)
	if !ok {
		return false
	}
	for _, h := range hooks {
		if m, ok := h.(map[string]any); ok {
			if cmd, ok := m["command"].(string); ok {
				// Match bare "rampart hook" or absolute path variants:
				// - Unix: /usr/local/bin/rampart hook
				// - Windows: C:\Users\foo\.rampart\bin\rampart.exe hook
				if cmd == "rampart hook" || cmd == "rampart.exe hook" ||
					strings.HasPrefix(cmd, "rampart hook ") || strings.HasPrefix(cmd, "rampart.exe hook ") ||
					strings.HasSuffix(cmd, "/rampart hook") || strings.HasSuffix(cmd, "\\rampart hook") ||
					strings.HasSuffix(cmd, "/rampart.exe hook") || strings.HasSuffix(cmd, "\\rampart.exe hook") ||
					strings.Contains(cmd, "/rampart hook ") || strings.Contains(cmd, "\\rampart hook ") ||
					strings.Contains(cmd, "/rampart.exe hook ") || strings.Contains(cmd, "\\rampart.exe hook ") {
					return true
				}
			}
		}
	}
	return false
}
