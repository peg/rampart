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
		Long: `Adds a PreToolUse hook to ~/.claude/settings.json that routes all
Bash commands through Rampart's policy engine before execution.

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

			// Build the hook config
			rampartHook := map[string]any{
				"type":    "command",
				"command": "rampart hook",
			}

			bashMatcher := map[string]any{
				"matcher": "Bash",
				"hooks":   []any{rampartHook},
			}
			readMatcher := map[string]any{
				"matcher": "Read",
				"hooks":   []any{rampartHook},
			}
			writeMatcher := map[string]any{
				"matcher": "Write|Edit",
				"hooks":   []any{rampartHook},
			}

			// Get or create hooks section
			hooks, ok := settings["hooks"].(map[string]any)
			if !ok {
				hooks = make(map[string]any)
			}

			// Get or create PreToolUse array
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
			preToolUse = append(preToolUse, bashMatcher, readMatcher, writeMatcher)

			hooks["PreToolUse"] = preToolUse
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
			fmt.Fprintln(cmd.OutOrStdout(), "  Claude Code will now route Bash commands through Rampart.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Run 'claude' normally — no wrapper needed.")

			// Check if rampart is in system PATH.
			if _, err := execLookPath("rampart"); err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "")
				fmt.Fprintln(cmd.ErrOrStderr(), "⚠ Warning: 'rampart' is not in your system PATH.")
				fmt.Fprintln(cmd.ErrOrStderr(), "  Claude Code hooks won't work until it is.")
				fmt.Fprintln(cmd.ErrOrStderr(), "  Fix with: sudo ln -sf $(go env GOPATH)/bin/rampart /usr/local/bin/rampart")
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

	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok {
		fmt.Fprintln(cmd.OutOrStdout(), "No PreToolUse hooks found. Nothing to remove.")
		return nil
	}

	var kept []any
	var removedCount int
	for _, h := range preToolUse {
		if m, ok := h.(map[string]any); ok && hasRampartInMatcher(m) {
			removedCount++
			matcher, _ := m["matcher"].(string)
			fmt.Fprintf(cmd.OutOrStdout(), "  Removed hook: matcher=%s\n", matcher)
			continue
		}
		kept = append(kept, h)
	}

	if removedCount == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No Rampart hooks found in Claude Code settings. Nothing to remove.")
		return nil
	}

	// Clean up empty structures
	if len(kept) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = kept
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

	cmd := &cobra.Command{
		Use:   "openclaw",
		Short: "Set up Rampart to protect an OpenClaw agent",
		Long: `Installs a shell shim and starts the Rampart policy server so that
every command OpenClaw executes goes through Rampart's policy engine.

Creates:
  - A systemd user service running "rampart serve"
  - A shell shim at ~/.local/bin/rampart-shim
  - Default policy at ~/.rampart/policies/standard.yaml (if missing)

After setup, configure OpenClaw to use the shim as its shell.

Use --patch-tools to also patch OpenClaw's file tools (read/write/edit/grep)
so file operations go through Rampart too. Re-run after OpenClaw upgrades.

Use --remove to uninstall the shim and service (preserves policies and audit logs).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if remove {
				return removeOpenClaw(cmd)
			}
			if runtime.GOOS == "windows" {
				return fmt.Errorf("setup openclaw: not supported on Windows")
			}

			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup: resolve home: %w", err)
			}

			shimPath := filepath.Join(home, ".local", "bin", "rampart-shim")
			if _, err := os.Stat(shimPath); err == nil && !force {
				fmt.Fprintf(cmd.OutOrStdout(), "Rampart shim already exists at %s\n", shimPath)
				fmt.Fprintln(cmd.OutOrStdout(), "Use --force to overwrite.")
				return nil
			}

			// Detect real shell
			realShell := os.Getenv("SHELL")
			if realShell == "" || strings.Contains(realShell, "rampart") {
				realShell = "/bin/bash"
			}

			// Generate stable token
			tokenBytes := make([]byte, 24)
			if _, err := rand.Read(tokenBytes); err != nil {
				return fmt.Errorf("setup: generate token: %w", err)
			}
			token := "rampart_" + hex.EncodeToString(tokenBytes)

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
				if err := os.WriteFile(policyPath, []byte(defaultPolicy), 0o600); err != nil {
					return fmt.Errorf("setup: write default policy: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Default policy written to %s\n", policyPath)
			}

			// Find rampart binary path
			rampartBin, err := os.Executable()
			if err != nil {
				rampartBin = "rampart"
				if p, e := execLookPath("rampart"); e == nil {
					rampartBin = p
				}
			}

			// Create service (OS-specific)
			if err := installService(cmd, home, rampartBin, policyPath, token, port); err != nil {
				return err
			}

			// Create shell shim
			shimContent := fmt.Sprintf(`#!/usr/bin/env bash
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
    PAYLOAD=$(printf '{"agent":"openclaw","session":"main","params":{"command_b64":"%%s"}}' "$ENCODED")
    RESP_FILE=$(mktemp /tmp/.rampart-resp.XXXXXX)
    HTTP_CODE=$(curl -sS -o "$RESP_FILE" -w "%%{http_code}" -X POST "${RAMPART_URL}/v1/tool/exec" \
        -H "Authorization: Bearer ${RAMPART_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" 2>/dev/null)
    DECISION=$(cat "$RESP_FILE" 2>/dev/null)
    rm -f "$RESP_FILE"

    # Fail open if no response
    if [ -z "$DECISION" ]; then
        exec "$REAL_SHELL" -c "$CMD" "$@"
    fi

    # Check HTTP status — 403 means denied
    if [ "$RAMPART_MODE" = "enforce" ] && [ "$HTTP_CODE" = "403" ]; then
        MSG=$(printf '%%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="policy denied"; fi
        echo "rampart: blocked — ${MSG}" >&2
        exit 126
    fi

    # Check "decision":"deny" as fallback
    DENIED=$(printf '%%s' "$DECISION" | sed -n 's/.*"decision":"\(deny\)".*/\1/p' | head -n 1)
    if [ "$RAMPART_MODE" = "enforce" ] && [ "$DENIED" = "deny" ]; then
        MSG=$(printf '%%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="policy denied"; fi
        echo "rampart: blocked — ${MSG}" >&2
        exit 126
    fi

    # Handle require_approval — block and poll until resolved
    APPROVAL_ID=$(printf '%%s' "$DECISION" | sed -n 's/.*"approval_id":"\([^"]*\)".*/\1/p' | head -n 1)
    if [ -n "$APPROVAL_ID" ]; then
        MSG=$(printf '%%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="approval required"; fi
        echo "rampart: ⏳ waiting for approval — ${MSG}" >&2
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
                    echo "rampart: ✅ approved" >&2
                    exec "$REAL_SHELL" -c "$CMD" "$@"
                    ;;
                denied|expired)
                    echo "rampart: ❌ ${STATUS}" >&2
                    exit 126
                    ;;
            esac
        done

        echo "rampart: ⏰ approval timed out after ${APPROVAL_TIMEOUT}s" >&2
        exit 126
    fi

    exec "$REAL_SHELL" -c "$CMD" "$@"
fi

exec "$REAL_SHELL" "$@"
`, realShell, port, token)

			if err := os.WriteFile(shimPath, []byte(shimContent), 0o700); err != nil {
				return fmt.Errorf("setup: write shim: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Shell shim installed at %s\n", shimPath)

			// Start service (OS-specific)
			if err := startService(cmd); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Could not start service: %v\n", err)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "✓ Rampart proxy service started")
			}

			// Optionally patch file tools
			if patchTools {
				if err := patchOpenClawTools(cmd, fmt.Sprintf("http://127.0.0.1:%d", port), token); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Could not patch file tools: %v\n", err)
					fmt.Fprintln(cmd.ErrOrStderr(), "  Shell commands are still protected. Run with --patch-tools again to retry.")
				}
			}

			// Print next steps
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintln(cmd.OutOrStdout(), "Next steps:")
			fmt.Fprintf(cmd.OutOrStdout(), "  1. Set SHELL=%s in your OpenClaw gateway config\n", shimPath)
			fmt.Fprintln(cmd.OutOrStdout(), "  2. Restart the OpenClaw gateway")
			fmt.Fprintln(cmd.OutOrStdout(), "  3. Every command will now go through Rampart's policy engine")
			if !patchTools {
				fmt.Fprintln(cmd.OutOrStdout(), "")
				fmt.Fprintln(cmd.OutOrStdout(), "  Optional: Run with --patch-tools to also protect file reads/writes/edits.")
			}
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintf(cmd.OutOrStdout(), "Policy: %s\n", policyPath)
			fmt.Fprintf(cmd.OutOrStdout(), "Audit:  %s\n", filepath.Join(home, ".rampart", "audit"))
			fmt.Fprintf(cmd.OutOrStdout(), "Watch:  rampart watch --audit-dir %s\n", filepath.Join(home, ".rampart", "audit"))

			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing shim and service config")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove Rampart shim and service (preserves policies and audit logs)")
	cmd.Flags().BoolVar(&patchTools, "patch-tools", false, "Also patch OpenClaw's file tools (read/write/edit/grep) for full coverage")
	cmd.Flags().IntVar(&port, "port", 19090, "Port for Rampart policy server")
	return cmd
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
			reload := osexec.Command("systemctl", "--user", "daemon-reload")
			_ = reload.Run()
		}
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
Environment=HOME=%s
Environment=RAMPART_TOKEN=%s

[Install]
WantedBy=default.target
`, rampartBin, port, policyPath, home, token)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0o644); err != nil {
		return fmt.Errorf("setup: write service file: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Systemd service written to %s\n", servicePath)
	return nil
}

func installLaunchd(cmd *cobra.Command, home, rampartBin, policyPath, token string, port int) error {
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		return fmt.Errorf("setup: create LaunchAgents dir: %w", err)
	}
	plistPath := filepath.Join(agentDir, "com.rampart.proxy.plist")
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
`, rampartBin, port, policyPath, home, token,
		filepath.Join(home, ".rampart", "rampart-proxy.log"),
		filepath.Join(home, ".rampart", "rampart-proxy.log"))

	if err := os.WriteFile(plistPath, []byte(plistContent), 0o644); err != nil {
		return fmt.Errorf("setup: write plist: %w", err)
	}
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

const defaultPolicy = `version: "1"
default_action: allow
policies:
  - name: block-destructive
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "rm -rf /"
            - "rm -rf ~"
            - "rm -rf /*"
            - "rm -rf ~/*"
            - ":(){ :|:& };:"
            - "dd if=*"
            - "mkfs*"
            - "chmod -R 777 /"
            - "> /dev/sda"
        message: "Destructive command blocked"
      - action: deny
        when:
          command_matches:
            - "nc -e *"
            - "nc -c *"
            - "ncat -e *"
            - "bash -i >*"
        message: "Reverse shell detected"
      - action: deny
        when:
          command_matches:
            - "crontab -r"
            - "crontab -r *"
        message: "Crontab deletion blocked"

  - name: log-privileged
    match:
      tool: ["exec"]
    rules:
      - action: log
        when:
          command_matches:
            - "sudo *"
            - "kubectl delete *"
            - "docker rm *"
            - "docker rmi *"
        message: "Privileged command logged"

  - name: log-network-tools
    match:
      tool: ["exec"]
    rules:
      - action: log
        when:
          command_matches:
            - "curl *"
            - "wget *"
            - "nc *"
            - "ncat *"
        message: "Network tool usage logged"

  - name: block-credential-commands
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "cat */.ssh/id_*"
            - "cat */.aws/credentials"
            - "cat */.env"
            - "cat */.netrc"
            - "cat */credentials"
            - "cat */.git-credentials"
            - "cat /etc/shadow"
            - "cat /etc/passwd"
            - "cat /etc/gshadow"
            - "cat /etc/master.passwd"
            - "head /etc/shadow"
            - "tail /etc/shadow"
            - "less /etc/shadow"
            - "more /etc/shadow"
            - "grep * /etc/shadow"
            - "cat /etc/sudoers"
            - "cat /etc/sudoers.d/*"
            - "cat */.bash_history"
            - "cat */.zsh_history"
            - "cat */.*_history"
            - "cat /proc/**/environ"
        message: "Credential access blocked"
`

func hasRampartHook(settings claudeSettings) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return false
	}
	for _, h := range preToolUse {
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
		"/usr/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools",
		"/usr/local/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools",
		filepath.Join(home, ".npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools"),
	}
}

func patchOpenClawTools(cmd *cobra.Command, url, token string) error {
	// Find the tools directory
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

func hasRampartInMatcher(matcher map[string]any) bool {
	hooks, ok := matcher["hooks"].([]any)
	if !ok {
		return false
	}
	for _, h := range hooks {
		if m, ok := h.(map[string]any); ok {
			if cmd, ok := m["command"].(string); ok {
				if cmd == "rampart hook" {
					return true
				}
			}
		}
	}
	return false
}
