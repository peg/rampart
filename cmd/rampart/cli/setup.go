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
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up Rampart integrations with AI agents",
		Long: `Set up Rampart integrations with supported AI agents.

Supported AI Agents:
  • Claude Code (Anthropic)   - Native hook integration
  • Cline (VS Code)           - Native hook integration  
  • OpenClaw                  - Shell wrapper integration`,
	}

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

	cmd := &cobra.Command{
		Use:   "claude-code",
		Short: "Install Rampart hook into Claude Code settings",
		Long: `Adds a PreToolUse hook to ~/.claude/settings.json that routes all
Bash commands through Rampart's policy engine before execution.

Safe to run multiple times — will not duplicate hooks or overwrite
other settings.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
	return cmd
}

// newSetupClineCmd is defined in cline.go

func newSetupOpenClawCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var port int

	cmd := &cobra.Command{
		Use:   "openclaw",
		Short: "Set up Rampart to protect an OpenClaw agent",
		Long: `Installs a shell shim and starts the Rampart policy server so that
every command OpenClaw executes goes through Rampart's policy engine.

Creates:
  - A systemd user service running "rampart serve"
  - A shell shim at ~/.local/bin/rampart-shim
  - Default policy at ~/.rampart/policies/standard.yaml (if missing)

After setup, configure OpenClaw to use the shim as its shell.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
				if err := os.WriteFile(policyPath, []byte(defaultPolicy), 0o644); err != nil {
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

if [ "$1" = "-c" ]; then
    shift
    CMD="$1"
    shift

    if ! command -v curl >/dev/null 2>&1; then
        exec "$REAL_SHELL" -c "$CMD" "$@"
    fi

    ENCODED=$(printf '%%s' "$CMD" | base64 | tr -d '\n\r')
    PAYLOAD=$(printf '{"agent":"openclaw","session":"main","params":{"command_b64":"%%s"}}' "$ENCODED")
    DECISION=$(curl -sfS -X POST "${RAMPART_URL}/v1/preflight/exec" \
        -H "Authorization: Bearer ${RAMPART_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" 2>/dev/null)

    if [ -z "$DECISION" ]; then
        exec "$REAL_SHELL" -c "$CMD" "$@"
    fi

    ALLOWED=$(printf '%%s' "$DECISION" | sed -n 's/.*"allowed":[[:space:]]*\(true\|false\).*/\1/p' | head -n 1)
    if [ -z "$ALLOWED" ]; then
        exec "$REAL_SHELL" -c "$CMD" "$@"
    fi
    if [ "$RAMPART_MODE" = "enforce" ] && [ "$ALLOWED" != "true" ]; then
        MSG=$(printf '%%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then
            MSG="policy denied"
        fi
        echo "rampart: blocked - ${MSG}" >&2
        exit 126
    fi

    exec "$REAL_SHELL" -c "$CMD" "$@"
fi

exec "$REAL_SHELL" "$@"
`, realShell, port, token)

			if err := os.WriteFile(shimPath, []byte(shimContent), 0o755); err != nil {
				return fmt.Errorf("setup: write shim: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Shell shim installed at %s\n", shimPath)

			// Start service (OS-specific)
			if err := startService(cmd); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Could not start service: %v\n", err)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "✓ Rampart proxy service started")
			}

			// Print next steps
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintln(cmd.OutOrStdout(), "Next steps:")
			fmt.Fprintf(cmd.OutOrStdout(), "  1. Set SHELL=%s in your OpenClaw gateway config\n", shimPath)
			fmt.Fprintln(cmd.OutOrStdout(), "  2. Restart the OpenClaw gateway")
			fmt.Fprintln(cmd.OutOrStdout(), "  3. Every command will now go through Rampart's policy engine")
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintf(cmd.OutOrStdout(), "Policy: %s\n", policyPath)
			fmt.Fprintf(cmd.OutOrStdout(), "Audit:  %s\n", filepath.Join(home, ".rampart", "audit"))
			fmt.Fprintf(cmd.OutOrStdout(), "Watch:  rampart watch --audit-dir %s\n", filepath.Join(home, ".rampart", "audit"))

			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing shim and service config")
	cmd.Flags().IntVar(&port, "port", 19090, "Port for Rampart policy server")
	return cmd
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
