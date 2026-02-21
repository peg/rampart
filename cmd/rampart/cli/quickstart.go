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
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newQuickstartCmd() *cobra.Command {
	var envFlag string
	var skipDoctor bool
	var yes bool

	cmd := &cobra.Command{
		Use:   "quickstart",
		Short: "One-shot setup: install serve, configure hooks, verify",
		Long: `quickstart detects your AI coding environment, installs the Rampart
background service, wires up the tool-call hook, and runs a health check.

Supported environments: claude-code, cline, cursor, windsurf, openclaw
If --env is not set, quickstart will auto-detect.

Use --yes to run non-interactively (AI agents, CI, automated setup).
For OpenClaw, --yes also enables --patch-tools for full file-operation coverage.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuickstart(cmd, envFlag, skipDoctor, yes)
		},
	}

	cmd.Flags().StringVar(&envFlag, "env", "", "AI coding environment (claude-code|cline|cursor|windsurf|openclaw|none)")
	cmd.Flags().BoolVar(&skipDoctor, "skip-doctor", false, "skip final health check")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "non-interactive mode: for OpenClaw, also enables --patch-tools (full file coverage); safe to pass for any agent")
	return cmd
}

func runQuickstart(cmd *cobra.Command, envFlag string, skipDoctor bool, yes bool) error {
	w := cmd.OutOrStdout()

	fmt.Fprintln(w, "◆ Rampart quickstart")
	fmt.Fprintln(w)

	// Step 1: detect environment
	env := envFlag
	if env == "" {
		env = detectEnv()
		if env == "" {
			fmt.Fprintln(w, "  ⚠  Could not detect AI coding environment.")
			fmt.Fprintln(w, "     Use --env claude-code|cline|cursor|windsurf|openclaw to specify manually.")
			env = "none"
		} else {
			fmt.Fprintf(w, "  ✓  Detected environment: %s\n", env)
		}
	}
	fmt.Fprintln(w)

	// Step 2: install/start serve
	fmt.Fprintln(w, "  Installing Rampart service...")
	if err := runSubcmd("serve", "install"); err != nil {
		// If already installed, that's fine — check if it's reachable.
		if !quickstartServeRunning() {
			return fmt.Errorf("serve install failed: %w", err)
		}
		fmt.Fprintln(w, "  ✓  Service already installed and running")
	} else {
		fmt.Fprintln(w, "  ✓  Service installed and started")
	}
	fmt.Fprintln(w)

	// Step 3: setup hooks for detected env
	if env != "none" {
		fmt.Fprintf(w, "  Configuring hooks for %s...\n", env)
		setupArgs := []string{"setup", env}
		// --yes enables full protection for OpenClaw (--patch-tools covers file reads/writes/edits)
		if yes && env == "openclaw" {
			setupArgs = append(setupArgs, "--patch-tools")
		}
		if err := runSubcmd(setupArgs...); err != nil {
			fmt.Fprintf(w, "  ⚠  Hook setup failed: %v\n", err)
			fmt.Fprintln(w, "     Run `rampart setup "+env+"` manually to retry.")
		} else {
			fmt.Fprintln(w, "  ✓  Hooks configured")
		}
		fmt.Fprintln(w)
	}

	// Step 4: doctor
	if !skipDoctor {
		fmt.Fprintln(w, "  Running health check...")
		fmt.Fprintln(w)
		_ = runSubcmd("doctor")
		fmt.Fprintln(w)
	}

	// Step 5: summary
	fmt.Fprintln(w, "◆ You're protected.")
	fmt.Fprintln(w)

	// Try to show dashboard URL
	svcURL := quickstartServiceURL()
	if svcURL != "" {
		dashURL := strings.TrimSuffix(svcURL, "/") + "/dashboard/"
		fmt.Fprintf(w, "  Dashboard: %s\n", dashURL)
	}

	if tok, err := readPersistedToken(); err == nil && tok != "" {
		masked := tok
		if len(tok) > 8 {
			masked = tok[:8] + "..."
		}
		fmt.Fprintf(w, "  Token:     %s  (full token in ~/.rampart/token)\n", masked)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Tip: export RAMPART_SESSION=my-project to tag audit events with a project name.")
	fmt.Fprintln(w, "  Docs: https://docs.rampart.sh")

	return nil
}

// detectEnv returns the first detected AI coding environment, or "".
func detectEnv() string {
	// OpenClaw: most reliable signal is OPENCLAW_SERVICE_MARKER env var,
	// which OpenClaw gateway sets when it spawns an agent process.
	if os.Getenv("OPENCLAW_SERVICE_MARKER") == "openclaw" {
		return "openclaw"
	}
	// Claude Code: settings.json or binary
	if _, err := os.Stat(claudeSettingsPath()); err == nil {
		return "claude-code"
	}
	if _, err := exec.LookPath("claude"); err == nil {
		return "claude-code"
	}
	// Cursor
	if _, err := os.Stat(cursorSettingsPath()); err == nil {
		return "cursor"
	}
	// Windsurf
	if _, err := os.Stat(windsurfSettingsPath()); err == nil {
		return "windsurf"
	}
	return ""
}

func claudeSettingsPath() string {
	home, _ := os.UserHomeDir()
	return home + "/.claude/settings.json"
}

func cursorSettingsPath() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return home + "/Library/Application Support/Cursor/User/settings.json"
	}
	return home + "/.config/Cursor/User/settings.json"
}

func windsurfSettingsPath() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return home + "/Library/Application Support/Windsurf/User/settings.json"
	}
	return home + "/.config/Windsurf/User/settings.json"
}

// quickstartServiceURL returns the base URL for the Rampart service.
func quickstartServiceURL() string {
	return fmt.Sprintf("http://localhost:%d", defaultServePort)
}

// quickstartServeRunning checks whether the Rampart service is reachable.
func quickstartServeRunning() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	url := quickstartServiceURL() + "/healthz"
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

// runSubcmd runs a rampart subcommand as a subprocess, inheriting
// stdout/stderr/stdin. This avoids mutating global cobra state and keeps
// each step independently observable.
func runSubcmd(args ...string) error {
	self, err := os.Executable()
	if err != nil {
		self = "rampart"
	}
	c := exec.Command(self, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}
