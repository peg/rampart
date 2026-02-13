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
	"bufio"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

// agentInfo describes a detected AI agent and how to protect it.
type agentInfo struct {
	Name      string
	Detected  bool
	HasSetup  bool // true if we can auto-configure via setup subcommand
	SetupCmd  string // subcommand name (e.g. "claude-code")
	ManualCmd string // fallback manual command for agents without native setup
}

// detectAgents checks PATH and common locations for known AI agents.
func detectAgents() []agentInfo {
	home, _ := os.UserHomeDir()

	agents := []agentInfo{
		{
			Name:     "Claude Code",
			HasSetup: true,
			SetupCmd: "claude-code",
		},
		{
			Name:     "Cline",
			HasSetup: true,
			SetupCmd: "cline",
		},
		{
			Name:     "OpenClaw",
			HasSetup: true,
			SetupCmd: "openclaw",
		},
		{
			Name:      "Cursor",
			HasSetup:  false,
			ManualCmd: "rampart mcp -- cursor",
		},
		{
			Name:      "Codex",
			HasSetup:  false,
			ManualCmd: "rampart preload -- codex",
		},
	}

	// Claude Code: check PATH or ~/.claude/
	if _, err := osexec.LookPath("claude"); err == nil {
		agents[0].Detected = true
	} else if home != "" {
		if _, err := os.Stat(filepath.Join(home, ".claude")); err == nil {
			agents[0].Detected = true
		}
	}

	// Cline: check ~/.vscode/extensions/ for cline or ~/Documents/Cline/
	if home != "" {
		clineExtDir := filepath.Join(home, ".vscode", "extensions")
		if entries, err := os.ReadDir(clineExtDir); err == nil {
			for _, e := range entries {
				if strings.Contains(strings.ToLower(e.Name()), "cline") {
					agents[1].Detected = true
					break
				}
			}
		}
		if !agents[1].Detected {
			if _, err := os.Stat(filepath.Join(home, "Documents", "Cline")); err == nil {
				agents[1].Detected = true
			}
		}
	}

	// OpenClaw: check PATH or running process
	if _, err := osexec.LookPath("openclaw"); err == nil {
		agents[2].Detected = true
	}

	// Cursor: check ~/.cursor/ or Applications
	if home != "" {
		if _, err := os.Stat(filepath.Join(home, ".cursor")); err == nil {
			agents[3].Detected = true
		}
	}
	if !agents[3].Detected && runtime.GOOS == "darwin" {
		if _, err := os.Stat("/Applications/Cursor.app"); err == nil {
			agents[3].Detected = true
		}
	}

	// Codex: check PATH
	if _, err := osexec.LookPath("codex"); err == nil {
		agents[4].Detected = true
	}

	return agents
}

// isTerminal returns true if the given file descriptor is a terminal.
func isTerminal(fd *os.File) bool {
	fi, err := fd.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// runInteractiveSetup launches the interactive setup wizard.
func runInteractiveSetup(cmd *cobra.Command, opts *rootOptions) error {
	if !isTerminal(os.Stdin) {
		return cmd.Help()
	}

	out := cmd.OutOrStdout()
	scanner := bufio.NewScanner(os.Stdin)

	force := false
	if f := cmd.Flags().Lookup("force"); f != nil {
		force = f.Changed
	}

	// 1. Welcome banner
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "🛡️  Rampart Setup")
	fmt.Fprintln(out, "Let's get your AI agents protected.")
	fmt.Fprintln(out, "")

	// 2. Auto-detect agents
	agents := detectAgents()
	detectedSetup := []agentInfo{}   // detected agents with auto-setup
	detectedManual := []agentInfo{}  // detected agents without auto-setup

	fmt.Fprintln(out, "Detected agents:")
	for _, a := range agents {
		if a.Detected {
			if a.HasSetup {
				fmt.Fprintf(out, "  ✓ %s (hooks available)\n", a.Name)
				detectedSetup = append(detectedSetup, a)
			} else {
				fmt.Fprintf(out, "  ✓ %s (manual — run: %s)\n", a.Name, a.ManualCmd)
				detectedManual = append(detectedManual, a)
			}
		} else {
			fmt.Fprintf(out, "  ✗ %s (not found)\n", a.Name)
		}
	}
	fmt.Fprintln(out, "")

	// If nothing with auto-setup detected, bail
	if len(detectedSetup) == 0 {
		fmt.Fprintln(out, "No agents with automatic setup were detected.")
		if len(detectedManual) > 0 {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "For detected agents without hook support, run the commands shown above.")
		}
		return nil
	}

	// 3. Ask which agents to protect
	selectedAgents := detectedSetup
	if !force {
		fmt.Fprintln(out, "Which agents would you like to protect? [all detected/select/skip]")
		fmt.Fprint(out, "Choice [all detected]: ")
		choice := readLine(scanner)
		choice = strings.TrimSpace(strings.ToLower(choice))

		switch choice {
		case "skip":
			fmt.Fprintln(out, "Skipping agent setup.")
			return nil
		case "select":
			selectedAgents = nil
			for _, a := range detectedSetup {
				fmt.Fprintf(out, "  Protect %s? [Y/n]: ", a.Name)
				ans := readLine(scanner)
				ans = strings.TrimSpace(strings.ToLower(ans))
				if ans == "" || ans == "y" || ans == "yes" {
					selectedAgents = append(selectedAgents, a)
				}
			}
			if len(selectedAgents) == 0 {
				fmt.Fprintln(out, "No agents selected.")
				return nil
			}
		default:
			// "all detected" or empty — use all detected
		}
		fmt.Fprintln(out, "")
	}

	// 4. Ask for policy profile
	profileNames := []string{"standard", "paranoid", "yolo"}
	profileDescs := []string{
		"standard (recommended) — blocks dangerous commands, logs everything",
		"paranoid — blocks most commands, requires explicit allows",
		"yolo — logs only, blocks nothing",
	}
	selectedProfile := "standard"

	if !force {
		fmt.Fprintln(out, "Choose a policy profile:")
		for i, desc := range profileDescs {
			fmt.Fprintf(out, "  %d. %s\n", i+1, desc)
		}
		fmt.Fprintln(out, "")
		fmt.Fprint(out, "Profile [1]: ")
		ans := readLine(scanner)
		ans = strings.TrimSpace(ans)
		switch ans {
		case "2":
			selectedProfile = profileNames[1]
		case "3":
			selectedProfile = profileNames[2]
		default:
			selectedProfile = profileNames[0]
		}
		fmt.Fprintln(out, "")
	}

	// 5. Show plan and confirm
	home, _ := os.UserHomeDir()
	fmt.Fprintln(out, "Ready to install:")
	for _, a := range selectedAgents {
		switch a.SetupCmd {
		case "claude-code":
			fmt.Fprintf(out, "  • Claude Code: hooks in %s\n", filepath.Join(home, ".claude", "settings.json"))
		case "cline":
			fmt.Fprintf(out, "  • Cline: hooks in %s\n", filepath.Join(home, "Documents", "Cline", "Hooks"))
		case "openclaw":
			fmt.Fprintf(out, "  • OpenClaw: shell shim in %s\n", filepath.Join(home, ".local", "bin", "rampart-shim"))
		}
	}
	fmt.Fprintf(out, "  • Policy: %s\n", filepath.Join(home, ".rampart", "policies", selectedProfile+".yaml"))
	fmt.Fprintln(out, "")

	if !force {
		fmt.Fprint(out, "Proceed? [Y/n]: ")
		ans := readLine(scanner)
		ans = strings.TrimSpace(strings.ToLower(ans))
		if ans == "n" || ans == "no" {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}
		fmt.Fprintln(out, "")
	}

	// 6. Install policy
	if err := installPolicy(out, home, selectedProfile); err != nil {
		return err
	}

	// Run setup for each selected agent via subcommands
	for _, a := range selectedAgents {
		subCmd, _, err := cmd.Find([]string{a.SetupCmd})
		if err != nil {
			return fmt.Errorf("setup: find subcommand %s: %w", a.SetupCmd, err)
		}
		// Set --force so subcommands don't prompt
		if f := subCmd.Flags().Lookup("force"); f != nil {
			_ = f.Value.Set("true")
		}
		if err := subCmd.RunE(subCmd, nil); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "⚠ %s setup failed: %v\n", a.Name, err)
		}
	}

	// 7. Shell completions
	if isTerminal(os.Stdin) {
		installCompletions := force
		if !force {
			fmt.Fprintln(out, "")
			fmt.Fprint(out, "Would you like to install shell completions? [Y/n] ")
			ans := readLine(scanner)
			ans = strings.TrimSpace(strings.ToLower(ans))
			installCompletions = ans == "" || ans == "y" || ans == "yes"
		}
		if installCompletions {
			if err := installShellCompletions(cmd, out); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Shell completions failed: %v\n", err)
			}
		}
	}

	// 8. Done
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "✅ Setup complete!")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Try it out:")
	fmt.Fprintln(out, "  rampart watch    — see decisions in real time")
	fmt.Fprintln(out, "  rampart report   — generate an audit report")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Need help? https://docs.rampart.sh")

	return nil
}

// installPolicy writes the selected policy profile to ~/.rampart/policies/.
func installPolicy(out io.Writer, home, profile string) error {
	policyDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		return fmt.Errorf("setup: create policy dir: %w", err)
	}

	policyPath := filepath.Join(policyDir, profile+".yaml")
	if _, err := os.Stat(policyPath); err == nil {
		// Already exists — don't overwrite
		fmt.Fprintf(out, "✓ Policy already exists at %s\n", policyPath)
		return nil
	}

	content, err := policies.FS.ReadFile(profile + ".yaml")
	if err != nil {
		return fmt.Errorf("setup: read embedded profile %s: %w", profile, err)
	}

	if err := os.WriteFile(policyPath, content, 0o644); err != nil {
		return fmt.Errorf("setup: write policy: %w", err)
	}
	fmt.Fprintf(out, "✓ Policy written to %s\n", policyPath)
	return nil
}

// installShellCompletions detects the user's shell and installs completion scripts.
func installShellCompletions(cmd *cobra.Command, out io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("setup: resolve home: %w", err)
	}

	shell := os.Getenv("SHELL")
	// Strip rampart-shim if that's set as SHELL
	if strings.Contains(shell, "rampart") {
		shell = "/bin/bash"
	}

	rootCmd := cmd.Root()

	var completionDir, completionFile string

	switch {
	case strings.HasSuffix(shell, "/zsh"):
		completionDir = filepath.Join(home, ".zsh", "completions")
		completionFile = filepath.Join(completionDir, "_rampart")
		if err := os.MkdirAll(completionDir, 0o755); err != nil {
			return fmt.Errorf("setup: create zsh completions dir: %w", err)
		}
		f, err := os.Create(completionFile)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := rootCmd.GenZshCompletion(f); err != nil {
			return err
		}
		fmt.Fprintf(out, "✓ Zsh completions installed to %s\n", completionFile)
		fmt.Fprintln(out, "  Add this to ~/.zshrc if not already present:")
		fmt.Fprintf(out, "    fpath=(~/.zsh/completions $fpath)\n")

	case strings.HasSuffix(shell, "/fish"):
		completionDir = filepath.Join(home, ".config", "fish", "completions")
		completionFile = filepath.Join(completionDir, "rampart.fish")
		if err := os.MkdirAll(completionDir, 0o755); err != nil {
			return fmt.Errorf("setup: create fish completions dir: %w", err)
		}
		f, err := os.Create(completionFile)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := rootCmd.GenFishCompletion(f, true); err != nil {
			return err
		}
		fmt.Fprintf(out, "✓ Fish completions installed to %s\n", completionFile)

	default:
		// Default to bash
		completionDir = filepath.Join(home, ".local", "share", "bash-completion", "completions")
		completionFile = filepath.Join(completionDir, "rampart")
		if err := os.MkdirAll(completionDir, 0o755); err != nil {
			return fmt.Errorf("setup: create bash completions dir: %w", err)
		}
		f, err := os.Create(completionFile)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := rootCmd.GenBashCompletion(f); err != nil {
			return err
		}
		fmt.Fprintf(out, "✓ Bash completions installed to %s\n", completionFile)
	}

	return nil
}

// readLine reads a line from the scanner, returning empty string on EOF.
func readLine(scanner *bufio.Scanner) string {
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}
