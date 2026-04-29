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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/detect"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type quickstartAgent struct {
	Key      string
	Name     string
	HasSetup bool
	SetupCmd string
	WrapCmd  string
}

func quickstartAgents() []quickstartAgent {
	return []quickstartAgent{
		{Key: "claude-code", Name: "Claude Code", HasSetup: true, SetupCmd: "claude-code"},
		{Key: "codex", Name: "Codex CLI", HasSetup: true, SetupCmd: "codex"},
		{Key: "cline", Name: "Cline", HasSetup: true, SetupCmd: "cline"},
		{Key: "openclaw", Name: "OpenClaw", HasSetup: true, SetupCmd: "openclaw"},
		{Key: "cursor", Name: "Cursor", HasSetup: false, WrapCmd: "rampart wrap -- cursor"},
		{Key: "aider", Name: "Aider", HasSetup: false, WrapCmd: "rampart wrap -- aider"},
		{Key: "windsurf", Name: "Windsurf", HasSetup: false, WrapCmd: "rampart wrap -- windsurf"},
		{Key: "copilot", Name: "GitHub Copilot CLI", HasSetup: false, WrapCmd: "rampart wrap -- gh-copilot"},
	}
}

func newQuickstartCmd() *cobra.Command {
	var agentsFlag string
	var profile string
	var skipDoctor bool
	var yes bool

	cmd := &cobra.Command{
		Use:   "quickstart",
		Short: "One-shot setup: install service, configure agent hooks, verify",
		Long: `quickstart scans your environment, installs Rampart service, wires up detected
AI agents, installs a policy profile, and runs a health summary.

Supported setup agents: claude-code, codex, cline, openclaw
Detected unsupported agents receive wrap guidance.

Use --yes to run non-interactively (AI agents, CI, automated setup).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuickstart(cmd, agentsFlag, profile, skipDoctor, yes)
		},
	}

	cmd.Flags().StringVar(&agentsFlag, "agents", "", "Comma-separated agents to configure (claude-code,codex,cline,openclaw,cursor,aider,windsurf,copilot,none)")
	cmd.Flags().StringVar(&profile, "profile", "", "Policy profile for initialization (default: standard)")
	cmd.Flags().BoolVar(&skipDoctor, "skip-doctor", false, "skip final health check summary")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "non-interactive mode for CI, scripts, and unattended setup")
	return cmd
}

func runQuickstart(cmd *cobra.Command, agentsFlag, profile string, skipDoctor, yes bool) error {
	w := cmd.OutOrStdout()

	fmt.Fprintln(w, "◆ Rampart quickstart")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Scanning environment...")
	fmt.Fprintln(w)

	result, err := detect.Environment()
	if err != nil {
		return fmt.Errorf("environment detection failed: %w", err)
	}

	printDetectedAgents(w, result)
	fmt.Fprintln(w)
	printDetectedTools(w, result)
	fmt.Fprintln(w)

	selectedAgents, err := selectQuickstartAgents(result, agentsFlag)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "  Installing Rampart service...")
	if err := runSubcmd("serve", "install"); err != nil {
		if !quickstartServeRunning() {
			return formatServeInstallError(err)
		}
		fmt.Fprintln(w, "  ✓ Service already running on 127.0.0.1:9090")
	} else {
		fmt.Fprintln(w, "  ✓ Service running on 127.0.0.1:9090")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Configuring hooks...")
	hooksConfigured := 0
	for _, agent := range selectedAgents {
		if agent.HasSetup {
			hooksAlreadyConfigured := quickstartHooksConfigured(agent.SetupCmd)
			setupArgs := []string{"setup", agent.SetupCmd}
			if err := runSubcmd(setupArgs...); err != nil {
				fmt.Fprintf(w, "  ⚠ %s: setup failed (%v)\n", agent.Name, err)
				fmt.Fprintf(w, "    → Retry with: rampart setup %s\n", agent.SetupCmd)
				continue
			}
			hooksConfigured++
			if hooksAlreadyConfigured {
				fmt.Fprintf(w, "  ✓ %s: hooks already configured\n", agent.Name)
			} else {
				fmt.Fprintf(w, "  ✓ %s: hooks installed\n", agent.Name)
			}
			continue
		}

		fmt.Fprintf(w, "  ⚠ %s detected but setup not yet supported\n", agent.Name)
		fmt.Fprintf(w, "    → Use: %s\n", agent.WrapCmd)
	}
	if len(selectedAgents) == 0 {
		fmt.Fprintln(w, "  ⚠ No agents selected for setup")
	}
	fmt.Fprintln(w)

	selectedProfile := strings.TrimSpace(profile)
	if selectedProfile == "" {
		// Auto-select openclaw profile when OpenClaw is one of the configured agents.
		// It includes standard.yaml rules plus OpenClaw-specific session awareness
		// and production deployment gates (kubectl, terraform, docker push).
		for _, agent := range selectedAgents {
			if agent.SetupCmd == "openclaw" {
				selectedProfile = "openclaw"
				break
			}
		}
		if selectedProfile == "" {
			selectedProfile = "standard"
		}
	}

	fmt.Fprintln(w, "  Installing policies...")
	if !hasInstalledPolicy() || strings.TrimSpace(profile) != "" {
		if err := runSubcmd("init", "--profile", selectedProfile); err != nil {
			return fmt.Errorf("policy init failed for profile %q: %w", selectedProfile, err)
		}
		fmt.Fprintf(w, "  ✓ %s profile installed\n", selectedProfile)
	} else {
		fmt.Fprintln(w, "  ✓ Existing policy profile detected")
	}

	suggested := suggestedPolicies(result, installedPolicyNames())
	if len(suggested) > 0 {
		fmt.Fprintf(w, "  💡 Suggested: %s (based on detected tools)\n", strings.Join(suggested, ", "))
		fmt.Fprintf(w, "    → Install with: rampart policy install %s\n", strings.Join(suggested, " "))
	}
	fmt.Fprintln(w)

	if !skipDoctor {
		fmt.Fprintln(w, "  Running health check...")
		if quickstartServeRunning() {
			fmt.Fprintln(w, "  ✓ Service reachable")
		} else {
			fmt.Fprintln(w, "  ⚠ Service unreachable (try: rampart serve)")
		}

		if hooksConfigured == 0 {
			fmt.Fprintln(w, "  ⚠ Hooks configured for 0 agents")
		} else {
			fmt.Fprintf(w, "  ✓ Hooks configured for %d agents\n", hooksConfigured)
		}

		profiles, rules := installedPolicyStats()
		if profiles == 0 {
			fmt.Fprintln(w, "  ⚠ No active policy profiles found")
		} else {
			noun := "profiles"
			if profiles == 1 {
				noun = "profile"
			}
			fmt.Fprintf(w, "  ✓ %d policy %s active (%d rules)\n", profiles, noun, rules)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "◆ You're protected.")
	fmt.Fprintln(w)

	svcURL := quickstartServiceURL()
	dashURL := strings.TrimSuffix(svcURL, "/") + "/dashboard/"
	fmt.Fprintf(w, "  Dashboard:  %s\n", dashURL)

	if tok, err := readPersistedToken(); err == nil && tok != "" {
		masked := tok
		if len(tok) > 8 {
			masked = tok[:8] + "..."
		}
		fmt.Fprintf(w, "  Token:      %s  (full token in ~/.rampart/token)\n", masked)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Next steps:")
	fmt.Fprintln(w, "    • Run your agent normally — Rampart intercepts tool calls automatically")
	fmt.Fprintln(w, "    • rampart watch        — see decisions in real time")
	fmt.Fprintln(w, "    • rampart policy list  — browse available policies")
	fmt.Fprintln(w, "    • Docs: https://docs.rampart.sh")

	return nil
}

func selectQuickstartAgents(result *detect.DetectResult, agentsFlag string) ([]quickstartAgent, error) {
	override := strings.TrimSpace(agentsFlag)

	selectedKeys, err := parseAgentOverride(override)
	if err != nil {
		return nil, err
	}

	agents := quickstartAgents()
	if len(selectedKeys) > 0 {
		keySet := make(map[string]struct{}, len(selectedKeys))
		for _, key := range selectedKeys {
			keySet[key] = struct{}{}
		}
		selected := make([]quickstartAgent, 0, len(selectedKeys))
		for _, a := range agents {
			if _, ok := keySet[a.Key]; ok {
				selected = append(selected, a)
			}
		}
		return selected, nil
	}

	selected := make([]quickstartAgent, 0, len(agents))
	for _, a := range agents {
		if isAgentDetected(result, a.Key) {
			selected = append(selected, a)
		}
	}
	return selected, nil
}

func parseAgentOverride(raw string) ([]string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	aliases := map[string]string{
		"codex-cli":          "codex",
		"github-copilot-cli": "copilot",
		"gh-copilot":         "copilot",
	}
	valid := map[string]struct{}{}
	for _, a := range quickstartAgents() {
		valid[a.Key] = struct{}{}
	}

	seen := map[string]struct{}{}
	selected := make([]string, 0, len(parts))
	for _, part := range parts {
		key := strings.TrimSpace(part)
		if key == "" {
			continue
		}
		if key == "none" {
			if len(parts) > 1 {
				return nil, fmt.Errorf("--agents none cannot be combined with other values")
			}
			return []string{}, nil
		}
		if canonical, ok := aliases[key]; ok {
			key = canonical
		}
		if _, ok := valid[key]; !ok {
			return nil, fmt.Errorf("invalid agent %q in --agents", key)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, key)
	}
	return selected, nil
}

func printDetectedAgents(w io.Writer, result *detect.DetectResult) {
	fmt.Fprintln(w, "  AI Agents:")
	for _, agent := range quickstartAgents() {
		status := "✗"
		if isAgentDetected(result, agent.Key) {
			status = "✓"
		}
		fmt.Fprintf(w, "    %s %s\n", status, agent.Name)
	}
}

func printDetectedTools(w io.Writer, result *detect.DetectResult) {
	fmt.Fprintln(w, "  Dev Tools:")
	fmt.Fprintf(w, "    %s kubectl    %s docker    %s node/npm\n", mark(result.HasKubectl), mark(result.HasDocker), mark(result.HasNode || result.HasNpm))
	fmt.Fprintf(w, "    %s python     %s git       %s terraform\n", mark(result.HasPython || result.HasPip), mark(result.HasGit), mark(result.HasTerraform))
	fmt.Fprintf(w, "    %s go         %s rust      %s aws-cli\n", mark(result.HasGo), mark(result.HasRust), mark(result.HasAWSCLI || result.AWSCredentials))
}

func mark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func isAgentDetected(result *detect.DetectResult, key string) bool {
	switch key {
	case "claude-code":
		return result.ClaudeCode
	case "codex":
		return result.HasCodex
	case "cline":
		return result.HasCline
	case "openclaw":
		return result.HasOpenClaw
	case "cursor":
		return result.HasCursor
	case "aider":
		return result.HasAider
	case "windsurf":
		return result.HasWindsurf
	case "copilot":
		return result.HasCopilot
	default:
		return false
	}
}

func formatServeInstallError(err error) error {
	return fmt.Errorf("serve install failed: %w\n  check permissions for service installation\n  try: sudo rampart serve install\n  or run manually in foreground: rampart serve", err)
}

func suggestedPolicies(result *detect.DetectResult, installed map[string]bool) []string {
	suggestions := make([]string, 0, 5)
	add := func(name string, cond bool) {
		if !cond || installed[name] {
			return
		}
		for _, existing := range suggestions {
			if existing == name {
				return
			}
		}
		suggestions = append(suggestions, name)
	}

	add("kubernetes", result.HasKubectl)
	add("docker", result.HasDocker)
	add("terraform", result.HasTerraform)
	add("node-python", result.HasNode || result.HasNpm || result.HasPython || result.HasPip)
	add("aws-cli", result.HasAWSCLI || result.AWSCredentials)
	return suggestions
}

func installedPolicyNames() map[string]bool {
	names := map[string]bool{}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return names
	}
	policyDir := filepath.Join(home, ".rampart", "policies")
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return names
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if name == "custom.yaml" {
			continue
		}
		if strings.HasSuffix(name, ".yaml") {
			names[strings.TrimSuffix(name, ".yaml")] = true
			continue
		}
		if strings.HasSuffix(name, ".yml") {
			names[strings.TrimSuffix(name, ".yml")] = true
		}
	}
	return names
}

func installedPolicyStats() (int, int) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return 0, 0
	}
	policyDir := filepath.Join(home, ".rampart", "policies")
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return 0, 0
	}

	profiles := 0
	totalRules := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if name == "custom.yaml" || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}
		profiles++

		data, err := os.ReadFile(filepath.Join(policyDir, e.Name()))
		if err != nil {
			continue
		}
		var parsed struct {
			Policies []struct {
				Rules []any `yaml:"rules"`
			} `yaml:"policies"`
			Rules []any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			continue
		}
		totalRules += len(parsed.Rules)
		for _, p := range parsed.Policies {
			totalRules += len(p.Rules)
		}
	}
	return profiles, totalRules
}

// quickstartServiceURL returns the base URL for the Rampart service.
func quickstartServiceURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", defaultServePort)
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

func hasInstalledPolicy() bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	policyDir := filepath.Join(home, ".rampart", "policies")
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		// custom.yaml is an auto-managed placeholder — it is always present and
		// contains no policies by default. Exclude it so a fresh install with only
		// custom.yaml still triggers standard policy auto-init.
		if name == "custom.yaml" {
			continue
		}
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			return true
		}
	}
	return false
}

func quickstartHooksConfigured(env string) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	switch env {
	case "openclaw":
		if isOpenClawPluginConfigured() {
			return true
		}
		_, err := os.Stat(filepath.Join(home, ".local", "bin", "rampart-shim"))
		return err == nil
	case "claude-code":
		data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
		if err != nil {
			return false
		}
		settings := make(claudeSettings)
		if err := json.Unmarshal(data, &settings); err != nil {
			return false
		}
		return hasRampartHook(settings)
	case "cline":
		pre := filepath.Join(home, "Documents", "Cline", "Hooks", "PreToolUse", "rampart-policy")
		post := filepath.Join(home, "Documents", "Cline", "Hooks", "PostToolUse", "rampart-audit")
		_, preErr := os.Stat(pre)
		_, postErr := os.Stat(post)
		return preErr == nil && postErr == nil
	case "codex":
		wrapper := filepath.Join(home, ".local", "bin", "codex")
		data, err := os.ReadFile(wrapper)
		if err != nil {
			return false
		}
		return containsRampartPreload(string(data))
	default:
		return false
	}
}
