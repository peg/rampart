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
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peg/rampart/internal/detect"
	"github.com/spf13/cobra"
)

type quickstartAgent struct {
	Key      string
	Name     string
	HasSetup bool
	SetupCmd string
	WrapCmd  string
}

func quickstartAgents() []quickstartAgent {
	drivers := make(map[string]integrationDriver)
	for _, driver := range supportedIntegrationDrivers() {
		if driver.AutoProtect {
			drivers[driver.ID] = driver
		}
	}
	agents := make([]quickstartAgent, 0, len(drivers)+3)
	for _, id := range []string{"claude-code", "codex", "cline", "openclaw", "copilot", "antigravity"} {
		if driver, ok := drivers[id]; ok {
			agents = append(agents, quickstartAgent{
				Key: id, Name: driver.DisplayName, HasSetup: true, SetupCmd: id,
			})
		}
	}
	return append(agents,
		quickstartAgent{Key: "cursor", Name: "Cursor", WrapCmd: "rampart wrap -- cursor"},
		quickstartAgent{Key: "aider", Name: "Aider", WrapCmd: "rampart wrap -- aider"},
		quickstartAgent{Key: "windsurf", Name: "Windsurf", WrapCmd: "rampart wrap -- windsurf"},
	)
}

func newQuickstartCmd(rootOpts *rootOptions) *cobra.Command {
	var agentsFlag string
	var profile string
	var skipDoctor bool
	var yes bool

	cmd := &cobra.Command{
		Use:   "quickstart",
		Short: "Compatibility onboarding flow (use rampart protect)",
		Long: `quickstart scans your environment, installs Rampart service, wires up detected
AI agents, installs a policy profile, and runs a health summary.

Native integrations use the same managed protection lifecycle as rampart
protect. Detected unsupported agents receive wrap guidance.

Quickstart is non-interactive. --yes remains accepted for compatibility with
existing CI, scripts, and agent-driven installs.`,
		Deprecated: "use `rampart protect`; quickstart remains as a compatibility workflow",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuickstart(cmd, rootOpts, agentsFlag, profile, skipDoctor, yes)
		},
	}

	cmd.Flags().StringVar(&agentsFlag, "agents", "", "Comma-separated agents to configure (claude-code,codex,cline,openclaw,copilot,antigravity,cursor,aider,windsurf,none)")
	cmd.Flags().StringVar(&profile, "profile", "", "Policy profile for initialization (default: standard)")
	cmd.Flags().BoolVar(&skipDoctor, "skip-doctor", false, "skip final health check summary")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "accepted for non-interactive script compatibility")
	return cmd
}

func runQuickstart(cmd *cobra.Command, rootOpts *rootOptions, agentsFlag, profile string, skipDoctor, yes bool) error {
	w := cmd.OutOrStdout()
	_ = yes // Retained as a no-op compatibility flag for existing scripts.
	if err := prepareManagedProtection(rootOpts); err != nil {
		return err
	}

	fmt.Fprintln(w, "◆ Rampart quickstart")
	fmt.Fprintln(w, "  Compatibility mode: new installations should use `rampart protect`.")
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
	drivers, unsupported, err := quickstartProtectionTargets(selectedAgents)
	if err != nil {
		return err
	}

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
		if err := runQuickstartInitProfile(cmd, rootOpts, selectedProfile); err != nil {
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

	for _, agent := range unsupported {
		fmt.Fprintf(w, "  ⚠ %s detected but native setup is not yet supported\n", agent.Name)
		fmt.Fprintf(w, "    → Cooperative fallback: %s\n", agent.WrapCmd)
	}
	if len(selectedAgents) == 0 {
		fmt.Fprintln(w, "  ⚠ No agents selected; configuring policy and service only")
	}

	summary, err := runProtectionPlan(cmd, rootOpts, drivers, protectionPlanOptions{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("quickstart did not protect every selected native integration: %w", err)
	}

	fmt.Fprintln(w)
	if summary.Succeeded > 0 {
		fmt.Fprintf(w, "◆ Rampart protection verified for %d agent(s).\n", summary.Succeeded)
	} else {
		fmt.Fprintln(w, "◆ Rampart policy and service setup complete; no native agent boundary was selected.")
	}
	if !skipDoctor {
		fmt.Fprintln(w, "\nCurrent protection status:")
		if err := runStatus(w, false); err != nil {
			return fmt.Errorf("quickstart status: %w", err)
		}
	}

	fmt.Fprintln(w, "\n  Next steps:")
	fmt.Fprintln(w, "    • rampart status       — see protection and assurance state")
	fmt.Fprintln(w, "    • rampart watch        — see decisions in real time")
	fmt.Fprintln(w, "    • Docs: https://docs.rampart.sh")

	return nil
}

func runQuickstartInitProfile(parent *cobra.Command, rootOpts *rootOptions, profile string) error {
	initCmd := newInitCmd(rootOpts)
	initCmd.SetContext(parent.Context())
	initCmd.SetIn(parent.InOrStdin())
	initCmd.SetOut(parent.OutOrStdout())
	initCmd.SetErr(parent.ErrOrStderr())
	if err := initCmd.Flags().Set("profile", profile); err != nil {
		return err
	}
	if initCmd.RunE == nil {
		return fmt.Errorf("init command has no implementation")
	}
	return initCmd.RunE(initCmd, nil)
}

func quickstartProtectionTargets(selected []quickstartAgent) (drivers []integrationDriver, unsupported []quickstartAgent, err error) {
	for _, agent := range selected {
		if !agent.HasSetup {
			unsupported = append(unsupported, agent)
			continue
		}
		driver, ok := findIntegrationDriver(agent.SetupCmd)
		if !ok || !driver.AutoProtect {
			return nil, unsupported, fmt.Errorf("quickstart: no managed protection driver registered for %s", agent.Name)
		}
		if !integrationDriverSupportsPlatform(driver, runtime.GOOS) {
			return nil, unsupported, fmt.Errorf("quickstart: %s is not supported on %s", driver.DisplayName, runtime.GOOS)
		}
		drivers = append(drivers, driver)
	}
	return drivers, unsupported, nil
}

func selectQuickstartAgents(result *detect.DetectResult, agentsFlag string) ([]quickstartAgent, error) {
	override := strings.TrimSpace(agentsFlag)

	selectedKeys, err := parseAgentOverride(override)
	if err != nil {
		return nil, err
	}
	// `none` is an explicit opt-out, not an empty autodetection result. Keep it
	// distinct from an omitted --agents flag so quickstart never installs hooks
	// the user expressly declined.
	if strings.EqualFold(override, "none") {
		return []quickstartAgent{}, nil
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
	case "antigravity":
		return result.HasAntigravity
	default:
		return false
	}
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
		// custom.yaml is an empty managed placeholder. guard.yaml is a supplemental
		// layer with no default_action. Neither is a complete base profile, so a
		// home containing only these files still needs standard/openclaw auto-init.
		if name == "custom.yaml" || name == "guard.yaml" {
			continue
		}
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			return true
		}
	}
	return false
}
