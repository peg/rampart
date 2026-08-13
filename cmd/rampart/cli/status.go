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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newStatusCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show Rampart protection status",
		Long:  "Display a quick dashboard of Rampart protection status, mode, and today's events.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd.OutOrStdout(), jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output status as JSON")
	return cmd
}

const statusSchemaVersion = "rampart.status.v1"

type statusSnapshot struct {
	generatedAt   time.Time
	buildVersion  string
	protected     []string
	integrations  []integrationAssuranceStatus
	mode          string
	defaultAction string
	serverRunning bool
	hookOnly      bool
	allow         int
	deny          int
	pending       int
	lastDeny      *audit.Event
}

type statusJSONOutput struct {
	SchemaVersion string                       `json:"schema_version"`
	GeneratedAt   time.Time                    `json:"generated_at"`
	BuildVersion  string                       `json:"build_version"`
	Protected     []string                     `json:"protected_agents"`
	Integrations  []integrationAssuranceStatus `json:"integrations"`
	Mode          string                       `json:"mode"`
	DefaultAction string                       `json:"default_action"`
	ServerRunning bool                         `json:"server_running"`
	HookOnly      bool                         `json:"hook_only"`
	Today         statusTodayJSON              `json:"today"`
	LastDeny      *statusLastDenyJSON          `json:"last_deny,omitempty"`
}

type statusTodayJSON struct {
	Allow   int `json:"allow"`
	Deny    int `json:"deny"`
	Pending int `json:"pending"`
}

type statusLastDenyJSON struct {
	Timestamp time.Time `json:"timestamp"`
	Tool      string    `json:"tool"`
	Command   string    `json:"command,omitempty"`
}

func runStatus(w io.Writer, jsonOut bool) error {
	snapshot := collectStatusSnapshot(time.Now().UTC())
	if jsonOut {
		return writeStatusJSON(w, snapshot)
	}

	useColor := !noColor() && isTerminal(os.Stdout)

	box := buildStatusBox(
		snapshot.protected,
		snapshot.mode,
		snapshot.defaultAction,
		snapshot.allow,
		snapshot.deny,
		snapshot.pending,
		snapshot.serverRunning,
		snapshot.hookOnly,
		snapshot.lastDeny,
		useColor,
	)
	fmt.Fprintln(w, box)
	printIntegrationAssurance(w, snapshot.integrations, snapshot.generatedAt)

	printStatusHints(w, snapshot.serverRunning, snapshot.protected, snapshot.allow, snapshot.deny, snapshot.pending)
	return nil
}

func collectStatusSnapshot(generatedAt time.Time) statusSnapshot {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	protected := detectProtectedAgents()
	serverRunning := isServeRunningLocal()
	mode, defaultAction := detectMode()
	allow, deny, pending, lastDeny := todayEventsAt(generatedAt)
	return statusSnapshot{
		generatedAt:   generatedAt,
		buildVersion:  build.Version,
		protected:     protected,
		integrations:  collectIntegrationAssuranceStatuses(generatedAt, serverRunning),
		mode:          mode,
		defaultAction: defaultAction,
		serverRunning: serverRunning,
		hookOnly:      isHookBasedOnly(protected),
		allow:         allow,
		deny:          deny,
		pending:       pending,
		lastDeny:      lastDeny,
	}
}

func writeStatusJSON(w io.Writer, snapshot statusSnapshot) error {
	protected := snapshot.protected
	if protected == nil {
		protected = []string{}
	}
	integrations := snapshot.integrations
	if integrations == nil {
		integrations = []integrationAssuranceStatus{}
	}

	out := statusJSONOutput{
		SchemaVersion: statusSchemaVersion,
		GeneratedAt:   snapshot.generatedAt,
		BuildVersion:  snapshot.buildVersion,
		Protected:     protected,
		Integrations:  integrations,
		Mode:          snapshot.mode,
		DefaultAction: snapshot.defaultAction,
		ServerRunning: snapshot.serverRunning,
		HookOnly:      snapshot.hookOnly,
		Today: statusTodayJSON{
			Allow:   snapshot.allow,
			Deny:    snapshot.deny,
			Pending: snapshot.pending,
		},
	}

	if snapshot.lastDeny != nil {
		last := &statusLastDenyJSON{
			Timestamp: snapshot.lastDeny.Timestamp,
			Tool:      snapshot.lastDeny.Tool,
		}
		if command := extractEventCommand(snapshot.lastDeny); !isUnknownOrEmpty(command) {
			last.Command = command
		}
		out.LastDeny = last
	}

	enc := json.NewEncoder(w)
	return enc.Encode(out)
}

// Box dimensions.
const (
	statusBoxTotal = 65 // total visual width including │ borders
	statusBoxFrame = 63 // dashes between corner chars (= statusBoxTotal - 2)
	statusContentW = 61 // visual content width between "│ " and " │"
	statusLabelCol = 14 // visual chars from start of content to value column
)

// renderProgressBar renders a progress bar like "███████░░░" (0–100 pct, `width` segments).
func renderProgressBar(pct, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := pct * width / 100
	empty := width - filled
	return strings.Repeat("█", filled) + strings.Repeat("░", empty)
}

// isServeRunningLocal returns true if rampart serve is reachable.
// Uses resolveServeURL (state file → env → default), then tries common alternative ports.
func isServeRunningLocal() bool {
	// Primary: resolved URL (state file, env, default).
	if isServeRunning(resolveServeURL("")) {
		return true
	}
	// Try common alternative ports (proxy port, common dev ports).
	for _, port := range []int{defaultServePort, 9091, 8090} {
		if isServeRunning(fmt.Sprintf("http://localhost:%d", port)) {
			return true
		}
	}
	return false
}

// buildStatusBox renders the full status panel.
func buildStatusBox(
	protected []string,
	mode, defaultAction string,
	allow, deny, pending int,
	serverRunning bool,
	hookOnly bool,
	lastDeny *audit.Event,
	useColor bool,
) string {
	// Lipgloss styles – only applied when useColor is true.
	accentSt := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6392")).Bold(true)
	successSt := lipgloss.NewStyle().Foreground(lipgloss.Color("#22c55e"))
	dangerSt := lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444"))
	warnSt := lipgloss.NewStyle().Foreground(lipgloss.Color("#f59e0b"))
	faintSt := lipgloss.NewStyle().Faint(true)
	_ = warnSt

	styled := func(s string, st lipgloss.Style) string {
		if !useColor {
			return s
		}
		return st.Render(s)
	}

	// Box frame lines.
	top := "╭" + strings.Repeat("─", statusBoxFrame) + "╮"
	sep := "├" + strings.Repeat("─", statusBoxFrame) + "┤"
	bot := "╰" + strings.Repeat("─", statusBoxFrame) + "╯"

	// row wraps content in box borders, padding to statusContentW.
	row := func(content string) string {
		vw := lipgloss.Width(content)
		pad := statusContentW - vw
		if pad < 0 {
			pad = 0
		}
		return "│ " + content + strings.Repeat(" ", pad) + " │"
	}

	// lbl returns a label of fixed visual width (statusLabelCol chars from left),
	// styled faint, with leading indent.
	lbl := func(s string) string {
		lw := len(s) // safe: labels are plain ASCII
		pad := statusLabelCol - 2 - lw
		if pad < 0 {
			pad = 0
		}
		return "  " + styled(s, faintSt) + strings.Repeat(" ", pad)
	}

	// ── Header ──────────────────────────────────────────────────────────────

	version := build.Version
	if version != "" && version != "dev" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	shieldTitle := styled("🛡️  RAMPART", accentSt)
	verStr := styled(version, faintSt)
	stw := lipgloss.Width(shieldTitle)
	vw2 := lipgloss.Width(verStr)
	// "  " (2) + shieldTitle + gap + verStr fits inside statusContentW.
	gap := statusContentW - 2 - stw - vw2
	if gap < 1 {
		gap = 1
	}
	headerContent := "  " + shieldTitle + strings.Repeat(" ", gap) + verStr

	// ── Status ──────────────────────────────────────────────────────────────

	var dotStr, statusVal string
	if serverRunning {
		dotStr = styled("●", successSt)
		statusVal = "Running"
	} else if hookOnly {
		dotStr = styled("◐", successSt)
		statusVal = "Hooks active (serve optional)"
	} else {
		dotStr = styled("○", dangerSt)
		statusVal = "Not running"
	}
	statusLine := lbl("Status") + dotStr + " " + statusVal

	// ── Protected ───────────────────────────────────────────────────────────

	protectedStr := "None — run 'rampart protect' to protect detected agents"
	if len(protected) > 0 {
		protectedStr = strings.Join(protected, ", ")
	}
	protectedLine := lbl("Configured") + protectedStr

	// ── Mode ────────────────────────────────────────────────────────────────

	modeStr := mode
	if defaultAction != "" {
		modeStr = mode + " (default: " + defaultAction + ")"
	}
	modeLine := lbl("Mode") + modeStr

	// ── Today's stats ───────────────────────────────────────────────────────

	total := allow + deny + pending
	pct := 0
	if total > 0 {
		pct = allow * 100 / total
	}

	bar := renderProgressBar(pct, 10)
	barStyled := styled(bar, successSt)
	todayLine := lbl("Today") + barStyled + fmt.Sprintf("  %d%% allowed", pct)

	allowStr := styled(fmt.Sprintf("%d allow", allow), successSt)
	denyStr := styled(fmt.Sprintf("%d deny", deny), dangerSt)
	countsLine := strings.Repeat(" ", statusLabelCol) +
		allowStr + " · " + denyStr + fmt.Sprintf(" · %d pending", pending)

	// ── Last deny (optional) ─────────────────────────────────────────────────

	var lastDenyLine string
	if lastDeny != nil {
		ago := formatAgo(time.Since(lastDeny.Timestamp))
		cmd := extractEventCommand(lastDeny)
		if !isUnknownOrEmpty(cmd) {
			lastDenyLine = lbl("Last deny") + styled(ago, faintSt) + " — " + cmd
		}
	}

	// ── Assemble ────────────────────────────────────────────────────────────

	var sb strings.Builder
	sb.WriteString(top + "\n")
	sb.WriteString(row(headerContent) + "\n")
	sb.WriteString(sep + "\n")
	sb.WriteString(row(statusLine) + "\n")
	sb.WriteString(row(protectedLine) + "\n")
	sb.WriteString(row(modeLine) + "\n")
	sb.WriteString(row(todayLine) + "\n")
	sb.WriteString(row(countsLine) + "\n")
	if lastDenyLine != "" {
		sb.WriteString(row(lastDenyLine) + "\n")
	}
	sb.WriteString(bot)

	return sb.String()
}

func detectProtectedAgents() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	agents := make([]string, 0, len(supportedIntegrationDrivers()))
	for _, driver := range supportedIntegrationDrivers() {
		if label := integrationProtectionState(driver, home); label != "" {
			agents = append(agents, label)
		}
	}
	return agents
}

func openClawProtectionState(home string) string {
	openclawDropIn := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d", "rampart.conf")
	openclawShim := filepath.Join(home, ".local", "bin", "rampart-shim")
	openclawConfig := filepath.Join(home, ".openclaw", "openclaw.json")
	if isOpenClawPluginConfigured() {
		return "OpenClaw (plugin)"
	}
	if _, err := os.Stat(openclawDropIn); err == nil {
		return "OpenClaw (preload+bridge)"
	}
	if _, err := os.Stat(openclawShim); err == nil {
		return "OpenClaw (shim+bridge)"
	}
	if data, err := os.ReadFile(openclawConfig); err == nil && hasLegacyOpenClawBridgeConfig(data) {
		return "OpenClaw (bridge)"
	}
	return ""
}

func codexProtectionState(home string) string {
	if codexHooksConfiguredForHome(home) {
		return "Codex (hooks)"
	}
	codexWrapper := filepath.Join(home, ".local", "bin", "codex")
	if data, err := os.ReadFile(codexWrapper); err == nil && containsRampartPreload(string(data)) {
		return "Codex (legacy wrapper)"
	}
	return ""
}

type hermesPluginState struct {
	Installed     bool
	Enabled       bool
	ConfigPresent bool
	ManifestValid bool
	HookDeclared  bool
	Version       string
	PluginDir     string
}

type hermesConfigFile struct {
	Plugins hermesConfigPlugins `yaml:"plugins"`
}

type hermesConfigPlugins struct {
	Enabled  []string                      `yaml:"enabled"`
	Disabled []string                      `yaml:"disabled"`
	Entries  map[string]hermesPluginConfig `yaml:"entries"`
}

type hermesPluginConfig struct {
	Enabled *bool `yaml:"enabled"`
}

func detectHermesPluginState() hermesPluginState {
	home, err := os.UserHomeDir()
	if err != nil {
		return hermesPluginState{}
	}
	return detectHermesPluginStateForHome(home)
}

func detectHermesPluginStateForHome(home string) hermesPluginState {
	hermesHome := hermesHomeDir(home)
	state := hermesPluginState{PluginDir: filepath.Join(hermesHome, "plugins", "rampart")}
	manifestPath := filepath.Join(state.PluginDir, "plugin.yaml")
	data, err := os.ReadFile(manifestPath)
	if err == nil {
		state.Installed = true
		var manifest hermesPluginManifest
		if yaml.Unmarshal(data, &manifest) == nil {
			state.ManifestValid = strings.TrimSpace(manifest.Name) == "rampart"
			state.Version = strings.TrimSpace(manifest.Version)
			for _, hook := range manifest.ProvidesHooks {
				if strings.TrimSpace(hook) == "pre_tool_call" {
					state.HookDeclared = true
					break
				}
			}
		}
	}

	configPath := filepath.Join(hermesHome, "config.yaml")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return state
	}
	state.ConfigPresent = true

	var cfg hermesConfigFile
	if yaml.Unmarshal(configData, &cfg) != nil {
		return state
	}
	if stringListContains(cfg.Plugins.Disabled, "rampart") {
		state.Enabled = false
		return state
	}
	if stringListContains(cfg.Plugins.Enabled, "rampart") {
		state.Enabled = true
	}
	if entry, ok := cfg.Plugins.Entries["rampart"]; ok && entry.Enabled != nil {
		state.Enabled = *entry.Enabled
	}
	return state
}

func stringListContains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func hasLegacyOpenClawBridgeConfig(data []byte) bool {
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	for _, key := range []string{"rampart", "rampartBridge", "rampart_bridge", "rampartUrl", "rampart_url"} {
		if _, ok := cfg[key]; ok {
			return true
		}
	}
	return false
}

func detectMode() (string, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown", "unknown"
	}
	policyDir := filepath.Join(home, ".rampart", "policies")

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return "unknown", "unknown"
	}

	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		store := engine.NewFileStore(filepath.Join(policyDir, e.Name()))
		cfg, err := store.Load()
		if err != nil {
			continue
		}
		da := cfg.DefaultAction
		if da == "" {
			da = "deny"
		}
		mode := "enforce"
		if da == "allow" {
			mode = "monitor"
		}
		return mode, da
	}
	return "unknown", "unknown"
}

// todayEvents returns today's allow/deny/pending counts and the most recent deny event.
// "pending" counts current ask, legacy require_approval, and webhook actions.
func todayEvents() (allow, deny, pending int, lastDeny *audit.Event) {
	return todayEventsAt(time.Now().UTC())
}

func todayEventsAt(now time.Time) (allow, deny, pending int, lastDeny *audit.Event) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	auditDir := filepath.Join(home, ".rampart", "audit")

	if now.IsZero() {
		now = time.Now().UTC()
	}
	today := now.UTC().Format("2006-01-02")

	seen := make(map[string]bool)
	var candidates []string
	if entries, err := os.ReadDir(auditDir); err == nil {
		for _, e := range entries {
			if strings.Contains(e.Name(), today) && strings.HasSuffix(e.Name(), ".jsonl") {
				p := filepath.Join(auditDir, e.Name())
				if !seen[p] {
					seen[p] = true
					candidates = append(candidates, p)
				}
			}
		}
	}

	for _, path := range candidates {
		events, _, err := audit.ReadEventsFromOffset(path, 0)
		if err != nil {
			continue
		}
		for i := range events {
			ev := &events[i]
			switch ev.Decision.Action {
			case "allow":
				allow++
			case "deny":
				deny++
				if lastDeny == nil || ev.Timestamp.After(lastDeny.Timestamp) {
					lastDeny = ev
				}
			case "ask", "require_approval", "webhook":
				pending++
			}
		}
	}
	return
}

func extractEventCommand(ev *audit.Event) string {
	if ev == nil {
		return ""
	}
	for _, key := range []string{"command", "cmd", "input"} {
		if v, ok := ev.Request[key]; ok {
			if s, ok := v.(string); ok {
				if len(s) > 60 {
					return s[:57] + "..."
				}
				return s
			}
		}
	}
	return ev.Tool
}

func formatAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func isUnknownOrEmpty(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "" || normalized == "unknown" || normalized == "(unknown)"
}
