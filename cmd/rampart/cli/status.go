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
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show Rampart protection status",
		Long:  "Display a quick dashboard of Rampart protection status, mode, and today's events.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd.OutOrStdout())
		},
	}
}

func runStatus(w io.Writer) error {
	protected := detectProtectedAgents()
	mode, defaultAction := detectMode()
	allow, deny, pending, lastDeny := todayEvents()
	serverRunning := isServeRunningLocal()
	hookOnly := isHookBasedOnly(protected)

	useColor := !noColor() && isTerminal(os.Stdout)

	box := buildStatusBox(protected, mode, defaultAction, allow, deny, pending, serverRunning, hookOnly, lastDeny, useColor)
	fmt.Fprintln(w, box)

	printStatusHints(w, serverRunning, protected, allow, deny, pending)
	return nil
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

	protectedStr := "None — run 'rampart setup' to protect an agent"
	if len(protected) > 0 {
		protectedStr = strings.Join(protected, ", ")
	}
	protectedLine := lbl("Protected") + protectedStr

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
	var agents []string
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	// Claude Code hooks
	claudeSettings := filepath.Join(home, ".claude", "settings.json")
	if data, err := os.ReadFile(claudeSettings); err == nil {
		var settings map[string]any
		if json.Unmarshal(data, &settings) == nil {
			if countClaudeHookMatchers(settings) > 0 {
				agents = append(agents, "Claude Code (hooks)")
			}
		}
	}

	// Cline hooks
	clineDir := filepath.Join(home, "Documents", "Cline", "Hooks")
	if entries, err := os.ReadDir(clineDir); err == nil && len(entries) > 0 {
		agents = append(agents, "Cline (hooks)")
	}

	// OpenClaw: prefer the native plugin only when it's actually configured to load.
	openclawDropIn := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d", "rampart.conf")
	openclawShim := filepath.Join(home, ".local", "bin", "rampart-shim")
	openclawConfig := filepath.Join(home, ".openclaw", "openclaw.json")
	if isOpenClawPluginConfigured() {
		agents = append(agents, "OpenClaw (plugin)")
	} else if _, err := os.Stat(openclawDropIn); err == nil {
		agents = append(agents, "OpenClaw (preload+bridge)")
	} else if _, err := os.Stat(openclawShim); err == nil {
		agents = append(agents, "OpenClaw (shim+bridge)")
	} else if data, err := os.ReadFile(openclawConfig); err == nil {
		if hasLegacyOpenClawBridgeConfig(data) {
			agents = append(agents, "OpenClaw (bridge)")
		}
	}

	// Codex wrapper installed by `rampart setup codex`.
	codexWrapper := filepath.Join(home, ".local", "bin", "codex")
	if data, err := os.ReadFile(codexWrapper); err == nil && containsRampartPreload(string(data)) {
		agents = append(agents, "Codex (wrapper)")
	}

	return agents
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
// "pending" counts require_approval and webhook actions.
func todayEvents() (allow, deny, pending int, lastDeny *audit.Event) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	auditDir := filepath.Join(home, ".rampart", "audit")

	today := time.Now().UTC().Format("2006-01-02")

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
			case "require_approval", "webhook":
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
