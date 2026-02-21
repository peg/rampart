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

// Package watch provides the live terminal dashboard for audit events.
package watch

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/peg/rampart/internal/audit"
)

// formatDuration renders a duration as Xm Ys.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

type tailerMsg struct {
	event audit.Event
	err   error
}

type tickMsg time.Time

// approvalsMsg carries the result of polling the approval API.
type approvalsMsg struct {
	approvals []PendingApproval
	err       error
}

// resolveResultMsg carries the result of resolving an approval.
type resolveResultMsg struct {
	id       string
	approved bool
	err      error
}

// Config holds settings for the watch TUI.
type Config struct {
	AuditFile  string
	PolicyName string
	Mode       string
	Agent      string
	Decision   string // Filter: only show this decision (allow/deny/log/webhook).
	Tool       string // Filter: only show this tool name.
	Out        io.Writer

	// ServeURL is the base URL for the serve API (optional).
	// When set, watch polls for pending approvals.
	ServeURL string

	// ServeToken is the Bearer token for the serve API.
	ServeToken string
}

// Stats tracks running totals of decisions.
type Stats struct {
	Total   int
	Allow   int
	Deny    int
	Log     int
	Webhook int
}

// Model is the bubbletea model for the watch TUI.
type Model struct {
	cfg       Config
	startedAt time.Time
	width     int
	height    int
	events    []audit.Event
	scroll    int
	stats     Stats
	lastErr   error
	tailer    *fileTailer
	tailerCh  <-chan tailerEvent

	// denyFlash tracks event indices that should flash (deny highlight).
	denyFlash map[int]time.Time

	// Interactive approval support.
	approvalClient   *ApprovalClient
	pendingApprovals []PendingApproval
	selectedApproval int // 1-indexed; 0 = none selected
	approvalErr      error
	resolveStatus    string // transient status message

	frameStyle      lipgloss.Style
	headerStyle     lipgloss.Style
	sectionStyle    lipgloss.Style
	allowStyle      lipgloss.Style
	denyStyle       lipgloss.Style
	logStyle        lipgloss.Style
	webhookStyle    lipgloss.Style
	denyBgStyle     lipgloss.Style
	mutedStyle      lipgloss.Style
	statusLineStyle lipgloss.Style
	pendingStyle    lipgloss.Style
}

// NewModel creates a new watch TUI model.
func NewModel(cfg Config) *Model {
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = "enforce"
	}
	if strings.TrimSpace(cfg.PolicyName) == "" {
		cfg.PolicyName = "(unspecified)"
	}
	if strings.TrimSpace(cfg.Agent) == "" {
		cfg.Agent = "all"
	}

	m := &Model{
		cfg:       cfg,
		startedAt: time.Now(),
		width:     80,
		height:    24,
		events:    make([]audit.Event, 0, 64),
		denyFlash: make(map[int]time.Time),
		tailer:    newFileTailer(cfg.AuditFile),
		frameStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("7")),
		headerStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("14")),
		sectionStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12")),
		allowStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		denyStyle:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")),
		logStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		webhookStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("14")),
		denyBgStyle:  lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")).Background(lipgloss.Color("52")),
		mutedStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
		statusLineStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("7")),
		pendingStyle: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11")),
	}

	if strings.TrimSpace(cfg.ServeURL) != "" {
		m.approvalClient = NewApprovalClient(cfg.ServeURL, cfg.ServeToken)
	}

	return m
}

// Run starts the watch TUI.
func Run(ctx context.Context, cfg Config) error {
	model := NewModel(cfg)
	model.tailerCh = model.tailer.start(ctx)
	opts := []tea.ProgramOption{tea.WithContext(ctx), tea.WithAltScreen()}
	if cfg.Out != nil {
		opts = append(opts, tea.WithOutput(cfg.Out))
	}
	p := tea.NewProgram(model, opts...)
	_, err := p.Run()
	return err
}

func (m *Model) Init() tea.Cmd {
	cmds := []tea.Cmd{waitForTailer(m.tailerCh), tickCmd()}
	if m.approvalClient != nil {
		cmds = append(cmds, m.pollApprovals())
	}
	return tea.Batch(cmds...)
}

func (m *Model) pollApprovals() tea.Cmd {
	client := m.approvalClient
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		approvals, err := client.ListPending(ctx)
		return approvalsMsg{approvals: approvals, err: err}
	}
}

func (m *Model) pollApprovalsAfterDelay() tea.Cmd {
	client := m.approvalClient
	return func() tea.Msg {
		time.Sleep(time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		approvals, err := client.ListPending(ctx)
		return approvalsMsg{approvals: approvals, err: err}
	}
}

func (m *Model) resolveApproval(id string, approved bool, persist bool) tea.Cmd {
	client := m.approvalClient
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := client.Resolve(ctx, id, approved, persist)
		return resolveResultMsg{id: id, approved: approved, err: err}
	}
}

func waitForTailer(ch <-chan tailerEvent) tea.Cmd {
	return func() tea.Msg {
		evt, ok := <-ch
		if !ok {
			return nil
		}
		return tailerMsg{event: evt.event, err: evt.err}
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := msg.(type) {
	case tea.KeyMsg:
		switch typed.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "j", "down":
			maxScroll := max(0, len(m.events)-1)
			if m.scroll < maxScroll {
				m.scroll++
			}
		case "k", "up":
			if m.scroll > 0 {
				m.scroll--
			}
		case "g":
			m.scroll = 0
		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			if m.approvalClient != nil {
				num := int(typed.String()[0] - '0')
				if num >= 1 && num <= len(m.pendingApprovals) {
					m.selectedApproval = num
				}
			}
		case "a":
			if m.approvalClient != nil && m.selectedApproval >= 1 && m.selectedApproval <= len(m.pendingApprovals) {
				a := m.pendingApprovals[m.selectedApproval-1]
				m.resolveStatus = fmt.Sprintf("Approving %s...", a.ID)
				return m, m.resolveApproval(a.ID, true, false)
			}
		case "d":
			if m.approvalClient != nil && m.selectedApproval >= 1 && m.selectedApproval <= len(m.pendingApprovals) {
				a := m.pendingApprovals[m.selectedApproval-1]
				m.resolveStatus = fmt.Sprintf("Denying %s...", a.ID)
				return m, m.resolveApproval(a.ID, false, false)
			}
		case "A":
			// Approve + persist: creates an auto-allow rule for future matching calls.
			if m.approvalClient != nil && m.selectedApproval >= 1 && m.selectedApproval <= len(m.pendingApprovals) {
				a := m.pendingApprovals[m.selectedApproval-1]
				m.resolveStatus = fmt.Sprintf("Approving (always) %s...", a.ID)
				return m, m.resolveApproval(a.ID, true, true)
			}
		}
	case tea.WindowSizeMsg:
		if typed.Width > 0 {
			m.width = typed.Width
		}
		if typed.Height > 0 {
			m.height = typed.Height
		}
	case tailerMsg:
		if typed.err != nil {
			m.lastErr = typed.err
			return m, waitForTailer(m.tailerCh)
		}

		if m.cfg.Agent != "all" && !strings.EqualFold(strings.TrimSpace(typed.event.Agent), strings.TrimSpace(m.cfg.Agent)) {
			return m, waitForTailer(m.tailerCh)
		}

		// Always count stats before display filtering.
		m.updateStats(typed.event)

		action := strings.ToLower(strings.TrimSpace(typed.event.Decision.Action))
		tool := strings.ToLower(strings.TrimSpace(typed.event.Tool))

		// Apply decision filter.
		if m.cfg.Decision != "" && !strings.EqualFold(m.cfg.Decision, action) {
			return m, waitForTailer(m.tailerCh)
		}
		// Apply tool filter.
		if m.cfg.Tool != "" && !strings.EqualFold(m.cfg.Tool, tool) {
			return m, waitForTailer(m.tailerCh)
		}

		// Shift deny flash indices since we prepend at index 0.
		newFlash := make(map[int]time.Time, len(m.denyFlash)+1)
		for idx, t := range m.denyFlash {
			newFlash[idx+1] = t
		}
		m.denyFlash = newFlash

		m.events = append([]audit.Event{typed.event}, m.events...)
		m.events = trimEvents(m.events)

		if action == "deny" || action == "denied" {
			m.denyFlash[0] = time.Now()
		}

		return m, waitForTailer(m.tailerCh)
	case approvalsMsg:
		if typed.err != nil {
			m.approvalErr = typed.err
		} else {
			m.approvalErr = nil
			m.pendingApprovals = typed.approvals
			// Reset selection if out of range.
			if m.selectedApproval > len(m.pendingApprovals) {
				m.selectedApproval = 0
			}
		}
		if m.approvalClient != nil {
			return m, m.pollApprovalsAfterDelay()
		}
		return m, nil

	case resolveResultMsg:
		if typed.err != nil {
			m.resolveStatus = fmt.Sprintf("Error: %v", typed.err)
		} else {
			action := "Denied"
			if typed.approved {
				action = "Approved"
			}
			m.resolveStatus = fmt.Sprintf("%s %s", action, typed.id)
			m.selectedApproval = 0
		}
		// Immediately re-poll.
		if m.approvalClient != nil {
			return m, m.pollApprovals()
		}
		return m, nil

	case tickMsg:
		// Clean up expired deny flashes (must be in Update, not View).
		now := time.Now()
		for idx, t := range m.denyFlash {
			if now.Sub(t) >= 3*time.Second {
				delete(m.denyFlash, idx)
			}
		}
		return m, tickCmd()
	}

	return m, nil
}

func (m *Model) updateStats(event audit.Event) {
	m.stats.Total++
	switch strings.ToLower(strings.TrimSpace(event.Decision.Action)) {
	case "allow", "approved", "always_allowed":
		m.stats.Allow++
	case "deny", "denied":
		m.stats.Deny++
	case "watch", "log":
		m.stats.Log++
	case "webhook":
		m.stats.Webhook++
	}
}

func (m *Model) View() string {
	innerWidth := max(20, m.width-4)
	feedRows := max(5, m.height-8)
	now := time.Now()
	uptime := now.Sub(m.startedAt).Round(time.Second)

	// Summary bar with colored counters.
	summaryLine := fmt.Sprintf("\U0001f6e1\ufe0f  Rampart Watch | %s | %s \u00b7 %s \u00b7 %s",
		m.cfg.Mode,
		m.allowStyle.Render(fmt.Sprintf("%d allow", m.stats.Allow)),
		m.denyStyle.Render(fmt.Sprintf("%d deny", m.stats.Deny)),
		m.logStyle.Render(fmt.Sprintf("%d log", m.stats.Log)),
	)
	if m.stats.Webhook > 0 {
		summaryLine += " \u00b7 " + m.webhookStyle.Render(fmt.Sprintf("%d webhook", m.stats.Webhook))
	}
	summaryLine += fmt.Sprintf(" | uptime: %s", formatUptime(uptime))

	lines := make([]string, 0, m.height)
	lines = append(lines, frameLineTop(innerWidth))
	lines = append(lines, frameLineBody(innerWidth, "  "+summaryLine))

	// Pending approvals section.
	approvalLines := 0
	if len(m.pendingApprovals) > 0 {
		lines = append(lines, frameLineMid(innerWidth))
		lines = append(lines, frameLineBody(innerWidth, m.pendingStyle.Render("  ┌─ PENDING APPROVALS ─────────────────────────────────────┐")))
		for i, a := range m.pendingApprovals {
			remaining := time.Until(a.ExpiresAt).Round(time.Second)
			if remaining < 0 {
				remaining = 0
			}
			num := i + 1
			sel := " "
			if num == m.selectedApproval {
				sel = ">"
			}
			line1 := fmt.Sprintf("  │ %s[%d] %s: %s  [%s]",
				sel, num, a.Tool, truncateRunes(a.Command, innerWidth-30), truncateRunes(a.Message, 30))
			line2 := fmt.Sprintf("  │     ⏳ %s remaining — (a)pprove (d)eny (A)lways allow", formatDuration(remaining))

			if num == m.selectedApproval {
				lines = append(lines, frameLineBody(innerWidth, m.pendingStyle.Render(truncateRunes(line1, innerWidth-2))))
				lines = append(lines, frameLineBody(innerWidth, m.pendingStyle.Render(truncateRunes(line2, innerWidth-2))))
			} else {
				lines = append(lines, frameLineBody(innerWidth, truncateRunes(line1, innerWidth-2)))
				lines = append(lines, frameLineBody(innerWidth, m.mutedStyle.Render(truncateRunes(line2, innerWidth-2))))
			}
		}
		lines = append(lines, frameLineBody(innerWidth, m.pendingStyle.Render("  └─────────────────────────────────────────────────────────┘")))
		approvalLines = 3 + len(m.pendingApprovals)*2 // header + footer + 2 per approval
	}
	if m.resolveStatus != "" {
		lines = append(lines, frameLineBody(innerWidth, "  "+m.allowStyle.Render(m.resolveStatus)))
		approvalLines++
	}

	lines = append(lines, frameLineMid(innerWidth))
	lines = append(lines, frameLineBody(innerWidth, m.sectionStyle.Render("  LIVE FEED")))
	_ = approvalLines

	visible := m.visibleEvents(feedRows)
	for i, event := range visible {
		globalIdx := m.scroll + i
		line := formatEventLineWithRelTime(event, innerWidth-4, now)
		action := strings.ToLower(strings.TrimSpace(event.Decision.Action))

		// Deny flash: highlight with background for 3 seconds.
		if action == "deny" {
			if flashTime, ok := m.denyFlash[globalIdx]; ok && now.Sub(flashTime) < 3*time.Second {
				lines = append(lines, frameLineBody(innerWidth, "  "+m.denyBgStyle.Render(line)))
				continue
			}
		}

		colorLine := m.colorizeLine(line, event.Decision.Action)
		lines = append(lines, frameLineBody(innerWidth, "  "+colorLine))
	}
	for len(visible) < feedRows {
		lines = append(lines, frameLineBody(innerWidth, ""))
		visible = append(visible, audit.Event{})
	}

	lines = append(lines, frameLineMid(innerWidth))
	status := fmt.Sprintf("POLICIES: %s | AGENT: %s", m.cfg.PolicyName, m.cfg.Agent)
	if m.cfg.Decision != "" {
		status += fmt.Sprintf(" | FILTER: decision=%s", m.cfg.Decision)
	}
	if m.cfg.Tool != "" {
		status += fmt.Sprintf(" | FILTER: tool=%s", m.cfg.Tool)
	}
	lines = append(lines, frameLineBody(innerWidth, "  "+m.statusLineStyle.Render(truncateRunes(status, innerWidth-2))))

	if m.lastErr != nil {
		errLine := "TAILER: " + m.lastErr.Error()
		lines = append(lines, frameLineBody(innerWidth, "  "+m.mutedStyle.Render(truncateRunes(errLine, innerWidth-2))))
	}

	lines = append(lines, frameLineBottom(innerWidth))

	return m.frameStyle.Render(strings.Join(lines, "\n"))
}

func policiesLoadedFromEvents(events []audit.Event) int {
	set := map[string]struct{}{}
	for _, evt := range events {
		for _, name := range evt.Decision.MatchedPolicies {
			set[name] = struct{}{}
		}
	}
	return len(set)
}

func (m *Model) visibleEvents(rows int) []audit.Event {
	if rows <= 0 || len(m.events) == 0 {
		return nil
	}
	start := m.scroll
	if start >= len(m.events) {
		start = len(m.events) - 1
	}
	if start < 0 {
		start = 0
	}
	end := min(len(m.events), start+rows)
	out := make([]audit.Event, 0, end-start)
	out = append(out, m.events[start:end]...)
	return out
}

func (m *Model) colorizeLine(line, action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "approved", "always_allowed":
		return m.allowStyle.Render(line)
	case "deny", "denied":
		return m.denyStyle.Render(line)
	case "watch", "log":
		return m.logStyle.Render(line)
	case "webhook":
		return m.webhookStyle.Render(line)
	case "require_approval":
		return m.pendingStyle.Render(line)
	default:
		return line
	}
}

func frameLineTop(width int) string {
	return "\u2554" + strings.Repeat("\u2550", width) + "\u2557"
}

func frameLineMid(width int) string {
	return "\u2560" + strings.Repeat("\u2550", width) + "\u2563"
}

func frameLineBottom(width int) string {
	return "\u255a" + strings.Repeat("\u2550", width) + "\u255d"
}

func frameLineBody(width int, s string) string {
	return "\u2551" + lipgloss.NewStyle().Width(width).Render(truncateRunes(s, width)) + "\u2551"
}

func formatUptime(d time.Duration) string {
	if d < time.Minute {
		return d.String()
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
