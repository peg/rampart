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

type tailerMsg struct {
	event audit.Event
	err   error
}

type tickMsg time.Time

type Config struct {
	AuditFile  string
	PolicyName string
	Mode       string
	Agent      string
	Out        io.Writer
}

type Stats struct {
	Total int
	Allow int
	Deny  int
	Log   int
}

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

	frameStyle      lipgloss.Style
	headerStyle     lipgloss.Style
	sectionStyle    lipgloss.Style
	allowStyle      lipgloss.Style
	denyStyle       lipgloss.Style
	logStyle        lipgloss.Style
	mutedStyle      lipgloss.Style
	statusLineStyle lipgloss.Style
}

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

	return &Model{
		cfg:       cfg,
		startedAt: time.Now(),
		width:     80,
		height:    24,
		events:    make([]audit.Event, 0, 64),
		tailer:    newFileTailer(cfg.AuditFile),
		frameStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("7")),
		headerStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("14")),
		sectionStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12")),
		allowStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		denyStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("9")),
		logStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		mutedStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
		statusLineStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("7")),
	}
}

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
	return tea.Batch(waitForTailer(m.tailerCh), tickCmd())
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

		m.events = append([]audit.Event{typed.event}, m.events...)
		m.events = trimEvents(m.events)
		m.updateStats(typed.event)
		if m.scroll == 0 {
			m.scroll = 0
		}
		return m, waitForTailer(m.tailerCh)
	case tickMsg:
		return m, tickCmd()
	}

	return m, nil
}

func (m *Model) updateStats(event audit.Event) {
	m.stats.Total++
	switch strings.ToLower(strings.TrimSpace(event.Decision.Action)) {
	case "allow":
		m.stats.Allow++
	case "deny":
		m.stats.Deny++
	case "log":
		m.stats.Log++
	}
}

func (m *Model) View() string {
	innerWidth := max(20, m.width-4)
	feedRows := max(5, m.height-10)

	top := "RAMPART WATCH"
	policyCount := policiesLoadedFromEvents(m.events)
	var header string
	if policyCount > 0 {
		header = fmt.Sprintf("%s - %s mode - %d policies matched", top, m.cfg.Mode, policyCount)
	} else {
		header = fmt.Sprintf("%s - %s mode", top, m.cfg.Mode)
	}
	header = truncateRunes(header, innerWidth)

	lines := make([]string, 0, m.height)
	lines = append(lines, frameLineTop(innerWidth))
	lines = append(lines, frameLineBody(innerWidth, m.headerStyle.Render("  "+header)))
	lines = append(lines, frameLineMid(innerWidth))
	lines = append(lines, frameLineBody(innerWidth, m.sectionStyle.Render("  LIVE FEED")))

	visible := m.visibleEvents(feedRows)
	for _, event := range visible {
		line := formatEventLine(event, innerWidth-4)
		colorLine := m.colorizeLine(line, event.Decision.Action)
		lines = append(lines, frameLineBody(innerWidth, "  "+colorLine))
	}
	for len(visible) < feedRows {
		lines = append(lines, frameLineBody(innerWidth, ""))
		visible = append(visible, audit.Event{})
	}

	lines = append(lines, frameLineMid(innerWidth))
	stats := fmt.Sprintf("STATS: %d total | %d allow | %d deny | %d log", m.stats.Total, m.stats.Allow, m.stats.Deny, m.stats.Log)
	lines = append(lines, frameLineBody(innerWidth, "  "+m.statusLineStyle.Render(truncateRunes(stats, innerWidth-2))))

	uptime := time.Since(m.startedAt).Round(time.Second)
	status := fmt.Sprintf("UPTIME: %s | POLICIES: %s | AGENT: %s", formatUptime(uptime), m.cfg.PolicyName, m.cfg.Agent)
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
	case "allow":
		return m.allowStyle.Render(line)
	case "deny":
		return m.denyStyle.Render(line)
	case "log":
		return m.logStyle.Render(line)
	default:
		return line
	}
}

func frameLineTop(width int) string {
	return "╔" + strings.Repeat("═", width) + "╗"
}

func frameLineMid(width int) string {
	return "╠" + strings.Repeat("═", width) + "╣"
}

func frameLineBottom(width int) string {
	return "╚" + strings.Repeat("═", width) + "╝"
}

func frameLineBody(width int, s string) string {
	return "║" + lipgloss.NewStyle().Width(width).Render(truncateRunes(s, width)) + "║"
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
