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
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/peg/rampart/internal/audit"
)

const (
	maxVisibleEvents = 1000
	maxCommandWidth  = 80
)

func requestSummary(event audit.Event) string {
	if event.Request == nil {
		return ""
	}

	if command, ok := event.Request["command"].(string); ok {
		return strings.TrimSpace(command)
	}

	if path, ok := event.Request["path"].(string); ok {
		return strings.TrimSpace(path)
	}

	for _, value := range event.Request {
		if str, ok := value.(string); ok {
			return strings.TrimSpace(str)
		}
	}

	return ""
}

func firstPolicy(event audit.Event) string {
	if len(event.Decision.MatchedPolicies) == 0 {
		return "-"
	}
	return event.Decision.MatchedPolicies[0]
}

func decisionMeta(action string) (icon string, color lipgloss.Color) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow":
		return "\u2705", lipgloss.Color("10")
	case "deny":
		return "\U0001f534", lipgloss.Color("9")
	case "log":
		return "\U0001f7e1", lipgloss.Color("11")
	case "webhook":
		return "\U0001f535", lipgloss.Color("14")
	default:
		return "\u2022", lipgloss.Color("7")
	}
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + "\u2026"
}

func compactPath(path string, width int) string {
	path = strings.TrimSpace(path)
	if width <= 0 || path == "" {
		return ""
	}
	if len([]rune(path)) <= width {
		return path
	}

	base := filepath.Base(path)
	if len([]rune(base))+3 <= width {
		return "..." + string(filepath.Separator) + base
	}

	return truncateRunes(path, width)
}

// relativeTime formats the elapsed time as a human-readable string.
func relativeTime(now, ts time.Time) string {
	d := now.Sub(ts)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m > 0 {
			return fmt.Sprintf("%dh%dm ago", h, m)
		}
		return fmt.Sprintf("%dh ago", h)
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func formatEventLine(event audit.Event, width int) string {
	icon, _ := decisionMeta(event.Decision.Action)
	timePart := event.Timestamp.Local().Format("15:04:05")
	toolPart := truncateRunes(strings.TrimSpace(event.Tool), 8)
	if toolPart == "" {
		toolPart = "-"
	}

	summary := requestSummary(event)
	if strings.EqualFold(strings.TrimSpace(event.Tool), "read") || strings.EqualFold(strings.TrimSpace(event.Tool), "write") {
		summary = compactPath(summary, min(maxCommandWidth, max(20, width/2)))
	}
	if summary == "" {
		summary = "-"
	}
	summary = truncateRunes(summary, maxCommandWidth)

	policy := firstPolicy(event)
	base := fmt.Sprintf("%s %s %-6s %q [%s]", icon, timePart, toolPart, summary, policy)
	return truncateRunes(base, width)
}

// formatEventLineWithRelTime renders an event line with relative timestamps.
func formatEventLineWithRelTime(event audit.Event, width int, now time.Time) string {
	icon, _ := decisionMeta(event.Decision.Action)
	rel := relativeTime(now, event.Timestamp)
	timePart := fmt.Sprintf("%-8s", rel)
	toolPart := truncateRunes(strings.TrimSpace(event.Tool), 8)
	if toolPart == "" {
		toolPart = "-"
	}

	summary := requestSummary(event)
	if strings.EqualFold(strings.TrimSpace(event.Tool), "read") || strings.EqualFold(strings.TrimSpace(event.Tool), "write") {
		summary = compactPath(summary, min(maxCommandWidth, max(20, width/2)))
	}
	if summary == "" {
		summary = "-"
	}
	summary = truncateRunes(summary, maxCommandWidth)

	policy := firstPolicy(event)
	base := fmt.Sprintf("%s %s %-6s %q [%s]", icon, timePart, toolPart, summary, policy)
	return truncateRunes(base, width)
}

func trimEvents(events []audit.Event) []audit.Event {
	if len(events) <= maxVisibleEvents {
		return events
	}
	trimmed := make([]audit.Event, maxVisibleEvents)
	copy(trimmed, events[:maxVisibleEvents])
	return trimmed
}
