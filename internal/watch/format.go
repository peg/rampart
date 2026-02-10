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

	"github.com/charmbracelet/lipgloss"
	"github.com/peg/rampart/internal/audit"
)

const (
	maxVisibleEvents = 1000
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
		return "✅", lipgloss.Color("10")
	case "deny":
		return "🔴", lipgloss.Color("9")
	case "log":
		return "🟡", lipgloss.Color("11")
	default:
		return "•", lipgloss.Color("7")
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
	return string(runes[:max-1]) + "…"
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

func formatEventLine(event audit.Event, width int) string {
	icon, _ := decisionMeta(event.Decision.Action)
	timePart := event.Timestamp.Local().Format("15:04:05")
	toolPart := truncateRunes(strings.TrimSpace(event.Tool), 8)
	if toolPart == "" {
		toolPart = "-"
	}

	summary := requestSummary(event)
	if strings.EqualFold(strings.TrimSpace(event.Tool), "read") || strings.EqualFold(strings.TrimSpace(event.Tool), "write") {
		summary = compactPath(summary, max(20, width/2))
	}
	if summary == "" {
		summary = "-"
	}

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
