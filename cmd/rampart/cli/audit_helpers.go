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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
)

const (
	colorGreen = "\033[32m"
	colorRed   = "\033[1;31m"
	colorYel   = "\033[33m"
	colorReset = "\033[0m"
)

type auditStats struct {
	Total      int
	ByDecision map[string]int
	ByTool     map[string]int
	ByAgent    map[string]int
}

func readAllAuditEvents(auditDir string) ([]audit.Event, error) {
	files, err := listAuditFiles(auditDir)
	if err != nil {
		return nil, err
	}

	events := make([]audit.Event, 0)
	for _, file := range files {
		fileEvents, readErr := readAuditEvents(file)
		if readErr != nil {
			return nil, readErr
		}
		events = append(events, fileEvents...)
	}
	return events, nil
}

func readAuditEvents(file string) ([]audit.Event, error) {
	events := make([]audit.Event, 0)
	if err := scanAuditEvents(file, func(event audit.Event) error {
		events = append(events, event)
		return nil
	}); err != nil {
		return nil, err
	}
	return events, nil
}

func scanAuditEvents(file string, onEvent func(audit.Event) error) error {
	handle, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("audit: open file %s: %w", filepath.Base(file), err)
	}
	defer handle.Close()

	scanner := bufio.NewScanner(handle)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var event audit.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return fmt.Errorf("audit: parse event in %s line %d: %w", filepath.Base(file), lineNum, err)
		}
		if event.ID == "" {
			continue
		}
		if err := onEvent(event); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("audit: scan file %s: %w", filepath.Base(file), err)
	}
	return nil
}

func readAuditEventsFromOffset(file string, offset int64) ([]audit.Event, int64, error) {
	return audit.ReadEventsFromOffset(file, offset)
}

func fileSize(file string) (int64, error) {
	info, err := os.Stat(file)
	if err != nil {
		return 0, fmt.Errorf("audit: stat file %s: %w", filepath.Base(file), err)
	}
	return info.Size(), nil
}

func renderAuditEventLine(event audit.Event, noColor bool) string {
	timestamp := event.Timestamp.Format("15:04:05")
	details := extractPrimaryRequestValue(event.Request)
	decision := strings.ToLower(event.Decision.Action)
	policy := "-"
	if len(event.Decision.MatchedPolicies) > 0 {
		policy = event.Decision.MatchedPolicies[0]
	}

	icon := "•"
	action := decision
	color := ""
	switch decision {
	case "allow":
		icon = "✅"
		color = colorGreen
	case "deny":
		icon = "🔴"
		action = "DENY"
		color = colorRed
	case "watch", "log":
		icon = "🟡"
		color = colorYel
	}

	line := fmt.Sprintf("%s %s %-6s %q %-7s %s", icon, timestamp, event.Tool, details, action, policy)
	if noColor || color == "" {
		return line
	}
	return color + line + colorReset
}

func extractPrimaryRequestValue(request map[string]any) string {
	if request == nil {
		return ""
	}
	if command, ok := request["command"].(string); ok {
		return command
	}
	if path, ok := request["path"].(string); ok {
		return path
	}
	for _, value := range request {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

func parseSinceDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}

	dayDuration := time.Duration(0)
	if strings.Contains(raw, "d") {
		parts := strings.SplitN(raw, "d", 2)
		if parts[0] == "" {
			return 0, fmt.Errorf("audit: invalid --since duration %q", raw)
		}
		days, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, fmt.Errorf("audit: invalid day value in --since %q", raw)
		}
		dayDuration = time.Duration(days) * 24 * time.Hour
		raw = strings.TrimSpace(parts[1])
	}
	if raw == "" {
		return dayDuration, nil
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("audit: parse --since duration: %w", err)
	}
	return dayDuration + parsed, nil
}

func filterEventsBySince(events []audit.Event, since string) ([]audit.Event, string, error) {
	if strings.TrimSpace(since) == "" {
		return events, "all time", nil
	}

	duration, err := parseSinceDuration(since)
	if err != nil {
		return nil, "", err
	}
	if duration <= 0 {
		return nil, "", fmt.Errorf("audit: --since must be > 0")
	}

	cutoff := time.Now().UTC().Add(-duration)
	filtered := make([]audit.Event, 0, len(events))
	for _, event := range events {
		if event.Timestamp.After(cutoff) || event.Timestamp.Equal(cutoff) {
			filtered = append(filtered, event)
		}
	}
	return filtered, "last " + since, nil
}

func computeAuditStats(events []audit.Event) auditStats {
	stats := auditStats{
		Total:      len(events),
		ByDecision: map[string]int{"allow": 0, "deny": 0, "watch": 0},
		ByTool:     map[string]int{},
		ByAgent:    map[string]int{},
	}

	for _, event := range events {
		decision := strings.ToLower(event.Decision.Action)
		stats.ByDecision[decision]++
		stats.ByTool[event.Tool]++
		stats.ByAgent[event.Agent]++
	}
	return stats
}

func formatAuditStats(stats auditStats, windowLabel string, noColor bool) string {
	var b strings.Builder

	title := fmt.Sprintf("Audit Stats (%s)\n", windowLabel)
	line := strings.Repeat("-", max(22, len(title)-1)) + "\n"
	_, _ = b.WriteString(title)
	_, _ = b.WriteString(line)
	_, _ = b.WriteString(fmt.Sprintf("Total events:  %d\n\n", stats.Total))

	_, _ = b.WriteString("By decision:\n")
	for _, decision := range []string{"allow", "deny", "watch"} {
		count := stats.ByDecision[decision]
		pct := 0.0
		if stats.Total > 0 {
			pct = float64(count) * 100 / float64(stats.Total)
		}

		label := decision
		if !noColor {
			switch decision {
			case "allow":
				label = colorGreen + decision + colorReset
			case "deny":
				label = colorRed + decision + colorReset
			case "watch", "log":
				label = colorYel + decision + colorReset
			}
		}
		_, _ = b.WriteString(fmt.Sprintf("  %-7s %4d (%.1f%%)\n", label, count, pct))
	}

	_, _ = b.WriteString("\nBy tool:\n")
	for _, key := range sortedMapKeys(stats.ByTool) {
		_, _ = b.WriteString(fmt.Sprintf("  %-8s %d\n", key, stats.ByTool[key]))
	}

	_, _ = b.WriteString("\nBy agent:\n")
	for _, key := range sortedMapKeys(stats.ByAgent) {
		_, _ = b.WriteString(fmt.Sprintf("  %-8s %d\n", key, stats.ByAgent[key]))
	}

	return b.String()
}

func matchesAuditFilters(event audit.Event, tool, agent, decision string) bool {
	if tool != "" && !strings.EqualFold(event.Tool, tool) {
		return false
	}
	if agent != "" && !strings.EqualFold(event.Agent, agent) {
		return false
	}
	if decision != "" && !strings.EqualFold(event.Decision.Action, decision) {
		return false
	}
	return true
}

func eventMatchesQuery(event audit.Event, query string) bool {
	if query == "" {
		return true
	}

	candidates := []string{
		event.Tool,
		event.Agent,
		event.Decision.Message,
		extractPrimaryRequestValue(event.Request),
	}

	for _, value := range candidates {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}

	for _, value := range event.Request {
		if str, ok := value.(string); ok {
			if strings.Contains(strings.ToLower(str), query) {
				return true
			}
		}
	}

	return false
}

func verifyAnchors(auditDir string, hashesByID map[string]string) error {
	anchors, err := listAnchorFiles(auditDir)
	if err != nil {
		return err
	}

	for _, anchorFile := range anchors {
		data, err := os.ReadFile(anchorFile)
		if err != nil {
			return fmt.Errorf("audit: read anchor file %s: %w", filepath.Base(anchorFile), err)
		}

		var anchor audit.ChainAnchor
		if err := json.Unmarshal(data, &anchor); err != nil {
			return fmt.Errorf("audit: parse anchor file %s: %w", filepath.Base(anchorFile), err)
		}
		if anchor.EventID == "" {
			continue
		}

		hash, ok := hashesByID[anchor.EventID]
		if !ok {
			return fmt.Errorf("audit: CHAIN BROKEN at event %s in file %s: anchor event not found", anchor.EventID, filepath.Base(anchorFile))
		}
		if hash != anchor.Hash {
			return fmt.Errorf("audit: CHAIN BROKEN at event %s in file %s: anchor hash mismatch", anchor.EventID, filepath.Base(anchorFile))
		}
	}
	return nil
}

func listAnchorFiles(auditDir string) ([]string, error) {
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read audit dir for anchors: %w", err)
	}

	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "audit-anchor.json" || strings.HasSuffix(name, ".anchor.json") {
			files = append(files, filepath.Join(auditDir, name))
		}
	}
	sort.Strings(files)
	return files, nil
}

func sortedMapKeys[V any](data map[string]V) []string {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
