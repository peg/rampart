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
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
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
	fmt.Fprintln(w, "🛡️ Rampart Status")
	fmt.Fprintln(w)

	// Detect protected agents
	protected := detectProtectedAgents()
	if len(protected) == 0 {
		fmt.Fprintln(w, "No agents protected. Run 'rampart setup' to get started.")
		return nil
	}

	fmt.Fprintf(w, "Protected: %s\n", strings.Join(protected, ", "))

	// Mode from policy
	mode, defaultAction := detectMode()
	fmt.Fprintf(w, "Mode: %s (default_action: %s)\n", mode, defaultAction)

	// Today's events
	allow, deny, log, lastDeny := todayEvents()
	fmt.Fprintf(w, "Today: %d allow · %d deny · %d log\n", allow, deny, log)

	if lastDeny != nil {
		ago := formatAgo(time.Since(lastDeny.Timestamp))
		cmd := extractEventCommand(lastDeny)
		policy := "unknown"
		if len(lastDeny.Decision.MatchedPolicies) > 0 {
			policy = lastDeny.Decision.MatchedPolicies[0]
		}
		fmt.Fprintf(w, "Last deny: %s — %s (%s)\n", ago, cmd, policy)
	}

	return nil
}

func detectProtectedAgents() []string {
	var agents []string
	home, _ := os.UserHomeDir()

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

	// OpenClaw shim
	client := &http.Client{Timeout: 1 * time.Second}
	if resp, err := client.Get("http://localhost:19090/health"); err == nil {
		resp.Body.Close()
		agents = append(agents, "OpenClaw (shim)")
	}

	return agents
}

func detectMode() (string, string) {
	home, _ := os.UserHomeDir()
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

func todayEvents() (allow, deny, log int, lastDeny *audit.Event) {
	home, _ := os.UserHomeDir()
	auditDir := filepath.Join(home, ".rampart", "audit")

	today := time.Now().UTC().Format("2006-01-02")

	// Try common audit file naming patterns
	candidates := []string{
		filepath.Join(auditDir, today+".jsonl"),
		filepath.Join(auditDir, "audit-"+today+".jsonl"),
		filepath.Join(auditDir, "rampart-"+today+".jsonl"),
	}

	// Also scan directory for any file containing today's date
	if entries, err := os.ReadDir(auditDir); err == nil {
		for _, e := range entries {
			if strings.Contains(e.Name(), today) && strings.HasSuffix(e.Name(), ".jsonl") {
				candidates = append(candidates, filepath.Join(auditDir, e.Name()))
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
			case "log":
				log++
			}
		}
	}
	return
}

func extractEventCommand(ev *audit.Event) string {
	if ev == nil {
		return ""
	}
	// Try common request fields
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
