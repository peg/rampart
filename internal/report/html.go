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

// Package report generates HTML audit reports from JSONL audit events.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
)

// ReportData contains all the data needed to generate an HTML report.
type ReportData struct {
	Title          string
	GeneratedAt    time.Time
	StartTime      time.Time
	EndTime        time.Time
	ChainValid     bool
	TotalEvents    int
	AllowedEvents  int
	DeniedEvents   int
	LoggedEvents   int
	AllowedPercent float64
	DeniedPercent  float64
	LoggedPercent  float64
	Timeline       []TimelineEntry
	TopDenied      []CommandCount
	TopPolicies    []PolicyCount
	Events         []ReportEvent
}

// TimelineEntry represents an hour's worth of events for the timeline chart.
type TimelineEntry struct {
	Hour     string
	Allowed  int
	Denied   int
	Logged   int
	Total    int
	MaxWidth int // For CSS width calculation
}

// CommandCount represents the count of a specific command.
type CommandCount struct {
	Command string
	Count   int
}

// PolicyCount represents the count of a specific policy trigger.
type PolicyCount struct {
	Policy string
	Count  int
}

// ReportEvent represents an event formatted for display in the report.
type ReportEvent struct {
	Time      string
	Tool      string
	Command   string
	Decision  string
	Policy    string
	Message   string
	CSSClass  string
}

// GenerateHTMLReport generates a self-contained HTML report from audit events.
func GenerateHTMLReport(events []audit.Event, startTime, endTime time.Time, writer io.Writer) error {
	data, err := prepareReportData(events, startTime, endTime)
	if err != nil {
		return fmt.Errorf("prepare report data: %w", err)
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML template: %w", err)
	}

	if err := tmpl.Execute(writer, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return nil
}

// ReadEventsFromDir reads all .jsonl files from the given directory.
func ReadEventsFromDir(auditDir string) ([]audit.Event, error) {
	var allEvents []audit.Event

	files, err := filepath.Glob(filepath.Join(auditDir, "*.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("glob audit files: %w", err)
	}

	for _, file := range files {
		events, _, err := audit.ReadEventsFromOffset(file, 0)
		if err != nil {
			// Skip files that can't be read, but log the error
			fmt.Fprintf(os.Stderr, "Warning: could not read %s: %v\n", file, err)
			continue
		}
		allEvents = append(allEvents, events...)
	}

	// Sort events by timestamp
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.Before(allEvents[j].Timestamp)
	})

	return allEvents, nil
}

// FilterEventsByTime filters events to only include those within the time window.
func FilterEventsByTime(events []audit.Event, since time.Duration) []audit.Event {
	cutoff := time.Now().Add(-since)
	var filtered []audit.Event

	for _, event := range events {
		if event.Timestamp.After(cutoff) {
			filtered = append(filtered, event)
		}
	}

	return filtered
}

// prepareReportData processes events into the data structure needed for the HTML template.
func prepareReportData(events []audit.Event, startTime, endTime time.Time) (*ReportData, error) {
	data := &ReportData{
		Title:       "🛡️ Rampart Audit Report",
		GeneratedAt: time.Now(),
		StartTime:   startTime,
		EndTime:     endTime,
		TotalEvents: len(events),
	}

	// Verify hash chain integrity
	data.ChainValid = verifyHashChain(events)

	// Count events by decision
	commandCounts := make(map[string]int)
	policyCounts := make(map[string]int)
	timelineCounts := make(map[string]map[string]int)

	for _, event := range events {
		switch event.Decision.Action {
		case "allow":
			data.AllowedEvents++
		case "deny":
			data.DeniedEvents++
		case "log":
			data.LoggedEvents++
		}

		// Count denied commands
		if event.Decision.Action == "deny" {
			command := getCommandString(event)
			commandCounts[command]++
		}

		// Count policy triggers
		for _, policy := range event.Decision.MatchedPolicies {
			policyCounts[policy]++
		}

		// Timeline data (group by hour)
		hour := event.Timestamp.Format("2006-01-02 15:00")
		if timelineCounts[hour] == nil {
			timelineCounts[hour] = make(map[string]int)
		}
		timelineCounts[hour][event.Decision.Action]++
	}

	// Calculate percentages
	if data.TotalEvents > 0 {
		data.AllowedPercent = float64(data.AllowedEvents) / float64(data.TotalEvents) * 100
		data.DeniedPercent = float64(data.DeniedEvents) / float64(data.TotalEvents) * 100
		data.LoggedPercent = float64(data.LoggedEvents) / float64(data.TotalEvents) * 100
	}

	// Prepare timeline data
	data.Timeline = prepareTimeline(timelineCounts)

	// Prepare top denied commands
	data.TopDenied = prepareTopCommands(commandCounts)

	// Prepare top policies
	data.TopPolicies = prepareTopPolicies(policyCounts)

	// Prepare event list
	data.Events = prepareEventList(events)

	return data, nil
}

// verifyHashChain checks if the hash chain is valid across all events.
func verifyHashChain(events []audit.Event) bool {
	for i, event := range events {
		valid, err := event.VerifyHash()
		if err != nil || !valid {
			return false
		}

		// Check chain linkage
		if i > 0 {
			prevHash := events[i-1].Hash
			if event.PrevHash != prevHash {
				return false
			}
		}
	}
	return true
}

// getCommandString extracts a readable command string from the event request.
func getCommandString(event audit.Event) string {
	// Try to get command from request
	if cmd, ok := event.Request["command"].(string); ok {
		return cmd
	}
	if path, ok := event.Request["file_path"].(string); ok {
		return fmt.Sprintf("%s %s", event.Tool, path)
	}
	if url, ok := event.Request["url"].(string); ok {
		return fmt.Sprintf("%s %s", event.Tool, url)
	}

	// Fallback to JSON representation (truncated)
	reqBytes, _ := json.Marshal(event.Request)
	reqStr := string(reqBytes)
	if len(reqStr) > 80 {
		reqStr = reqStr[:77] + "..."
	}
	return fmt.Sprintf("%s %s", event.Tool, reqStr)
}

// prepareTimeline creates timeline entries from the time-based counts.
func prepareTimeline(timelineCounts map[string]map[string]int) []TimelineEntry {
	var timeline []TimelineEntry
	maxTotal := 0

	// Convert to sorted timeline entries
	hours := make([]string, 0, len(timelineCounts))
	for hour := range timelineCounts {
		hours = append(hours, hour)
	}
	sort.Strings(hours)

	for _, hour := range hours {
		counts := timelineCounts[hour]
		allowed := counts["allow"]
		denied := counts["deny"]
		logged := counts["log"]
		total := allowed + denied + logged

		if total > maxTotal {
			maxTotal = total
		}

		timeline = append(timeline, TimelineEntry{
			Hour:    hour,
			Allowed: allowed,
			Denied:  denied,
			Logged:  logged,
			Total:   total,
		})
	}

	// Set max width for CSS scaling
	for i := range timeline {
		if maxTotal > 0 {
			timeline[i].MaxWidth = (timeline[i].Total * 100) / maxTotal
		}
	}

	return timeline
}

// prepareTopCommands creates a sorted list of top denied commands.
func prepareTopCommands(commandCounts map[string]int) []CommandCount {
	var commands []CommandCount
	for cmd, count := range commandCounts {
		commands = append(commands, CommandCount{
			Command: cmd,
			Count:   count,
		})
	}

	sort.Slice(commands, func(i, j int) bool {
		return commands[i].Count > commands[j].Count
	})

	// Limit to top 10
	if len(commands) > 10 {
		commands = commands[:10]
	}

	return commands
}

// prepareTopPolicies creates a sorted list of top triggered policies.
func prepareTopPolicies(policyCounts map[string]int) []PolicyCount {
	var policies []PolicyCount
	for policy, count := range policyCounts {
		policies = append(policies, PolicyCount{
			Policy: policy,
			Count:  count,
		})
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Count > policies[j].Count
	})

	// Limit to top 10
	if len(policies) > 10 {
		policies = policies[:10]
	}

	return policies
}

// prepareEventList formats events for display in the report table.
func prepareEventList(events []audit.Event) []ReportEvent {
	var reportEvents []ReportEvent

	for _, event := range events {
		command := getCommandString(event)
		if len(command) > 80 {
			command = command[:77] + "..."
		}

		var cssClass string
		switch event.Decision.Action {
		case "allow":
			cssClass = "decision-allow"
		case "deny":
			cssClass = "decision-deny"
		case "log":
			cssClass = "decision-log"
		}

		policy := strings.Join(event.Decision.MatchedPolicies, ", ")
		if policy == "" {
			policy = "-"
		}

		reportEvents = append(reportEvents, ReportEvent{
			Time:     event.Timestamp.Format("2006-01-02 15:04:05"),
			Tool:     event.Tool,
			Command:  command,
			Decision: event.Decision.Action,
			Policy:   policy,
			Message:  event.Decision.Message,
			CSSClass: cssClass,
		})
	}

	return reportEvents
}

// htmlTemplate is the complete HTML template for the audit report.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            line-height: 1.5;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background-color: #161b22;
            border-radius: 8px;
        }
        
        .header h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .header .meta {
            color: #7d8590;
            font-size: 0.9em;
        }
        
        .chain-status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-left: 10px;
        }
        
        .chain-valid {
            background-color: #238636;
            color: white;
        }
        
        .chain-broken {
            background-color: #da3633;
            color: white;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background-color: #161b22;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid #21262d;
        }
        
        .card.total { border-left-color: #58a6ff; }
        .card.allow { border-left-color: #3fb950; }
        .card.deny { border-left-color: #f85149; }
        .card.log { border-left-color: #d29922; }
        
        .card-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .card-label {
            color: #7d8590;
            font-size: 0.9em;
        }
        
        .card-percent {
            font-size: 0.8em;
            color: #7d8590;
            margin-top: 5px;
        }
        
        .section {
            background-color: #161b22;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .section h2 {
            margin-bottom: 20px;
            font-size: 1.3em;
        }
        
        .timeline {
            margin-bottom: 20px;
        }
        
        .timeline-entry {
            margin-bottom: 8px;
        }
        
        .timeline-hour {
            font-size: 0.8em;
            color: #7d8590;
            margin-bottom: 4px;
        }
        
        .timeline-bar {
            height: 20px;
            border-radius: 3px;
            overflow: hidden;
            display: flex;
        }
        
        .bar-segment {
            height: 100%;
        }
        
        .bar-allow { background-color: #3fb950; }
        .bar-deny { background-color: #f85149; }
        .bar-log { background-color: #d29922; }
        
        .timeline-counts {
            font-size: 0.8em;
            color: #7d8590;
            margin-top: 2px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #21262d;
        }
        
        th {
            background-color: #21262d;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }
        
        th:hover {
            background-color: #2d333b;
        }
        
        tr:hover {
            background-color: #21262d;
        }
        
        .command {
            font-family: "SF Mono", Monaco, "Cascadia Code", "Roboto Mono", Consolas, "Courier New", monospace;
            font-size: 0.85em;
        }
        
        .decision {
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: 500;
        }
        
        .decision-allow {
            background-color: #238636;
            color: white;
        }
        
        .decision-deny {
            background-color: #da3633;
            color: white;
        }
        
        .decision-log {
            background-color: #bf8700;
            color: white;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .summary {
                grid-template-columns: repeat(2, 1fr);
            }
            
            table {
                font-size: 0.9em;
            }
            
            th, td {
                padding: 6px 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <div class="meta">
                {{.StartTime.Format "2006-01-02 15:04"}} — {{.EndTime.Format "2006-01-02 15:04"}}
                <br>
                Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05 MST"}}
                <span class="chain-status {{if .ChainValid}}chain-valid{{else}}chain-broken{{end}}">
                    {{if .ChainValid}}Chain Valid ✓{{else}}Chain Broken ✗{{end}}
                </span>
            </div>
        </div>
        
        <div class="summary">
            <div class="card total">
                <div class="card-number">{{.TotalEvents}}</div>
                <div class="card-label">Total Events</div>
            </div>
            <div class="card allow">
                <div class="card-number">{{.AllowedEvents}}</div>
                <div class="card-label">Allowed</div>
                <div class="card-percent">{{printf "%.1f%%" .AllowedPercent}}</div>
            </div>
            <div class="card deny">
                <div class="card-number">{{.DeniedEvents}}</div>
                <div class="card-label">Denied</div>
                <div class="card-percent">{{printf "%.1f%%" .DeniedPercent}}</div>
            </div>
            <div class="card log">
                <div class="card-number">{{.LoggedEvents}}</div>
                <div class="card-label">Logged</div>
                <div class="card-percent">{{printf "%.1f%%" .LoggedPercent}}</div>
            </div>
        </div>
        
        {{if .Timeline}}
        <div class="section">
            <h2>Timeline</h2>
            <div class="timeline">
                {{range .Timeline}}
                <div class="timeline-entry">
                    <div class="timeline-hour">{{.Hour}}</div>
                    <div class="timeline-bar" style="width: {{.MaxWidth}}%;">
                        {{if .Allowed}}<div class="bar-segment bar-allow" style="flex: {{.Allowed}};"></div>{{end}}
                        {{if .Denied}}<div class="bar-segment bar-deny" style="flex: {{.Denied}};"></div>{{end}}
                        {{if .Logged}}<div class="bar-segment bar-log" style="flex: {{.Logged}};"></div>{{end}}
                    </div>
                    <div class="timeline-counts">
                        {{if .Allowed}}Allow: {{.Allowed}} {{end}}
                        {{if .Denied}}Deny: {{.Denied}} {{end}}
                        {{if .Logged}}Log: {{.Logged}}{{end}}
                    </div>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}
        
        {{if .TopDenied}}
        <div class="section">
            <h2>Top Denied Commands</h2>
            <table>
                <thead>
                    <tr>
                        <th>Command</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .TopDenied}}
                    <tr>
                        <td class="command">{{.Command}}</td>
                        <td>{{.Count}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}
        
        {{if .TopPolicies}}
        <div class="section">
            <h2>Top Policies Triggered</h2>
            <table>
                <thead>
                    <tr>
                        <th>Policy</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .TopPolicies}}
                    <tr>
                        <td>{{.Policy}}</td>
                        <td>{{.Count}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}
        
        <div class="section">
            <h2>Full Event Log</h2>
            <table id="eventTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Time ↕</th>
                        <th onclick="sortTable(1)">Tool ↕</th>
                        <th onclick="sortTable(2)">Command ↕</th>
                        <th onclick="sortTable(3)">Decision ↕</th>
                        <th onclick="sortTable(4)">Policy ↕</th>
                        <th onclick="sortTable(5)">Message ↕</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Events}}
                    <tr>
                        <td>{{.Time}}</td>
                        <td>{{.Tool}}</td>
                        <td class="command">{{.Command}}</td>
                        <td><span class="decision {{.CSSClass}}">{{.Decision}}</span></td>
                        <td>{{.Policy}}</td>
                        <td>{{.Message}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function sortTable(columnIndex) {
            const table = document.getElementById('eventTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            const isAscending = table.dataset.sortOrder !== 'asc' || table.dataset.sortColumn !== columnIndex.toString();
            
            rows.sort((a, b) => {
                const aVal = a.cells[columnIndex].textContent.trim();
                const bVal = b.cells[columnIndex].textContent.trim();
                
                if (isAscending) {
                    return aVal.localeCompare(bVal);
                } else {
                    return bVal.localeCompare(aVal);
                }
            });
            
            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
            
            table.dataset.sortOrder = isAscending ? 'asc' : 'desc';
            table.dataset.sortColumn = columnIndex.toString();
        }
    </script>
</body>
</html>`