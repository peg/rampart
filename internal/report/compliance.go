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

package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
)

type ControlStatus string

type ComplianceStatus string

const (
	ControlStatusPass ControlStatus = "PASS"
	ControlStatusWarn ControlStatus = "WARN"
	ControlStatusFail ControlStatus = "FAIL"

	ComplianceStatusCompliant    ComplianceStatus = "COMPLIANT"
	ComplianceStatusPartial      ComplianceStatus = "PARTIAL"
	ComplianceStatusNonCompliant ComplianceStatus = "NON-COMPLIANT"
)

type CompliancePeriod struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

type DecisionCounts struct {
	Total int `json:"total"`
	Allow int `json:"allow"`
	Deny  int `json:"deny"`
	Log   int `json:"log"`
	Ask   int `json:"ask"`
	Other int `json:"other"`
}

type ComplianceSummary struct {
	DecisionCounts   DecisionCounts   `json:"decision_counts"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
}

type ComplianceControl struct {
	Name     string        `json:"name"`
	Status   ControlStatus `json:"status"`
	Evidence []string      `json:"evidence"`
}

type AIUC1Report struct {
	ReportID       string                       `json:"report_id"`
	GeneratedAt    time.Time                    `json:"generated_at"`
	Period         CompliancePeriod             `json:"period"`
	RampartVersion string                       `json:"rampart_version"`
	Standard       string                       `json:"standard"`
	Summary        ComplianceSummary            `json:"summary"`
	Controls       map[string]ComplianceControl `json:"controls"`
}

type ComplianceOptions struct {
	AuditDir       string
	PolicyPath     string
	Since          time.Time
	Until          time.Time
	GeneratedAt    time.Time
	RampartVersion string
}

func GenerateAIUC1Report(opts ComplianceOptions) (*AIUC1Report, error) {
	generatedAt := opts.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	since := opts.Since.UTC()
	if since.IsZero() {
		since = generatedAt.AddDate(0, 0, -30)
	}
	until := opts.Until.UTC()
	if until.IsZero() {
		until = generatedAt
	}
	if since.After(until) {
		return nil, fmt.Errorf("report: period start must be before period end")
	}

	auditDir, err := expandHomePath(opts.AuditDir)
	if err != nil {
		return nil, fmt.Errorf("report: expand audit dir: %w", err)
	}
	if strings.TrimSpace(auditDir) == "" {
		auditDir = "."
	}

	report := &AIUC1Report{
		ReportID:    generateUUID4(),
		GeneratedAt: generatedAt,
		Period: CompliancePeriod{
			Since: since,
			Until: until,
		},
		RampartVersion: opts.RampartVersion,
		Standard:       "AIUC-1",
		Controls: map[string]ComplianceControl{
			"AIUC-1.1": {Name: "Tool Call Authorization"},
			"AIUC-1.2": {Name: "Audit Logging"},
			"AIUC-1.3": {Name: "Human-in-the-Loop"},
			"AIUC-1.4": {Name: "Data Exfiltration Prevention"},
		},
	}

	auditFiles, listErr := listAuditJSONLFiles(auditDir)
	if listErr != nil {
		report.Controls["AIUC-1.1"] = ComplianceControl{
			Name:   "Tool Call Authorization",
			Status: ControlStatusFail,
			Evidence: []string{
				fmt.Sprintf("Could not read audit directory %q: %v", auditDir, listErr),
			},
		}
		report.Controls["AIUC-1.2"] = ComplianceControl{
			Name:   "Audit Logging",
			Status: ControlStatusFail,
			Evidence: []string{
				"Audit chain could not be verified because audit logs are unavailable.",
			},
		}
		report.Controls["AIUC-1.3"] = ComplianceControl{
			Name:   "Human-in-the-Loop",
			Status: ControlStatusWarn,
			Evidence: []string{
				"No audit events available for period; cannot confirm ask decisions.",
			},
		}
	} else {
		report.applyAuditControlResults(auditDir, auditFiles, since, until)
	}

	report.applyPolicyControlResult(opts.PolicyPath)
	report.Summary.ComplianceStatus = deriveComplianceStatus(report.Controls)

	return report, nil
}

func (r *AIUC1Report) applyAuditControlResults(auditDir string, auditFiles []string, since, until time.Time) {
	if len(auditFiles) == 0 {
		r.Controls["AIUC-1.1"] = ComplianceControl{
			Name:   "Tool Call Authorization",
			Status: ControlStatusFail,
			Evidence: []string{
				fmt.Sprintf("No audit log files found in %q.", auditDir),
			},
		}
		r.Controls["AIUC-1.2"] = ComplianceControl{
			Name:   "Audit Logging",
			Status: ControlStatusFail,
			Evidence: []string{
				"Audit chain verification cannot run because no audit log files were found.",
			},
		}
		r.Controls["AIUC-1.3"] = ComplianceControl{
			Name:   "Human-in-the-Loop",
			Status: ControlStatusWarn,
			Evidence: []string{
				"No audit events available in the reporting period.",
			},
		}
		return
	}

	allEvents, hashesByID, chainErr := readAndVerifyAuditChain(auditFiles)
	if chainErr != nil {
		r.Controls["AIUC-1.2"] = ComplianceControl{
			Name:     "Audit Logging",
			Status:   ControlStatusFail,
			Evidence: []string{fmt.Sprintf("Audit chain verification failed: %v", chainErr)},
		}
	} else {
		anchorErr := verifyAnchorsInDir(auditDir, hashesByID)
		if anchorErr != nil {
			r.Controls["AIUC-1.2"] = ComplianceControl{
				Name:     "Audit Logging",
				Status:   ControlStatusFail,
				Evidence: []string{fmt.Sprintf("Audit anchor verification failed: %v", anchorErr)},
			}
		} else {
			r.Controls["AIUC-1.2"] = ComplianceControl{
				Name:     "Audit Logging",
				Status:   ControlStatusPass,
				Evidence: []string{fmt.Sprintf("Verified %d events across %d audit files.", len(allEvents), len(auditFiles))},
			}
		}
	}

	periodEvents := filterEventsByPeriod(allEvents, since, until)
	counts := computeDecisionCounts(periodEvents)
	r.Summary.DecisionCounts = counts

	if len(periodEvents) > 0 {
		r.Controls["AIUC-1.1"] = ComplianceControl{
			Name:     "Tool Call Authorization",
			Status:   ControlStatusPass,
			Evidence: []string{fmt.Sprintf("Found %d audited tool-call events in reporting period.", len(periodEvents))},
		}
	} else {
		r.Controls["AIUC-1.1"] = ComplianceControl{
			Name:   "Tool Call Authorization",
			Status: ControlStatusWarn,
			Evidence: []string{
				"Audit log files exist, but no events were recorded in the reporting period.",
			},
		}
	}

	if counts.Ask > 0 {
		r.Controls["AIUC-1.3"] = ComplianceControl{
			Name:     "Human-in-the-Loop",
			Status:   ControlStatusPass,
			Evidence: []string{fmt.Sprintf("Found %d ask decisions in reporting period.", counts.Ask)},
		}
	} else {
		r.Controls["AIUC-1.3"] = ComplianceControl{
			Name:     "Human-in-the-Loop",
			Status:   ControlStatusWarn,
			Evidence: []string{"No ask decisions found in reporting period."},
		}
	}
}

func (r *AIUC1Report) applyPolicyControlResult(policyPath string) {
	resolved, err := expandHomePath(policyPath)
	if err != nil {
		resolved = policyPath
	}
	trimmed := strings.TrimSpace(resolved)
	if trimmed == "" {
		r.Controls["AIUC-1.4"] = ComplianceControl{
			Name:     "Data Exfiltration Prevention",
			Status:   ControlStatusWarn,
			Evidence: []string{"No policy file path provided; cannot verify sensitive deny rules."},
		}
		return
	}

	const maxPolicyBytes = 10 << 20 // 10 MiB
	fi, err := os.Stat(trimmed)
	if err != nil {
		r.Controls["AIUC-1.4"] = ComplianceControl{
			Name:     "Data Exfiltration Prevention",
			Status:   ControlStatusWarn,
			Evidence: []string{fmt.Sprintf("Could not read policy file %q: %v", trimmed, err)},
		}
		return
	}
	if !fi.Mode().IsRegular() {
		r.Controls["AIUC-1.4"] = ComplianceControl{
			Name:     "Data Exfiltration Prevention",
			Status:   ControlStatusWarn,
			Evidence: []string{fmt.Sprintf("Policy path %q is not a regular file", trimmed)},
		}
		return
	}
	if fi.Size() > maxPolicyBytes {
		r.Controls["AIUC-1.4"] = ComplianceControl{
			Name:     "Data Exfiltration Prevention",
			Status:   ControlStatusWarn,
			Evidence: []string{fmt.Sprintf("Policy file %q exceeds 10 MiB size limit", trimmed)},
		}
		return
	}
	data, err := os.ReadFile(trimmed)
	if err != nil {
		r.Controls["AIUC-1.4"] = ComplianceControl{
			Name:     "Data Exfiltration Prevention",
			Status:   ControlStatusWarn,
			Evidence: []string{fmt.Sprintf("Could not read policy file %q: %v", trimmed, err)},
		}
		return
	}

	// Note: evaluateSensitiveDenyCoverage uses keyword proximity heuristics,
	// not semantic YAML parsing. Manual review of the policy file is recommended
	// for full assurance that deny rules actually match the sensitive paths.
	covered, found, missing := evaluateSensitiveDenyCoverage(string(data))
	heuristicNote := "Note: coverage check is keyword proximity heuristic — manual policy review recommended for full assurance."
	if covered {
		r.Controls["AIUC-1.4"] = ComplianceControl{
			Name:   "Data Exfiltration Prevention",
			Status: ControlStatusPass,
			Evidence: []string{
				fmt.Sprintf("Keyword proximity check passed for: %s", strings.Join(found, ", ")),
				heuristicNote,
			},
		}
		return
	}

	evidence := []string{"Sensitive keyword proximity check did not find deny coverage for all required targets."}
	if len(found) > 0 {
		evidence = append(evidence, fmt.Sprintf("Found: %s", strings.Join(found, ", ")))
	}
	if len(missing) > 0 {
		evidence = append(evidence, fmt.Sprintf("Missing: %s", strings.Join(missing, ", ")))
	}
	evidence = append(evidence, heuristicNote)
	r.Controls["AIUC-1.4"] = ComplianceControl{
		Name:     "Data Exfiltration Prevention",
		Status:   ControlStatusWarn,
		Evidence: evidence,
	}
}

func deriveComplianceStatus(controls map[string]ComplianceControl) ComplianceStatus {
	hasWarn := false
	for _, c := range controls {
		switch c.Status {
		case ControlStatusFail:
			return ComplianceStatusNonCompliant
		case ControlStatusWarn:
			hasWarn = true
		}
	}
	if hasWarn {
		return ComplianceStatusPartial
	}
	return ComplianceStatusCompliant
}

func filterEventsByPeriod(events []audit.Event, since, until time.Time) []audit.Event {
	filtered := make([]audit.Event, 0, len(events))
	for _, evt := range events {
		ts := evt.Timestamp.UTC()
		if (ts.Equal(since) || ts.After(since)) && (ts.Equal(until) || ts.Before(until)) {
			filtered = append(filtered, evt)
		}
	}
	return filtered
}

func computeDecisionCounts(events []audit.Event) DecisionCounts {
	counts := DecisionCounts{Total: len(events)}
	for _, evt := range events {
		switch strings.ToLower(strings.TrimSpace(evt.Decision.Action)) {
		case "allow":
			counts.Allow++
		case "deny":
			counts.Deny++
		case "log", "watch":
			counts.Log++
		case "ask":
			counts.Ask++
		default:
			counts.Other++
		}
	}
	return counts
}

func readAndVerifyAuditChain(files []string) ([]audit.Event, map[string]string, error) {
	allEvents := make([]audit.Event, 0)
	hashesByID := map[string]string{}
	prevHash := ""
	eventCount := 0

	for _, file := range files {
		events, _, err := audit.ReadEventsFromOffset(file, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("read events from %s: %w", filepath.Base(file), err)
		}
		for _, event := range events {
			eventCount++
			if eventCount == 1 && event.PrevHash != "" {
				return nil, nil, fmt.Errorf("first event %s in %s has non-empty prev_hash", event.ID, filepath.Base(file))
			}
			if eventCount > 1 && event.PrevHash != prevHash {
				return nil, nil, fmt.Errorf("event %s in %s has prev_hash mismatch", event.ID, filepath.Base(file))
			}
			ok, err := event.VerifyHash()
			if err != nil {
				return nil, nil, fmt.Errorf("verify hash for event %s in %s: %w", event.ID, filepath.Base(file), err)
			}
			if !ok {
				return nil, nil, fmt.Errorf("event %s in %s failed hash verification", event.ID, filepath.Base(file))
			}

			prevHash = event.Hash
			hashesByID[event.ID] = event.Hash
			allEvents = append(allEvents, event)
		}
	}

	return allEvents, hashesByID, nil
}

func verifyAnchorsInDir(auditDir string, hashesByID map[string]string) error {
	anchors, err := listAnchorFiles(auditDir)
	if err != nil {
		return err
	}
	for _, anchorFile := range anchors {
		data, err := os.ReadFile(anchorFile)
		if err != nil {
			return fmt.Errorf("read anchor file %s: %w", filepath.Base(anchorFile), err)
		}

		var anchor audit.ChainAnchor
		if err := json.Unmarshal(data, &anchor); err != nil {
			return fmt.Errorf("parse anchor file %s: %w", filepath.Base(anchorFile), err)
		}
		if strings.TrimSpace(anchor.EventID) == "" {
			continue
		}
		hash, ok := hashesByID[anchor.EventID]
		if !ok {
			return fmt.Errorf("anchor event %s not found in chain", anchor.EventID)
		}
		if hash != anchor.Hash {
			return fmt.Errorf("anchor hash mismatch at event %s", anchor.EventID)
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
		return nil, fmt.Errorf("read audit dir for anchors: %w", err)
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

func listAuditJSONLFiles(auditDir string) ([]string, error) {
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		files = append(files, filepath.Join(auditDir, entry.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func evaluateSensitiveDenyCoverage(policyText string) (bool, []string, []string) {
	categories := []struct {
		label    string
		keywords []string
	}{
		{label: "/etc/shadow", keywords: []string{"/etc/shadow", "etc/shadow"}},
		{label: "~/.ssh", keywords: []string{"~/.ssh", ".ssh/", ".ssh\\"}},
		{label: ".env", keywords: []string{".env"}},
		{label: "credentials", keywords: []string{"credentials"}},
	}

	lines := strings.Split(strings.ToLower(policyText), "\n")
	denyLines := make([]int, 0)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "action:") && strings.Contains(trimmed, "deny") {
			denyLines = append(denyLines, i)
		}
	}
	if len(denyLines) == 0 {
		missing := make([]string, 0, len(categories))
		for _, cat := range categories {
			missing = append(missing, cat.label)
		}
		return false, nil, missing
	}

	found := make([]string, 0)
	missing := make([]string, 0)
	for _, cat := range categories {
		if hasDenyCoverageForCategory(lines, denyLines, cat.keywords) {
			found = append(found, cat.label)
		} else {
			missing = append(missing, cat.label)
		}
	}

	return len(missing) == 0, found, missing
}

func hasDenyCoverageForCategory(lines []string, denyLines []int, keywords []string) bool {
	const window = 20
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		matchedKeyword := false
		for _, kw := range keywords {
			if strings.Contains(line, kw) {
				matchedKeyword = true
				break
			}
		}
		if !matchedKeyword {
			continue
		}

		for _, denyIdx := range denyLines {
			if absInt(i-denyIdx) <= window {
				return true
			}
		}
	}
	return false
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func expandHomePath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", nil
	}
	if trimmed == "~" || strings.HasPrefix(trimmed, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if trimmed == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(trimmed, "~/")), nil
	}
	return trimmed, nil
}

func generateUUID4() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		fallback := make([]byte, 16)
		for i := range fallback {
			fallback[i] = byte(i * 17)
		}
		buf = fallback
	}

	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80

	hexStr := hex.EncodeToString(buf)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32])
}

func FormatAIUC1TextReport(report *AIUC1Report) string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "AIUC-1 Compliance Report\n")
	_, _ = fmt.Fprintf(&b, "========================\n")
	_, _ = fmt.Fprintf(&b, "Report ID: %s\n", report.ReportID)
	_, _ = fmt.Fprintf(&b, "Generated: %s\n", report.GeneratedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(&b, "Period: %s to %s\n", report.Period.Since.Format(time.RFC3339), report.Period.Until.Format(time.RFC3339))
	_, _ = fmt.Fprintf(&b, "Rampart Version: %s\n", report.RampartVersion)
	_, _ = fmt.Fprintf(&b, "Standard: %s\n", report.Standard)
	_, _ = fmt.Fprintf(&b, "Overall Status: %s\n\n", report.Summary.ComplianceStatus)

	counts := report.Summary.DecisionCounts
	_, _ = fmt.Fprintf(&b, "Decision Counts\n")
	_, _ = fmt.Fprintf(&b, "---------------\n")
	_, _ = fmt.Fprintf(&b, "Total: %d\n", counts.Total)
	_, _ = fmt.Fprintf(&b, "Allow: %d\n", counts.Allow)
	_, _ = fmt.Fprintf(&b, "Deny: %d\n", counts.Deny)
	_, _ = fmt.Fprintf(&b, "Log: %d\n", counts.Log)
	_, _ = fmt.Fprintf(&b, "Ask: %d\n", counts.Ask)
	_, _ = fmt.Fprintf(&b, "Other: %d\n\n", counts.Other)

	keys := []string{"AIUC-1.1", "AIUC-1.2", "AIUC-1.3", "AIUC-1.4"}
	_, _ = fmt.Fprintf(&b, "Controls\n")
	_, _ = fmt.Fprintf(&b, "--------\n")
	for _, key := range keys {
		control := report.Controls[key]
		_, _ = fmt.Fprintf(&b, "%s %-4s %s\n", key, string(control.Status), control.Name)
		for _, evidence := range control.Evidence {
			_, _ = fmt.Fprintf(&b, "  - %s\n", evidence)
		}
	}

	return b.String()
}
