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

package proxy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
)

// WithAuditDir sets the audit log directory for history API endpoints.
func WithAuditDir(dir string) Option {
	return func(s *Server) {
		s.auditDir = dir
	}
}

// handleAuditEvents serves GET /v1/audit/events — query audit events with pagination and filtering.
func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if s.auditDir == "" {
		writeError(w, http.StatusServiceUnavailable, "audit directory not configured")
		return
	}

	q := r.URL.Query()
	date := q.Get("date")
	if date == "" {
		date = time.Now().UTC().Format("2006-01-02")
	}
	if _, err := time.Parse("2006-01-02", date); err != nil {
		writeError(w, http.StatusBadRequest, "invalid date format, expected YYYY-MM-DD")
		return
	}

	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}

	offset := int64(0)
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			offset = n
		}
	}

	toolFilter := q.Get("tool")
	actionFilter := q.Get("action")
	agentFilter := q.Get("agent")

	// Find matching files for this date (may have rotation parts like 2026-02-18.p1.jsonl).
	files := s.auditFilesForDate(date)
	if len(files) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"events":        []any{},
			"total_in_file": 0,
			"next_offset":   0,
			"date":          date,
		})
		return
	}

	// Read all events from all files for this date.
	// NOTE: For very large files this loads everything into memory. Fine for now,
	// but a streaming reverse-reader would be needed for scale.
	var allEvents []audit.Event
	for _, f := range files {
		events, _, err := audit.ReadEventsFromOffset(f, 0)
		if err != nil {
			s.logger.Error("proxy: audit read failed", "file", f, "error", err)
			continue
		}
		allEvents = append(allEvents, events...)
	}

	totalInFile := len(allEvents)

	// Apply filters.
	filtered := allEvents[:0:0]
	for _, evt := range allEvents {
		if toolFilter != "" && evt.Tool != toolFilter {
			continue
		}
		if actionFilter != "" && evt.Decision.Action != actionFilter {
			continue
		}
		if agentFilter != "" && evt.Agent != agentFilter {
			continue
		}
		filtered = append(filtered, evt)
	}

	// Reverse for most-recent-first.
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}

	// Pagination by index (offset here means event index, not byte offset, for filtered results).
	// We repurpose offset as event-index for the response since byte offset doesn't work well
	// with filtering + reversal.
	startIdx := int(offset)
	if startIdx > len(filtered) {
		startIdx = len(filtered)
	}
	endIdx := startIdx + limit
	if endIdx > len(filtered) {
		endIdx = len(filtered)
	}

	page := filtered[startIdx:endIdx]

	var nextOffset int64
	if endIdx < len(filtered) {
		nextOffset = int64(endIdx)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events":        page,
		"total_in_file": totalInFile,
		"next_offset":   nextOffset,
		"date":          date,
	})
}

// handleAuditDates serves GET /v1/audit/dates — list available audit log dates.
func (s *Server) handleAuditDates(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if s.auditDir == "" {
		writeError(w, http.StatusServiceUnavailable, "audit directory not configured")
		return
	}

	entries, err := os.ReadDir(s.auditDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read audit directory")
		return
	}

	dateSet := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		// Extract date from filename: "2026-02-18.jsonl" or "2026-02-18.p1.jsonl"
		name := e.Name()
		if len(name) >= 10 {
			d := name[:10]
			if _, err := time.Parse("2006-01-02", d); err == nil {
				dateSet[d] = true
			}
		}
	}

	dates := make([]string, 0, len(dateSet))
	for d := range dateSet {
		dates = append(dates, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dates)))

	writeJSON(w, http.StatusOK, map[string]any{
		"dates":     dates,
		"audit_dir": s.auditDir,
	})
}

// handleAuditExport serves GET /v1/audit/export — download a day's audit log as JSONL.
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if s.auditDir == "" {
		writeError(w, http.StatusServiceUnavailable, "audit directory not configured")
		return
	}

	date := r.URL.Query().Get("date")
	if date == "" {
		writeError(w, http.StatusBadRequest, "date parameter is required")
		return
	}
	if _, err := time.Parse("2006-01-02", date); err != nil {
		writeError(w, http.StatusBadRequest, "invalid date format, expected YYYY-MM-DD")
		return
	}

	files := s.auditFilesForDate(date)
	if len(files) == 0 {
		writeError(w, http.StatusNotFound, "no audit log found for "+date)
		return
	}

	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rampart-audit-%s.jsonl"`, date))
	w.WriteHeader(http.StatusOK)

	// Stream all files for this date.
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		_, _ = io.Copy(w, file)
		file.Close()
	}
}

// handleAuditStats serves GET /v1/audit/stats — quick stats for a date range.
func (s *Server) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if s.auditDir == "" {
		writeError(w, http.StatusServiceUnavailable, "audit directory not configured")
		return
	}

	q := r.URL.Query()
	today := time.Now().UTC().Format("2006-01-02")
	fromStr := q.Get("from")
	if fromStr == "" {
		fromStr = today
	}
	toStr := q.Get("to")
	if toStr == "" {
		toStr = today
	}

	fromDate, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid from date")
		return
	}
	toDate, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid to date")
		return
	}
	if toDate.Before(fromDate) {
		writeError(w, http.StatusBadRequest, "to date must not be before from date")
		return
	}

	totalEvents := 0
	byAction := map[string]int{}
	byTool := map[string]int{}
	byAgent := map[string]int{}

	for d := fromDate; !d.After(toDate); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")
		files := s.auditFilesForDate(dateStr)
		for _, f := range files {
			events, _, err := audit.ReadEventsFromOffset(f, 0)
			if err != nil {
				continue
			}
			for _, evt := range events {
				totalEvents++
				byAction[evt.Decision.Action]++
				byTool[evt.Tool]++
				if evt.Agent != "" {
					byAgent[evt.Agent]++
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_events": totalEvents,
		"by_action":    byAction,
		"by_tool":      byTool,
		"by_agent":     byAgent,
	})
}

// auditFilesForDate returns all JSONL file paths for a given date, sorted.
func (s *Server) auditFilesForDate(date string) []string {
	entries, err := os.ReadDir(s.auditDir)
	if err != nil {
		return nil
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		if strings.HasPrefix(e.Name(), date) {
			files = append(files, filepath.Join(s.auditDir, e.Name()))
		}
	}
	sort.Strings(files)
	return files
}
