//go:build !windows

// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// ...

package audit

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func testEvent() Event {
	return Event{
		ID:        "01JTEST000000000000000000",
		Timestamp: time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC),
		Agent:     "test-agent",
		Session:   "sess-1",
		Tool:      "exec",
		Request: map[string]any{
			"command": "rm -rf /",
			"path":    "/tmp/test",
		},
		Decision: EventDecision{
			Action:          "deny",
			MatchedPolicies: []string{"no-destructive"},
			EvalTimeUS:      42,
			Message:         "blocked destructive command",
		},
	}
}

func TestFormatCEF_Basic(t *testing.T) {
	e := testEvent()
	cef := FormatCEF(e)

	if !strings.HasPrefix(cef, "CEF:0|Rampart|PolicyEngine|") {
		t.Fatalf("bad CEF prefix: %s", cef)
	}
	if !strings.Contains(cef, "|deny|") {
		t.Errorf("missing action in CEF: %s", cef)
	}
	if !strings.Contains(cef, "|8|") {
		t.Errorf("missing severity 8 for deny: %s", cef)
	}
	if !strings.Contains(cef, "src=test-agent") {
		t.Errorf("missing src: %s", cef)
	}
	if !strings.Contains(cef, "cmd=rm -rf /") {
		t.Errorf("missing cmd: %s", cef)
	}
	if !strings.Contains(cef, "path=/tmp/test") {
		t.Errorf("missing path: %s", cef)
	}
	if !strings.Contains(cef, "policy=no-destructive") {
		t.Errorf("missing policy: %s", cef)
	}
}

func TestFormatCEF_AllActions(t *testing.T) {
	tests := []struct {
		action   string
		severity int
	}{
		{"deny", 8},
		{"ask", 5},
		{"log", 3},
		{"allow", 1},
	}
	for _, tc := range tests {
		e := testEvent()
		e.Decision.Action = tc.action
		cef := FormatCEF(e)
		expected := strings.Repeat("", 0) + "|" + tc.action + "|"
		if !strings.Contains(cef, expected) {
			t.Errorf("action %s not in CEF: %s", tc.action, cef)
		}
		sevStr := strings.Repeat("", 0) + "|" + string(rune('0'+tc.severity))
		if tc.severity == 8 {
			sevStr = "|8|"
		} else if tc.severity == 5 {
			sevStr = "|5|"
		} else if tc.severity == 3 {
			sevStr = "|3|"
		} else {
			sevStr = "|1|"
		}
		if !strings.Contains(cef, sevStr) {
			t.Errorf("severity %d not in CEF for %s: %s", tc.severity, tc.action, cef)
		}
	}
}

func TestFormatCEF_EscapePipes(t *testing.T) {
	e := testEvent()
	e.Decision.Message = "pipe|in|message"
	cef := FormatCEF(e)
	if strings.Contains(cef, "pipe|in") {
		t.Errorf("unescaped pipes in header: %s", cef)
	}
	if !strings.Contains(cef, `pipe\|in\|message`) {
		t.Errorf("pipes not escaped: %s", cef)
	}
}

func TestSyslogJSONFormat(t *testing.T) {
	e := testEvent()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Decision.Action != "deny" {
		t.Errorf("roundtrip failed: %s", decoded.Decision.Action)
	}
}

func TestMultiSink_FanOut(t *testing.T) {
	var written []Event
	primary := &mockSink{writeFn: func(e Event) error {
		written = append(written, e)
		return nil
	}}

	// No syslog/cef — just verify MultiSink passes through to primary.
	ms := NewMultiSink(primary, nil, nil, nil)
	e := testEvent()
	if err := ms.Write(e); err != nil {
		t.Fatal(err)
	}
	if err := ms.Close(); err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 {
		t.Fatalf("expected 1 write, got %d", len(written))
	}
}

func TestCEFFileSink_Write(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/cef.log"
	sink, err := NewCEFFileSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := testEvent()
	sink.Send(e)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	// Verify file contains CEF.
	data, _ := readFileBytes(path)
	if !strings.Contains(string(data), "CEF:0|Rampart|") {
		t.Errorf("cef.log missing CEF header: %s", string(data))
	}
}

type mockSink struct {
	writeFn func(Event) error
}

func (m *mockSink) Write(e Event) error { return m.writeFn(e) }
func (m *mockSink) Flush() error        { return nil }
func (m *mockSink) Close() error        { return nil }

func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}
