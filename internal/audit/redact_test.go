// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"strings"
	"testing"
)

type captureAuditSink struct {
	event   Event
	flushes int
	closes  int
}

func (s *captureAuditSink) Write(event Event) error { s.event = event; return nil }
func (s *captureAuditSink) Flush() error            { s.flushes++; return nil }
func (s *captureAuditSink) Close() error            { s.closes++; return nil }

func TestRedactEventScrubsSecretsWithoutMutatingSource(t *testing.T) {
	command := `curl -H 'Authorization: Bearer top-secret-token' https://example.com`
	event := Event{
		Request: map[string]any{
			"command":     command,
			"command_b64": "encoded-secret-copy",
			"path":        "/workspace/main.go",
			"headers": map[string]any{
				"Authorization": "Bearer nested-secret",
				"Accept":        "application/json",
			},
		},
		Decision: EventDecision{
			Message:     "blocked " + command,
			Suggestions: []string{"rampart allow " + command},
		},
	}

	redacted := RedactEvent(event)
	if got := redacted.Request["command"].(string); strings.Contains(got, "top-secret-token") || !strings.Contains(got, redactedValue) {
		t.Fatalf("redacted command = %q", got)
	}
	if redacted.Request["command_b64"] != redactedValue {
		t.Fatalf("command_b64 = %v, want redacted", redacted.Request["command_b64"])
	}
	headers := redacted.Request["headers"].(map[string]any)
	if headers["Authorization"] != redactedValue || headers["Accept"] != "application/json" {
		t.Fatalf("redacted headers = %#v", headers)
	}
	if redacted.Request["path"] != "/workspace/main.go" {
		t.Fatalf("safe path changed: %v", redacted.Request["path"])
	}
	if strings.Contains(redacted.Decision.Message, "top-secret-token") || strings.Contains(redacted.Decision.Suggestions[0], "top-secret-token") {
		t.Fatal("decision metadata retained credential material")
	}
	if event.Request["command"] != command || event.Request["command_b64"] != "encoded-secret-copy" {
		t.Fatal("source event was mutated")
	}
}

func TestRedactingSinkSanitizesBeforeDelegating(t *testing.T) {
	capture := &captureAuditSink{}
	sink := NewRedactingSink(capture)
	if err := sink.Write(Event{Request: map[string]any{"api_key": "secret-value", "path": "/tmp/file"}}); err != nil {
		t.Fatal(err)
	}
	if capture.event.Request["api_key"] != redactedValue || capture.event.Request["path"] != "/tmp/file" {
		t.Fatalf("captured request = %#v", capture.event.Request)
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if capture.flushes != 1 || capture.closes != 1 {
		t.Fatalf("delegation counts: flush=%d close=%d", capture.flushes, capture.closes)
	}
}
