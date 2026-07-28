// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	compactedRequestKey = "_rampart_compacted"
	truncationMarker    = "... [truncated]"
	maxIdentifierRunes  = 4096
)

// MarshalRecord applies event defaults, deterministically compacts fields when
// necessary, computes the event hash after compaction, and marshals one JSONL
// record (without its trailing newline). It is the common record encoder for
// chained sinks and direct hook/MCP appenders.
func MarshalRecord(event Event) ([]byte, error) {
	_, line, err := marshalRecord(event)
	return line, err
}

func marshalRecord(event Event) (Event, []byte, error) {
	event = applyEventDefaults(event)
	event.Hash = ""
	if event.CompactedFields != nil {
		fields := make(map[string]FieldCompaction, len(event.CompactedFields))
		for name, info := range event.CompactedFields {
			fields[name] = info
		}
		event.CompactedFields = fields
	}

	compacted, err := compactRecord(event)
	if err != nil {
		return Event{}, nil, err
	}
	if err := compacted.ComputeHash(); err != nil {
		return Event{}, nil, fmt.Errorf("audit: compute hash: %w", err)
	}
	line, err := json.Marshal(compacted)
	if err != nil {
		return Event{}, nil, fmt.Errorf("audit: marshal event: %w", err)
	}
	if len(line) > MaxRecordBytes {
		return Event{}, nil, errRecordTooLarge
	}
	return compacted, line, nil
}

func marshalHashedRecord(event Event) ([]byte, error) {
	event.Hash = ""
	if err := event.ComputeHash(); err != nil {
		return nil, fmt.Errorf("audit: compute hash: %w", err)
	}
	line, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal event: %w", err)
	}
	return line, nil
}

func recordFits(event Event) (bool, error) {
	line, err := marshalHashedRecord(event)
	if err != nil {
		return false, err
	}
	return len(line) <= MaxRecordBytes, nil
}

func compactRecord(event Event) (Event, error) {
	if ok, err := recordFits(event); err != nil || ok {
		return event, err
	}

	requestJSON, err := json.Marshal(event.Request)
	if err != nil {
		return Event{}, fmt.Errorf("audit: marshal request for compaction: %w", err)
	}
	// Large request objects are the common source of oversize records. Compact
	// them first, but only after proving the complete event cannot fit unchanged.
	if len(requestJSON) > MaxRecordBytes/2 {
		event = compactRequest(event, requestJSON)
		if ok, fitErr := recordFits(event); fitErr != nil || ok {
			return event, fitErr
		}
	}

	// Suggestions are reproducible guidance and less important than the policy
	// verdict itself, so discard them before shortening the decision message.
	if len(event.Decision.Suggestions) > 0 {
		encoded, marshalErr := json.Marshal(event.Decision.Suggestions)
		if marshalErr != nil {
			return Event{}, fmt.Errorf("audit: marshal decision suggestions for compaction: %w", marshalErr)
		}
		event.setCompaction("decision.suggestions", encoded, "dropped")
		event.Decision.Suggestions = nil
		if ok, fitErr := recordFits(event); fitErr != nil || ok {
			return event, fitErr
		}
	}

	if event.Decision.Message != "" {
		encoded, marshalErr := json.Marshal(event.Decision.Message)
		if marshalErr != nil {
			return Event{}, fmt.Errorf("audit: marshal decision message for compaction: %w", marshalErr)
		}
		event.setCompaction("decision.message", encoded, "truncated")
		event = truncateDecisionMessageToFit(event)
		if ok, fitErr := recordFits(event); fitErr != nil || ok {
			return event, fitErr
		}
	}

	if len(event.ApprovalOwner) > 0 {
		encoded, marshalErr := json.Marshal(event.ApprovalOwner)
		if marshalErr != nil {
			return Event{}, fmt.Errorf("audit: marshal approval owner for compaction: %w", marshalErr)
		}
		event.setCompaction("approval_owner", encoded, "replaced")
		event.ApprovalOwner = compactedMap(encoded)
		if ok, fitErr := recordFits(event); fitErr != nil || ok {
			return event, fitErr
		}
	}

	if event.Response != nil {
		encoded, marshalErr := json.Marshal(event.Response)
		if marshalErr != nil {
			return Event{}, fmt.Errorf("audit: marshal response for compaction: %w", marshalErr)
		}
		event.setCompaction("response", encoded, "dropped")
		event.Response = nil
		if ok, fitErr := recordFits(event); fitErr != nil || ok {
			return event, fitErr
		}
	}

	if len(event.Decision.MatchedPolicies) > 0 {
		encoded, marshalErr := json.Marshal(event.Decision.MatchedPolicies)
		if marshalErr != nil {
			return Event{}, fmt.Errorf("audit: marshal matched policies for compaction: %w", marshalErr)
		}
		event.setCompaction("decision.matched_policies", encoded, "dropped")
		event.Decision.MatchedPolicies = nil
		if ok, fitErr := recordFits(event); fitErr != nil || ok {
			return event, fitErr
		}
	}

	// A moderately sized request can still be the remaining contributor when
	// several fields combine to exceed the limit. Preserve it until reproducible
	// guidance and optional response/correlation fields have been reduced.
	_, requestCompacted := event.CompactedFields["request"]
	if !requestCompacted && len(event.Request) > 0 {
		event = compactRequest(event, requestJSON)
		if ok, fitErr := recordFits(event); fitErr != nil || ok {
			return event, fitErr
		}
	}

	// Tool protocol inputs are bounded, but identifiers inside those inputs can
	// still consume nearly the whole allowance. Retain a readable prefix and a
	// digest rather than allowing one identifier to create an audit gap.
	truncateStringField(&event, "agent", &event.Agent)
	truncateStringField(&event, "session", &event.Session)
	truncateStringField(&event, "run_id", &event.RunID)
	truncateStringField(&event, "tool_call_id", &event.ToolCallID)
	truncateStringField(&event, "tool", &event.Tool)
	if ok, fitErr := recordFits(event); fitErr != nil || ok {
		return event, fitErr
	}

	return Event{}, errRecordTooLarge
}

func compactRequest(event Event, encoded []byte) Event {
	event.setCompaction("request", encoded, "replaced")
	event.Request = compactedMap(encoded)
	return event
}

func compactedMap(encoded []byte) map[string]any {
	return map[string]any{
		compactedRequestKey: map[string]any{
			"original_json_bytes": len(encoded),
			"sha256":              digest(encoded),
		},
	}
}

func (event *Event) setCompaction(field string, encoded []byte, disposition string) {
	if event.CompactedFields == nil {
		event.CompactedFields = make(map[string]FieldCompaction)
	}
	event.CompactedFields[field] = FieldCompaction{
		OriginalJSONBytes: len(encoded),
		SHA256:            digest(encoded),
		Disposition:       disposition,
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func truncateDecisionMessageToFit(event Event) Event {
	original := []rune(event.Decision.Message)
	best := ""
	low, high := 0, len(original)
	for low <= high {
		mid := low + (high-low)/2
		candidate := event
		candidate.Decision.Message = truncatedPrefix(original, mid)
		ok, err := recordFits(candidate)
		if err == nil && ok {
			best = candidate.Decision.Message
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	event.Decision.Message = best
	return event
}

func truncatedPrefix(value []rune, prefixLen int) string {
	if prefixLen >= len(value) {
		return string(value)
	}
	if prefixLen <= 0 {
		return ""
	}
	return string(value[:prefixLen]) + truncationMarker
}

func truncateStringField(event *Event, name string, value *string) {
	runes := []rune(*value)
	if len(runes) <= maxIdentifierRunes {
		return
	}
	encoded, err := json.Marshal(*value)
	if err != nil {
		return
	}
	event.setCompaction(name, encoded, "truncated")
	*value = string(runes[:maxIdentifierRunes]) + truncationMarker
}
