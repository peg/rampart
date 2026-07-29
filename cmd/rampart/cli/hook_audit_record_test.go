// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
)

func TestReadBoundedHookInput(t *testing.T) {
	accepted := strings.Repeat("x", maxHookInputBytes)
	got, err := readBoundedHookInput(strings.NewReader(accepted))
	if err != nil {
		t.Fatalf("read limit-sized input: %v", err)
	}
	if len(got) != maxHookInputBytes {
		t.Fatalf("read %d bytes, want %d", len(got), maxHookInputBytes)
	}

	_, err = readBoundedHookInput(strings.NewReader(accepted + "x"))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized input error = %v, want size-limit error", err)
	}
}

func TestHookAuditCompactsEscapedNearMiBRequest(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	policyPath := filepath.Join(home, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: \"1\"\ndefault_action: allow\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	auditDir := filepath.Join(home, "audit")
	payload := `{"session_id":"audit-large","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` +
		strings.Repeat("<", 1024*1024-2048) + `"}}`

	_, _, err := runHookWithStdin(t, &rootOptions{configPath: policyPath}, payload,
		"--mode", "enforce", "--audit-dir", auditDir)
	if err != nil {
		t.Fatalf("run hook: %v", err)
	}

	path := filepath.Join(auditDir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	events, _, err := audit.ReadEventsFromOffset(path, 0)
	if err != nil {
		t.Fatalf("read hook audit: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("read %d hook audit events, want 1", len(events))
	}
	event := events[0]
	if _, ok := event.CompactedFields["request"]; !ok {
		t.Fatal("hook audit request was not compacted")
	}
	if ok, verifyErr := event.VerifyHash(); verifyErr != nil || !ok {
		t.Fatalf("hook audit hash valid = %v, error = %v", ok, verifyErr)
	}
}
