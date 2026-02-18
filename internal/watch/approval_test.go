// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package watch

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPendingApprovalsRendered(t *testing.T) {
	m := NewModel(Config{
		AuditFile: "/tmp/test.jsonl",
		ServeURL:  "http://localhost:9999", // enables approval client
	})
	m.pendingApprovals = []PendingApproval{
		{
			ID:        "abc123",
			Tool:      "exec",
			Command:   "kubectl delete pod nginx",
			Message:   "block-destructive",
			ExpiresAt: time.Now().Add(2*time.Minute + 13*time.Second),
		},
		{
			ID:        "def456",
			Tool:      "write",
			Command:   "/etc/hosts",
			Message:   "block-system-files",
			ExpiresAt: time.Now().Add(4*time.Minute + 1*time.Second),
		},
	}
	m.selectedApproval = 1

	view := m.View()
	assert.Contains(t, view, "PENDING APPROVALS")
	assert.Contains(t, view, "kubectl delete pod nginx")
	assert.Contains(t, view, "/etc/hosts")
	assert.Contains(t, view, "(a)pprove")
}

func TestKeybindingSelectAndApprove(t *testing.T) {
	m := NewModel(Config{
		AuditFile: "/tmp/test.jsonl",
		ServeURL:  "http://localhost:9999",
	})
	m.pendingApprovals = []PendingApproval{
		{ID: "abc123", Tool: "exec", Command: "rm -rf /", ExpiresAt: time.Now().Add(5 * time.Minute)},
		{ID: "def456", Tool: "write", Command: "/etc/hosts", ExpiresAt: time.Now().Add(5 * time.Minute)},
	}

	// Select approval 2.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	um := updated.(*Model)
	assert.Equal(t, 2, um.selectedApproval)

	// Select approval 1.
	updated, _ = um.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	um = updated.(*Model)
	assert.Equal(t, 1, um.selectedApproval)

	// Out of range selection ignored.
	updated, _ = um.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	um = updated.(*Model)
	assert.Equal(t, 1, um.selectedApproval) // unchanged
}

func TestKeybindingDeny(t *testing.T) {
	m := NewModel(Config{
		AuditFile: "/tmp/test.jsonl",
		ServeURL:  "http://localhost:9999",
	})
	m.pendingApprovals = []PendingApproval{
		{ID: "abc123", Tool: "exec", Command: "rm -rf /", ExpiresAt: time.Now().Add(5 * time.Minute)},
	}
	m.selectedApproval = 1

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	um := updated.(*Model)
	assert.Contains(t, um.resolveStatus, "Denying")
	assert.NotNil(t, cmd) // should have spawned a resolve command
}

func TestApprovalClientListPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/approvals", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(map[string]any{
			"approvals": []map[string]any{
				{"id": "a1", "tool": "exec", "command": "ls", "status": "pending",
					"created_at": time.Now().Format(time.RFC3339),
					"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339)},
				{"id": "a2", "tool": "write", "command": "/tmp/x", "status": "approved",
					"created_at": time.Now().Format(time.RFC3339),
					"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339)},
			},
		})
	}))
	defer srv.Close()

	client := NewApprovalClient(srv.URL, "test-token")
	approvals, err := client.ListPending(t.Context())
	require.NoError(t, err)
	assert.Len(t, approvals, 1) // only pending
	assert.Equal(t, "a1", approvals[0].ID)
}

func TestApprovalClientResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/approvals/abc123/resolve", r.URL.Path)
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, true, body["approved"])
		assert.Equal(t, "watch-tui", body["resolved_by"])
		fmt.Fprintf(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	client := NewApprovalClient(srv.URL, "")
	err := client.Resolve(t.Context(), "abc123", true)
	require.NoError(t, err)
}

func TestFormatDuration(t *testing.T) {
	assert.Equal(t, "0s", formatDuration(0))
	assert.Equal(t, "30s", formatDuration(30*time.Second))
	assert.Equal(t, "2m13s", formatDuration(2*time.Minute+13*time.Second))
	assert.Equal(t, "0s", formatDuration(-5*time.Second))
}

func TestNoApprovalsWithoutServeURL(t *testing.T) {
	m := NewModel(Config{AuditFile: "/tmp/test.jsonl"})
	assert.Nil(t, m.approvalClient)
	// Keybindings should be no-ops.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	um := updated.(*Model)
	assert.Equal(t, 0, um.selectedApproval)
}
