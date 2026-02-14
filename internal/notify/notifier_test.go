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

package notify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetectPlatform(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://hooks.slack.com/services/EXAMPLE/EXAMPLE/EXAMPLE", "slack"},
		{"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz", "discord"},
		{"https://outlook.office.com/webhook/abcd-1234-efgh-5678/IncomingWebhook/xyz", "teams"},
		{"https://webhook.office.com/webhookb2/abcd-1234-efgh-5678@tenant.onmicrosoft.com/IncomingWebhook/xyz", "teams"},
		{"https://hooks.openclaw.dev/events", "openclaw"},
		{"https://api.openclaw.ai/webhooks/123", "openclaw"},
		{"https://notify.openclaw.io/v1/events", "openclaw"},
		{"https://example.com/webhook", "webhook"},
		{"http://localhost:8080/notifications", "webhook"},
		{"https://mycompany.com/openclaw-events/handler", "webhook"}, // substring, not domain match
		{"http://localhost:9090/openclaw/callback", "webhook"},       // localhost with openclaw path
	}

	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			result := DetectPlatform(test.url)
			if result != test.expected {
				t.Errorf("DetectPlatform(%s) = %s, want %s", test.url, result, test.expected)
			}
		})
	}
}

func TestNewNotifier(t *testing.T) {
	tests := []struct {
		url      string
		platform string
		expected string
	}{
		{"https://hooks.slack.com/services/test", "slack", "*notify.SlackNotifier"},
		{"https://discord.com/api/webhooks/test", "discord", "*notify.DiscordNotifier"},
		{"https://webhook.office.com/test", "teams", "*notify.TeamsNotifier"},
		{"https://hooks.openclaw.dev/events", "openclaw", "*notify.OpenClawNotifier"},
		{"https://example.com/webhook", "webhook", "*notify.GenericNotifier"},
		{"https://hooks.slack.com/services/test", "auto", "*notify.SlackNotifier"},
		{"https://discord.com/api/webhooks/test", "", "*notify.DiscordNotifier"},
		{"https://hooks.openclaw.dev/events", "", "*notify.OpenClawNotifier"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s-%s", test.platform, test.url), func(t *testing.T) {
			notifier := NewNotifier(test.url, test.platform)
			typeName := fmt.Sprintf("%T", notifier)
			if typeName != test.expected {
				t.Errorf("NewNotifier(%s, %s) type = %s, want %s", test.url, test.platform, typeName, test.expected)
			}
		})
	}
}

func TestGenericNotifier_Send(t *testing.T) {
	// Create test event
	event := NotifyEvent{
		Action:    "deny",
		Tool:      "exec",
		Command:   "rm -rf /",
		Policy:    "dangerous-commands",
		Message:   "Destructive command not allowed",
		Agent:     "test-agent",
		Timestamp: "2026-02-11T08:30:00Z",
	}

	// Create test server
	var receivedPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Test notifier
	notifier := NewGenericNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Errorf("Send() error = %v", err)
	}

	if got := receivedPayload["action"]; got != event.Action {
		t.Fatalf("action = %v, want %s", got, event.Action)
	}
	if got := receivedPayload["tool"]; got != event.Tool {
		t.Fatalf("tool = %v, want %s", got, event.Tool)
	}
	if got := receivedPayload["command"]; got != event.Command {
		t.Fatalf("command = %v, want %s", got, event.Command)
	}
	if got := receivedPayload["policy"]; got != event.Policy {
		t.Fatalf("policy = %v, want %s", got, event.Policy)
	}
	if got := receivedPayload["message"]; got != event.Message {
		t.Fatalf("message = %v, want %s", got, event.Message)
	}
	if got := receivedPayload["agent"]; got != event.Agent {
		t.Fatalf("agent = %v, want %s", got, event.Agent)
	}
	if got := receivedPayload["timestamp"]; got != event.Timestamp {
		t.Fatalf("timestamp = %v, want %s", got, event.Timestamp)
	}
}

func TestSlackNotifier_Send(t *testing.T) {
	event := NotifyEvent{
		Action:    "log",
		Tool:      "read",
		Command:   "/etc/passwd",
		Policy:    "sensitive-files",
		Message:   "Reading sensitive file",
		Agent:     "test-agent",
		Timestamp: "2026-02-11T08:30:00Z",
	}

	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Verify Slack-specific structure
	attachments, ok := receivedPayload["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Error("Expected attachments array")
		return
	}

	attachment := attachments[0].(map[string]interface{})
	if attachment["color"] != "#d29922" {
		t.Errorf("Expected orange color for log action, got %s", attachment["color"])
	}

	blocks, ok := attachment["blocks"].([]interface{})
	if !ok || len(blocks) == 0 {
		t.Error("Expected blocks array")
	}
}

func TestDiscordNotifier_Send(t *testing.T) {
	event := NotifyEvent{
		Action:    "deny",
		Tool:      "exec",
		Command:   "sudo rm -rf /",
		Policy:    "admin-commands",
		Message:   "Admin command denied",
		Agent:     "test-agent",
		Timestamp: "2026-02-11T08:30:00Z",
	}

	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewDiscordNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Verify Discord-specific structure
	embeds, ok := receivedPayload["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Error("Expected embeds array")
		return
	}

	embed := embeds[0].(map[string]interface{})
	if embed["title"] != "Rampart: Command Denied" {
		t.Errorf("Expected deny title, got %s", embed["title"])
	}
	if embed["color"] != float64(0xf85149) {
		t.Errorf("Expected red color for deny action, got %v", embed["color"])
	}

	fields, ok := embed["fields"].([]interface{})
	if !ok || len(fields) == 0 {
		t.Error("Expected fields array")
	}
}

func TestTeamsNotifier_Send(t *testing.T) {
	event := NotifyEvent{
		Action:    "deny",
		Tool:      "write",
		Command:   "/etc/hosts",
		Policy:    "system-files",
		Message:   "System file modification denied",
		Agent:     "test-agent",
		Timestamp: "2026-02-11T08:30:00Z",
	}

	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewTeamsNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Verify Teams-specific structure
	if receivedPayload["@type"] != "MessageCard" {
		t.Errorf("Expected MessageCard type, got %s", receivedPayload["@type"])
	}
	if receivedPayload["themeColor"] != "f85149" {
		t.Errorf("Expected red theme color for deny action, got %s", receivedPayload["themeColor"])
	}
	if !strings.Contains(receivedPayload["title"].(string), "Command Denied") {
		t.Errorf("Expected deny title, got %s", receivedPayload["title"])
	}

	sections, ok := receivedPayload["sections"].([]interface{})
	if !ok || len(sections) == 0 {
		t.Error("Expected sections array")
		return
	}

	section := sections[0].(map[string]interface{})
	facts, ok := section["facts"].([]interface{})
	if !ok || len(facts) == 0 {
		t.Error("Expected facts array")
	}
}

func TestNotifierErrorHandling(t *testing.T) {
	// Test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	event := NotifyEvent{
		Action: "deny",
		Tool:   "exec",
	}

	notifiers := []Notifier{
		NewGenericNotifier(server.URL),
		NewSlackNotifier(server.URL),
		NewDiscordNotifier(server.URL),
		NewTeamsNotifier(server.URL),
	}

	for i, notifier := range notifiers {
		t.Run(fmt.Sprintf("notifier-%d", i), func(t *testing.T) {
			if err := notifier.Send(event); err == nil {
				t.Error("Expected error for bad request, got nil")
			}
		})
	}
}

func TestGenericNotifier_SendRequireApproval(t *testing.T) {
	event := NotifyEvent{
		Action:     "require_approval",
		Tool:       "exec",
		Command:    "kubectl delete pod x",
		Policy:     "prod-guardrails",
		Message:    "Approval needed for production changes",
		Agent:      "test-agent",
		Timestamp:  "2026-02-11T08:30:00Z",
		ApprovalID: "01JKV8PY8NJWQ2Y0C4YQ4JQ9M8",
		ExpiresAt:  "2026-02-11T08:35:00Z",
		ResolveURL: "http://localhost:9090/v1/approvals/01JKV8PY8NJWQ2Y0C4YQ4JQ9M8/resolve",
	}

	var receivedPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewGenericNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := receivedPayload["approval_id"]; got != event.ApprovalID {
		t.Fatalf("approval_id = %v, want %s", got, event.ApprovalID)
	}
	if got := receivedPayload["expires_at"]; got != event.ExpiresAt {
		t.Fatalf("expires_at = %v, want %s", got, event.ExpiresAt)
	}
	if got := receivedPayload["resolve_url"]; got != event.ResolveURL {
		t.Fatalf("resolve_url = %v, want %s", got, event.ResolveURL)
	}
}

func TestDiscordNotifier_SendRequireApproval(t *testing.T) {
	event := NotifyEvent{
		Action:     "require_approval",
		Tool:       "exec",
		Command:    "terraform apply",
		Agent:      "test-agent",
		Timestamp:  "2026-02-11T08:30:00Z",
		ApprovalID: "01JKV8PY8NJWQ2Y0C4YQ4JQ9M8",
		ExpiresAt:  "2026-02-11T08:35:00Z",
		ResolveURL: "http://localhost:9090/v1/approvals/01JKV8PY8NJWQ2Y0C4YQ4JQ9M8/resolve",
	}

	var receivedPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewDiscordNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	embeds := receivedPayload["embeds"].([]any)
	embed := embeds[0].(map[string]any)
	if got := embed["title"]; got != "Rampart: Approval Required" {
		t.Fatalf("title = %v, want Rampart: Approval Required", got)
	}
	if got := embed["color"]; got != float64(0xd29922) {
		t.Fatalf("color = %v, want %v", got, float64(0xd29922))
	}

	fields := embed["fields"].([]any)
	raw, _ := json.Marshal(fields)
	if !strings.Contains(string(raw), "Approval ID") {
		t.Fatalf("fields missing Approval ID: %s", raw)
	}
	if !strings.Contains(string(raw), event.ResolveURL) {
		t.Fatalf("fields missing resolve URL: %s", raw)
	}
}

func TestSlackNotifier_SendRequireApproval(t *testing.T) {
	event := NotifyEvent{
		Action:     "require_approval",
		Tool:       "exec",
		Command:    "terraform apply",
		Agent:      "test-agent",
		Timestamp:  "2026-02-11T08:30:00Z",
		ApprovalID: "01JKV8PY8NJWQ2Y0C4YQ4JQ9M8",
		ExpiresAt:  "2026-02-11T08:35:00Z",
		ResolveURL: "http://localhost:9090/v1/approvals/01JKV8PY8NJWQ2Y0C4YQ4JQ9M8/resolve",
	}

	var receivedPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	attachments := receivedPayload["attachments"].([]any)
	attachment := attachments[0].(map[string]any)
	if got := attachment["color"]; got != "#d29922" {
		t.Fatalf("color = %v, want #d29922", got)
	}
	raw, _ := json.Marshal(attachment["blocks"])
	if !strings.Contains(string(raw), "Approval Required") {
		t.Fatalf("blocks missing approval title: %s", raw)
	}
	if !strings.Contains(string(raw), event.ResolveURL) {
		t.Fatalf("blocks missing resolve URL: %s", raw)
	}
}

func TestTeamsNotifier_SendRequireApproval(t *testing.T) {
	event := NotifyEvent{
		Action:     "require_approval",
		Tool:       "exec",
		Command:    "terraform apply",
		Agent:      "test-agent",
		Timestamp:  "2026-02-11T08:30:00Z",
		ApprovalID: "01JKV8PY8NJWQ2Y0C4YQ4JQ9M8",
		ExpiresAt:  "2026-02-11T08:35:00Z",
		ResolveURL: "http://localhost:9090/v1/approvals/01JKV8PY8NJWQ2Y0C4YQ4JQ9M8/resolve",
	}

	var receivedPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewTeamsNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := receivedPayload["themeColor"]; got != "d29922" {
		t.Fatalf("themeColor = %v, want d29922", got)
	}
	if !strings.Contains(receivedPayload["title"].(string), "Approval Required") {
		t.Fatalf("title = %v, expected Approval Required", receivedPayload["title"])
	}

	raw, _ := json.Marshal(receivedPayload["sections"])
	if !strings.Contains(string(raw), "Approval ID") {
		t.Fatalf("sections missing Approval ID: %s", raw)
	}
	if !strings.Contains(string(raw), event.ResolveURL) {
		t.Fatalf("sections missing resolve URL: %s", raw)
	}
}

func TestOpenClawNotifier_SendRequireApproval(t *testing.T) {
	event := NotifyEvent{
		Action:     "require_approval",
		Tool:       "exec",
		Command:    "kubectl delete pod x",
		Agent:      "codex",
		Timestamp:  "2026-02-11T08:30:00Z",
		ApprovalID: "01JKV8PY8NJWQ2Y0C4YQ4JQ9M8",
		ExpiresAt:  "2026-02-11T08:35:00Z",
		ResolveURL: "http://localhost:9091/v1/approvals/01JKV8PY8NJWQ2Y0C4YQ4JQ9M8/resolve",
	}

	var receivedPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewOpenClawNotifier(server.URL)
	if err := notifier.Send(event); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := receivedPayload["approval_id"]; got != event.ApprovalID {
		t.Fatalf("approval_id = %v, want %s", got, event.ApprovalID)
	}
	if got := receivedPayload["resolve_url"]; got != event.ResolveURL {
		t.Fatalf("resolve_url = %v, want %s", got, event.ResolveURL)
	}
	if got := receivedPayload["expires_at"]; got != event.ExpiresAt {
		t.Fatalf("expires_at = %v, want %s", got, event.ExpiresAt)
	}
	text, _ := receivedPayload["text"].(string)
	if !strings.Contains(text, "Approval required") || !strings.Contains(text, event.ResolveURL) {
		t.Fatalf("text = %q, expected approval instruction with resolve URL", text)
	}
}
