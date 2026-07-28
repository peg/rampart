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

package webhookaction

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/engine"
)

func TestExecuteRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"decision":"allow","reason":"` + strings.Repeat("x", maxResponseBytes) + `"}`))
	}))
	defer server.Close()

	decision := Execute(nil, engine.ToolCall{Tool: "exec"}, engine.Decision{
		Action:        engine.ActionWebhook,
		WebhookConfig: &engine.WebhookActionConfig{URL: server.URL},
	})
	if decision.Action != engine.ActionDeny {
		t.Fatalf("action = %s, want deny", decision.Action)
	}
}

func TestExecuteDoesNotExposeWebhookCredentialsOnFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	secretURL := server.URL + "/hooks/private-token?signature=also-secret"
	server.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	decision := Execute(logger, engine.ToolCall{Tool: "exec"}, engine.Decision{
		Action:          engine.ActionWebhook,
		MatchedPolicies: []string{"remote-check"},
		WebhookConfig:   &engine.WebhookActionConfig{URL: secretURL},
	})
	if decision.Action != engine.ActionDeny {
		t.Fatalf("action = %s, want deny", decision.Action)
	}
	combined := logs.String() + decision.Message
	for _, secret := range []string{"private-token", "also-secret"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("webhook credential %q leaked in diagnostics: %s", secret, combined)
		}
	}
}
