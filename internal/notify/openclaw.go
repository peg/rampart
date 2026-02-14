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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OpenClawNotifier sends compact system-event-style payloads for OpenClaw.
type OpenClawNotifier struct {
	url    string
	client *http.Client
}

// NewOpenClawNotifier creates a new OpenClaw notifier.
func NewOpenClawNotifier(url string) *OpenClawNotifier {
	return &OpenClawNotifier{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

type openClawPayload struct {
	Text       string `json:"text"`
	ApprovalID string `json:"approval_id"`
	ResolveURL string `json:"resolve_url"`
	ExpiresAt  string `json:"expires_at"`
}

// Send posts an OpenClaw-friendly approval event payload.
func (n *OpenClawNotifier) Send(event NotifyEvent) error {
	payload := openClawPayload{
		Text:       fmt.Sprintf("🛡️ Rampart: Approval required for `%s` (agent: %s). Approve or deny at %s", event.Command, event.Agent, event.ResolveURL),
		ApprovalID: event.ApprovalID,
		ResolveURL: event.ResolveURL,
		ExpiresAt:  event.ExpiresAt,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal openclaw payload: %w", err)
	}

	resp, err := n.client.Post(n.url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("post openclaw webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("openclaw webhook returned status %d", resp.StatusCode)
	}

	return nil
}
