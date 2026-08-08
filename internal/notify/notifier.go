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

// Package notify sends webhook notifications for policy decisions.
package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// NotifyEvent contains the data for a webhook notification.
// Breaking change: JSON field names are now snake_case for all fields.
type NotifyEvent struct {
	Action    string `json:"action"`    // "deny", "watch", "ask", or legacy "require_approval"
	Tool      string `json:"tool"`      // e.g. "exec", "read", "write"
	Command   string `json:"command"`   // the command or path
	Policy    string `json:"policy"`    // policy name that matched
	Message   string `json:"message"`   // human-readable reason
	Agent     string `json:"agent"`     // agent identifier
	Timestamp string `json:"timestamp"` // ISO 8601

	ApprovalID string `json:"approval_id,omitempty"` // pending approval ID
	ExpiresAt  string `json:"expires_at,omitempty"`  // approval expiry timestamp (ISO 8601)
	ResolveURL string `json:"resolve_url,omitempty"` // direct URL to resolve the approval
}

func isApprovalAction(action string) bool {
	return action == "ask" || action == "require_approval"
}

// Notifier sends notifications.
type Notifier interface {
	Send(event NotifyEvent) error
}

// GenericNotifier sends notifications to any webhook URL by POSTing the event as JSON.
type GenericNotifier struct {
	url    string
	client *http.Client
}

func newNotifyHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Notification payloads can contain command data and a signed approval
			// URL. Never let a webhook endpoint redirect those capabilities to a
			// different destination.
			return http.ErrUseLastResponse
		},
	}
}

// NewGenericNotifier creates a new generic webhook notifier.
func NewGenericNotifier(url string) *GenericNotifier {
	return &GenericNotifier{
		url:    url,
		client: newNotifyHTTPClient(),
	}
}

// Send posts the event as JSON to the webhook URL.
func (n *GenericNotifier) Send(event NotifyEvent) error {
	event = sanitizeEvent(event)
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	resp, err := n.client.Post(n.url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return notificationTransportError("post webhook", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func notificationTransportError(operation string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return fmt.Errorf("%s: %w", operation, urlErr.Err)
	}
	return fmt.Errorf("%s failed (%T)", operation, err)
}
