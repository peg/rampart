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

// SlackNotifier sends notifications to Slack using incoming webhooks with Block Kit formatting.
type SlackNotifier struct {
	url    string
	client *http.Client
}

// NewSlackNotifier creates a new Slack notifier.
func NewSlackNotifier(url string) *SlackNotifier {
	return &SlackNotifier{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

type slackPayload struct {
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string        `json:"color"`
	Blocks []interface{} `json:"blocks"`
}

type slackSection struct {
	Type   string                 `json:"type"`
	Text   *slackText             `json:"text,omitempty"`
	Fields []slackText            `json:"fields,omitempty"`
}

type slackContext struct {
	Type     string              `json:"type"`
	Elements []slackContextElement `json:"elements"`
}

type slackContextElement struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Send sends a notification to Slack using Block Kit format.
func (n *SlackNotifier) Send(event NotifyEvent) error {
	// Choose color based on action
	color := "#f85149" // red for deny
	actionText := "Command Denied"
	if event.Action == "log" {
		color = "#d29922" // orange for log
		actionText = "Command Logged"
	}

	// Build the payload
	payload := slackPayload{
		Attachments: []slackAttachment{
			{
				Color: color,
				Blocks: []interface{}{
					// Header section
					slackSection{
						Type: "section",
						Text: &slackText{
							Type: "mrkdwn",
							Text: fmt.Sprintf("*🛡️ Rampart: %s*", actionText),
						},
					},
					// Fields section
					slackSection{
						Type: "section",
						Fields: []slackText{
							{Type: "mrkdwn", Text: fmt.Sprintf("*Tool:*\n%s", event.Tool)},
							{Type: "mrkdwn", Text: fmt.Sprintf("*Command/Path:*\n%s", event.Command)},
							{Type: "mrkdwn", Text: fmt.Sprintf("*Policy:*\n%s", event.Policy)},
							{Type: "mrkdwn", Text: fmt.Sprintf("*Message:*\n%s", event.Message)},
						},
					},
					// Context section with timestamp
					slackContext{
						Type: "context",
						Elements: []slackContextElement{
							{Type: "mrkdwn", Text: fmt.Sprintf("Agent: %s | %s", event.Agent, event.Timestamp)},
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	resp, err := n.client.Post(n.url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("post slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}