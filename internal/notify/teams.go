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

// TeamsNotifier sends notifications to Microsoft Teams using Office 365 connector cards.
type TeamsNotifier struct {
	url    string
	client *http.Client
}

// NewTeamsNotifier creates a new Teams notifier.
func NewTeamsNotifier(url string) *TeamsNotifier {
	return &TeamsNotifier{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

type teamsMessageCard struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	Summary    string         `json:"summary"`
	Title      string         `json:"title"`
	ThemeColor string         `json:"themeColor"`
	Sections   []teamsSection `json:"sections"`
}

type teamsSection struct {
	Facts []teamsFact `json:"facts"`
}

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Send sends a notification to Teams using MessageCard format.
func (n *TeamsNotifier) Send(event NotifyEvent) error {
	// Choose theme color and title based on action
	themeColor := "f85149" // red for deny
	title := "🛡️ Rampart: Command Denied"
	summary := "Rampart policy engine denied a command"
	if event.Action == "log" {
		themeColor = "d29922" // orange for log
		title = "🛡️ Rampart: Command Logged"
		summary = "Rampart policy engine logged a command"
	} else if event.Action == "require_approval" {
		themeColor = "d29922" // amber for approval required
		title = "🛡️ Rampart: Approval Required"
		summary = "Rampart policy engine requires human approval"
	}

	facts := []teamsFact{
		{Name: "Tool", Value: event.Tool},
		{Name: "Command/Path", Value: event.Command},
		{Name: "Agent", Value: event.Agent},
		{Name: "Timestamp", Value: event.Timestamp},
	}
	if event.Action == "require_approval" {
		facts = append(facts,
			teamsFact{Name: "Approval ID", Value: shortApprovalID(event.ApprovalID)},
			teamsFact{Name: "Expires In", Value: expiresInText(event.ExpiresAt)},
			teamsFact{Name: "Resolve URL", Value: event.ResolveURL},
		)
	} else {
		facts = append(facts,
			teamsFact{Name: "Policy", Value: event.Policy},
			teamsFact{Name: "Message", Value: event.Message},
		)
	}

	// Build the message card
	card := teamsMessageCard{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		Summary:    summary,
		Title:      title,
		ThemeColor: themeColor,
		Sections: []teamsSection{
			{
				Facts: facts,
			},
		},
	}

	data, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("marshal teams payload: %w", err)
	}

	resp, err := n.client.Post(n.url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("post teams webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("teams webhook returned status %d", resp.StatusCode)
	}

	return nil
}
