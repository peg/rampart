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

// DiscordNotifier sends notifications to Discord using webhook embeds.
type DiscordNotifier struct {
	url    string
	client *http.Client
}

// NewDiscordNotifier creates a new Discord notifier.
func NewDiscordNotifier(url string) *DiscordNotifier {
	return &DiscordNotifier{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title     string         `json:"title"`
	Color     int            `json:"color"`
	Fields    []discordField `json:"fields"`
	Timestamp string         `json:"timestamp"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// Send sends a notification to Discord using embeds format.
func (n *DiscordNotifier) Send(event NotifyEvent) error {
	// Choose color and title based on action
	color := 0xf85149 // red for deny
	title := "Rampart: Command Denied"
	if event.Action == "watch" || event.Action == "log" {
		color = 0xd29922 // orange for log
		title = "Rampart: Command Logged"
	} else if event.Action == "require_approval" {
		color = 0xd29922 // amber for approval required
		title = "Rampart: Approval Required"
	}

	fields := []discordField{
		{Name: "Tool", Value: event.Tool, Inline: true},
		{Name: "Agent", Value: event.Agent, Inline: true},
	}

	if event.Action == "require_approval" {
		fields = append(fields,
			discordField{Name: "Command", Value: event.Command, Inline: false},
			discordField{Name: "Approval ID", Value: shortApprovalID(event.ApprovalID), Inline: true},
			discordField{Name: "Expires In", Value: expiresInText(event.ExpiresAt), Inline: true},
			discordField{Name: "Resolve", Value: fmt.Sprintf("[Open Approval](%s)", event.ResolveURL), Inline: false},
		)
	} else {
		fields = append(fields,
			discordField{Name: "Policy", Value: event.Policy, Inline: true},
			discordField{Name: "Command/Path", Value: event.Command, Inline: false},
			discordField{Name: "Message", Value: event.Message, Inline: false},
		)
	}

	// Build the embed
	embed := discordEmbed{
		Title:     title,
		Color:     color,
		Timestamp: event.Timestamp,
		Fields:    fields,
	}

	payload := discordPayload{
		Embeds: []discordEmbed{embed},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	resp, err := n.client.Post(n.url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("post discord webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}

	return nil
}
