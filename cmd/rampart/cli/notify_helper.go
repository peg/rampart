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

package cli

import (
	"log/slog"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/notify"
)

// sendNotification sends a webhook notification for the policy decision.
func sendNotification(config *engine.NotifyConfig, call engine.ToolCall, decision engine.Decision, logger *slog.Logger) {
	// Check if this action should trigger a notification
	actionStr := decision.Action.String()
	shouldNotify := false
	for _, triggerAction := range config.On {
		if triggerAction == actionStr {
			shouldNotify = true
			break
		}
	}
	if !shouldNotify {
		return
	}

	// Extract command/path from tool parameters
	command := extractCommand(call)

	// Get the matched policy name
	policyName := "unknown"
	if len(decision.MatchedPolicies) > 0 {
		policyName = decision.MatchedPolicies[0]
	}

	// Create notification event
	event := notify.NotifyEvent{
		Action:    actionStr,
		Tool:      call.Tool,
		Command:   command,
		Policy:    policyName,
		Message:   decision.Message,
		Agent:     call.Agent,
		Timestamp: call.Timestamp.Format(time.RFC3339),
	}

	// Create and send notification
	notifier := notify.NewNotifier(config.URL, config.Platform)
	if err := notifier.Send(event); err != nil {
		logger.Error("webhook notification failed", "error", err, "url", config.URL)
	} else {
		logger.Debug("webhook notification sent", "action", actionStr, "policy", policyName)
	}
}

// extractCommand pulls the relevant command/path from tool call parameters.
func extractCommand(call engine.ToolCall) string {
	switch call.Tool {
	case "exec":
		if cmd, ok := call.Params["command"].(string); ok {
			return cmd
		}
	case "read", "write":
		if path, ok := call.Params["path"].(string); ok {
			return path
		}
		if filePath, ok := call.Params["file_path"].(string); ok {
			return filePath
		}
	case "fetch":
		if url, ok := call.Params["url"].(string); ok {
			return url
		}
	}
	return ""
}
