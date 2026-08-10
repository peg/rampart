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
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/notify"
)

var (
	// Rate limiting for webhook notifications
	lastNotificationTime time.Time
	notificationMutex    sync.Mutex
)

// sanitizeCommand removes sensitive patterns from command strings before sending to webhooks.
func sanitizeCommand(command string) string {
	return notify.SanitizeCommand(command)
}

// sendNotification sends a webhook notification for the policy decision.
func sendNotification(config *engine.NotifyConfig, call engine.ToolCall, decision engine.Decision, logger *slog.Logger) {
	sendNotificationWithTimeout(config, call, decision, logger, 0)
}

func sendNotificationWithTimeout(config *engine.NotifyConfig, call engine.ToolCall, decision engine.Decision, logger *slog.Logger, timeout time.Duration) {
	// Check if this action should trigger a notification
	actionStr := decision.Action.String()
	shouldNotify := false
	for _, triggerAction := range config.On {
		if notificationActionMatches(triggerAction, actionStr) {
			shouldNotify = true
			break
		}
	}
	if !shouldNotify {
		return
	}

	// Rate limiting: check if less than 6 seconds since last notification
	notificationMutex.Lock()
	now := time.Now()
	if now.Sub(lastNotificationTime) < 6*time.Second {
		notificationMutex.Unlock()
		logger.Warn("webhook notification rate limited", "action", actionStr)
		return
	}
	lastNotificationTime = now
	notificationMutex.Unlock()

	// Extract command/path from tool parameters
	command := extractCommand(call)

	// Sanitize command before sending to webhook
	sanitizedCommand := sanitizeCommand(command)

	// Get the matched policy name
	policyName := "unknown"
	if len(decision.MatchedPolicies) > 0 {
		policyName = decision.MatchedPolicies[0]
	}

	// Create notification event with sanitized command
	event := notify.NotifyEvent{
		Action:    actionStr,
		Tool:      call.Tool,
		Command:   sanitizedCommand,
		Policy:    policyName,
		Message:   decision.Message,
		Agent:     call.Agent,
		Timestamp: call.Timestamp.Format(time.RFC3339),
	}

	// Create and send notification
	notifier := notify.NewNotifierWithTimeout(config.URL, config.Platform, timeout)
	if err := notifier.Send(event); err != nil {
		// Notification webhook URLs often embed credentials in their path. The
		// configured platform is enough diagnostic context without leaking them.
		logger.Error("webhook notification failed", "error_type", fmt.Sprintf("%T", err), "platform", config.Platform)
	} else {
		logger.Debug("webhook notification sent", "action", actionStr, "policy", policyName)
	}
}

// notificationActionMatches preserves the notification-only aliases accepted
// by older configurations without reintroducing them as policy actions.
func notificationActionMatches(configured, actual string) bool {
	normalize := func(action string) string {
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "log":
			return "watch"
		case "require_approval":
			return "ask"
		default:
			return strings.ToLower(strings.TrimSpace(action))
		}
	}
	return normalize(configured) == normalize(actual)
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
