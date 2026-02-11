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
	"regexp"
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
	result := command
	
	// Handle quoted Authorization headers first (before individual token patterns)
	result = regexp.MustCompile(`'Authorization:\s+(Bearer|Basic)\s+[^']+'`).ReplaceAllString(result, "'[REDACTED]'")
	
	// MySQL passwords: -p'...' or -p"..." or -pSOMETHING (be more specific to avoid conflicts)
	result = regexp.MustCompile(`\s-p'[^']*'`).ReplaceAllString(result, " [REDACTED]")
	result = regexp.MustCompile(`\s-p"[^"]*"`).ReplaceAllString(result, " [REDACTED]")
	result = regexp.MustCompile(`\s-p[A-Za-z0-9][^\s]*`).ReplaceAllString(result, " [REDACTED]")
	
	// Password arguments (handle these before general token patterns)  
	result = regexp.MustCompile(`--password=\S+`).ReplaceAllString(result, "[REDACTED]")
	result = regexp.MustCompile(`--password\s+\S+`).ReplaceAllString(result, "[REDACTED]")
	
	// GitHub tokens (handle before general sk- pattern)
	result = regexp.MustCompile(`ghp_[a-zA-Z0-9]{40}`).ReplaceAllString(result, "[REDACTED]")
	result = regexp.MustCompile(`gho_[a-zA-Z0-9]+`).ReplaceAllString(result, "[REDACTED]")
	result = regexp.MustCompile(`ghs_[a-zA-Z0-9]+`).ReplaceAllString(result, "[REDACTED]")
	
	// Slack tokens (handle before general patterns)
	result = regexp.MustCompile(`xoxb-[a-zA-Z0-9-]+`).ReplaceAllString(result, "[REDACTED]")
	result = regexp.MustCompile(`xoxp-[a-zA-Z0-9-]+`).ReplaceAllString(result, "[REDACTED]")
	
	// OpenAI-style API keys
	result = regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`).ReplaceAllString(result, "[REDACTED]")
	
	// AWS access key IDs
	result = regexp.MustCompile(`AKIA[0-9A-Z]{16}`).ReplaceAllString(result, "[REDACTED]")
	
	// Unquoted Authorization headers
	result = regexp.MustCompile(`Authorization:\s+(Bearer|Basic)\s+\S+`).ReplaceAllString(result, "Authorization: $1 [REDACTED]")
	
	// Long base64 strings when preceded by credential keywords (handle last, be more specific)
	result = regexp.MustCompile(`(?i)\b(api_?key|auth_?token|token|secret|access_?token)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}`).ReplaceAllString(result, "[REDACTED]")
	
	return result
}

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
