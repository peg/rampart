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

	// Pre-compiled regexes for sanitizeCommand — compiled once at init, not per call.
	sanitizePatterns = []struct {
		re          *regexp.Regexp
		replacement string
	}{
		// Quoted Authorization headers (before individual token patterns)
		{regexp.MustCompile(`'Authorization:\s+(Bearer|Basic)\s+[^']+'`), "'[REDACTED]'"},
		// MySQL passwords: -p'...' or -p"..." or -pSOMETHING
		{regexp.MustCompile(`\s-p'[^']*'`), " [REDACTED]"},
		{regexp.MustCompile(`\s-p"[^"]*"`), " [REDACTED]"},
		{regexp.MustCompile(`\s-p[A-Za-z0-9][^\s]*`), " [REDACTED]"},
		// Password arguments
		{regexp.MustCompile(`--password=\S+`), "[REDACTED]"},
		{regexp.MustCompile(`--password\s+\S+`), "[REDACTED]"},
		// GitHub tokens
		{regexp.MustCompile(`ghp_[a-zA-Z0-9]{40}`), "[REDACTED]"},
		{regexp.MustCompile(`gho_[a-zA-Z0-9]+`), "[REDACTED]"},
		{regexp.MustCompile(`ghs_[a-zA-Z0-9]+`), "[REDACTED]"},
		// Slack tokens
		{regexp.MustCompile(`xoxb-[a-zA-Z0-9-]+`), "[REDACTED]"},
		{regexp.MustCompile(`xoxp-[a-zA-Z0-9-]+`), "[REDACTED]"},
		// OpenAI-style API keys
		{regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "[REDACTED]"},
		// AWS access key IDs
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[REDACTED]"},
		// Unquoted Authorization headers
		{regexp.MustCompile(`Authorization:\s+(Bearer|Basic)\s+\S+`), "Authorization: $1 [REDACTED]"},
		// Long base64 strings with credential keywords (last — most general)
		{regexp.MustCompile(`(?i)\b(api_?key|auth_?token|token|secret|access_?token)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}`), "[REDACTED]"},
	}
)

// sanitizeCommand removes sensitive patterns from command strings before sending to webhooks.
func sanitizeCommand(command string) string {
	result := command
	for _, p := range sanitizePatterns {
		result = p.re.ReplaceAllString(result, p.replacement)
	}
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
