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

import "strings"

// DetectPlatform detects the webhook platform based on the URL.
// Returns "slack", "discord", "teams", "openclaw", or "webhook".
func DetectPlatform(url string) string {
	normalizedURL := strings.ToLower(strings.TrimSpace(url))

	if strings.Contains(normalizedURL, "hooks.slack.com") {
		return "slack"
	}
	if strings.Contains(normalizedURL, "discord.com/api/webhooks") {
		return "discord"
	}
	if strings.Contains(normalizedURL, "webhook.office.com") || strings.Contains(normalizedURL, "outlook.office.com") {
		return "teams"
	}
	// OpenClaw auto-detection requires an explicit domain match to avoid
	// false positives on URLs that happen to contain "openclaw" as a substring.
	if strings.Contains(normalizedURL, "openclaw.dev") ||
		strings.Contains(normalizedURL, "openclaw.ai") ||
		strings.Contains(normalizedURL, "openclaw.io") {
		return "openclaw"
	}
	return "webhook"
}

// NewNotifier creates a notifier for the specified platform.
// If platform is "auto" or empty, it will auto-detect based on the URL.
func NewNotifier(url, platform string) Notifier {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "auto" || platform == "" {
		platform = DetectPlatform(url)
	}

	switch platform {
	case "slack":
		return NewSlackNotifier(url)
	case "discord":
		return NewDiscordNotifier(url)
	case "teams":
		return NewTeamsNotifier(url)
	case "openclaw":
		return NewOpenClawNotifier(url)
	default:
		return NewGenericNotifier(url)
	}
}
