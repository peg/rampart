// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package notify

import (
	"regexp"
	"strings"
)

var sanitizePatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)'Authorization:\s+(Bearer|Basic)\s+[^']+'`), "'[REDACTED]'"},
	{regexp.MustCompile(`(?i)"Authorization:\s+(Bearer|Basic)\s+[^"]+"`), `"[REDACTED]"`},
	{regexp.MustCompile(`\s-p'[^']*'`), " [REDACTED]"},
	{regexp.MustCompile(`\s-p"[^"]*"`), " [REDACTED]"},
	{regexp.MustCompile(`\s-p[A-Za-z0-9][^\s]*`), " [REDACTED]"},
	{regexp.MustCompile(`--password=\S+`), "[REDACTED]"},
	{regexp.MustCompile(`--password\s+\S+`), "[REDACTED]"},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{40}`), "[REDACTED]"},
	{regexp.MustCompile(`gho_[a-zA-Z0-9]+`), "[REDACTED]"},
	{regexp.MustCompile(`ghs_[a-zA-Z0-9]+`), "[REDACTED]"},
	{regexp.MustCompile(`xoxb-[a-zA-Z0-9-]+`), "[REDACTED]"},
	{regexp.MustCompile(`xoxp-[a-zA-Z0-9-]+`), "[REDACTED]"},
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[REDACTED]"},
	{regexp.MustCompile(`(?i)Authorization:\s+(Bearer|Basic)\s+\S+`), "Authorization: $1 [REDACTED]"},
	{regexp.MustCompile(`(?i)\b(api_?key|auth_?token|token|secret|access_?token)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}`), "[REDACTED]"},
	{regexp.MustCompile(`(?i)(--(?:api[-_]?key|auth[-_]?token|access[-_]?token|token|secret))(=|\s+)(?:"[^"]*"|'[^']*'|[^\s]+)`), "$1$2[REDACTED]"},
	{regexp.MustCompile(`(?i)(\b(?:api[-_]?key|auth[-_]?token|access[-_]?token|password|token|secret)\b\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&]+)`), "$1[REDACTED]"},
}

// SanitizeCommand removes common credential shapes from presentation text.
// Apply it to output copies, never to private authorization identity.
func SanitizeCommand(command string) string {
	result := command
	for _, pattern := range sanitizePatterns {
		result = pattern.re.ReplaceAllString(result, pattern.replacement)
	}
	return result
}

// SanitizeSuggestions returns a copy containing only guidance that needs no
// redaction. Rewriting a runnable allowance would authorize a different action;
// omit it instead, including guidance already containing a redaction marker.
func SanitizeSuggestions(suggestions []string) []string {
	if suggestions == nil {
		return nil
	}
	safe := make([]string, 0, len(suggestions))
	for _, suggestion := range suggestions {
		if !strings.Contains(suggestion, "[REDACTED]") && SanitizeCommand(suggestion) == suggestion {
			safe = append(safe, suggestion)
		}
	}
	return safe
}

func sanitizeEvent(event NotifyEvent) NotifyEvent {
	event.Command = SanitizeCommand(event.Command)
	return event
}
