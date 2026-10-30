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
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), "[REDACTED]"},
	// URL userinfo, e.g. postgres://user:password@host or https://x:token@host.
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]*:)[^@\s/]+@`), "${1}[REDACTED]@"},
	// Token prefixes are unanchored: a token can follow "_", "=" or URL
	// encoding, and these patterns must not cover less than earlier releases.
	{regexp.MustCompile(`gh[os]_[a-zA-Z0-9]+`), "[REDACTED]"},
	{regexp.MustCompile(`gh[pru]_[a-zA-Z0-9]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`xox[abeoprs]-[a-zA-Z0-9-]+`), "[REDACTED]"},
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "[REDACTED]"},
	// sk- keys include hyphenated prefixes such as sk-ant-api03- and sk-proj-.
	// The hyphenated form needs a boundary so names like task-runner-... stay.
	{regexp.MustCompile(`(^|[^a-zA-Z0-9_-])sk-[a-zA-Z0-9_-]{20,}`), "${1}[REDACTED]"},
	{regexp.MustCompile(`[rs]k_(?:live|test)_[a-zA-Z0-9]{16,}`), "[REDACTED]"},
	{regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`), "[REDACTED]"},
	{regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "[REDACTED]"},
	{regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`), "[REDACTED]"},
	{regexp.MustCompile(`(?i)Authorization:\s+(Bearer|Basic)\s+\S+`), "Authorization: $1 [REDACTED]"},
	{regexp.MustCompile(`(?i)\b(api_?key|auth_?token|token|secret|access_?token)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}`), "[REDACTED]"},
	{regexp.MustCompile(`(?i)(--(?:api[-_]?key|auth[-_]?token|access[-_]?token|token|secret))(=|\s+)(?:"[^"]*"|'[^']*'|[^\s]+)`), "$1$2[REDACTED]"},
	{regexp.MustCompile(`(?i)(\b(?:api[-_]?key|auth[-_]?token|access[-_]?token|password|token|secret)\b\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&]+)`), "$1[REDACTED]"},
	// Underscored names such as AWS_SECRET_ACCESS_KEY or GITHUB_TOKEN: "_" is a
	// word character, so the \b-delimited pattern above does not see them.
	{regexp.MustCompile(`(?i)(\b[a-z0-9_]*_(?:secret|token|password|passwd|api_?key|access_?key|private_?key|credentials?)(?:_[a-z0-9_]*)?\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s&;|]+)`), "$1[REDACTED]"},
	{regexp.MustCompile(`(?i)(\b(?:secret|token|password|passwd|api_?key|access_?key|private_?key|credentials?)_[a-z0-9_]*\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s&;|]+)`), "$1[REDACTED]"},
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
