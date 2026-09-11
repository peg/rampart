// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"strings"

	"github.com/peg/rampart/internal/notify"
)

const redactedValue = "[REDACTED]"

type redactingSink struct {
	inner AuditSink
}

// NewRedactingSink removes common credential material before events reach a
// persistent or external audit sink. Nil remains nil for optional auditing.
func NewRedactingSink(inner AuditSink) AuditSink {
	if inner == nil {
		return nil
	}
	return &redactingSink{inner: inner}
}

func (s *redactingSink) Write(event Event) error {
	return s.inner.Write(RedactEvent(event))
}

func (s *redactingSink) Flush() error { return s.inner.Flush() }
func (s *redactingSink) Close() error { return s.inner.Close() }

// RedactEvent returns a defensive copy suitable for persistence. It preserves
// audit structure and policy evidence while scrubbing sensitive key values and
// credential shapes embedded in strings such as shell commands.
// Apply it before hashing new records; stored history and private authorization
// identity must not be rewritten from this display representation.
func RedactEvent(event Event) Event {
	event.ID = notify.SanitizeCommand(event.ID)
	event.Agent = notify.SanitizeCommand(event.Agent)
	event.Session = notify.SanitizeCommand(event.Session)
	event.RunID = notify.SanitizeCommand(event.RunID)
	event.ToolCallID = notify.SanitizeCommand(event.ToolCallID)
	event.Tool = notify.SanitizeCommand(event.Tool)
	if event.Host != nil {
		host := *event.Host
		host.Hostname = notify.SanitizeCommand(host.Hostname)
		host.OS = notify.SanitizeCommand(host.OS)
		host.Arch = notify.SanitizeCommand(host.Arch)
		event.Host = &host
	}
	event.Request = redactMap(event.Request)
	event.ApprovalOwner = redactMap(event.ApprovalOwner)
	event.Decision.Action = notify.SanitizeCommand(event.Decision.Action)
	event.Decision.Message = notify.SanitizeCommand(event.Decision.Message)
	event.Decision.MatchedPolicies = redactStrings(event.Decision.MatchedPolicies)
	event.Decision.Suggestions = redactStrings(event.Decision.Suggestions)
	if event.Response != nil {
		response := *event.Response
		response.Flags = redactStrings(response.Flags)
		event.Response = &response
	}
	return event
}

func redactStrings(values []string) []string {
	if values == nil {
		return nil
	}
	redacted := make([]string, len(values))
	for i, value := range values {
		redacted[i] = notify.SanitizeCommand(value)
	}
	return redacted
}

func redactMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	redacted := make(map[string]any, len(values))
	for key, value := range values {
		if isSensitiveAuditKey(key) {
			redacted[key] = redactedValue
			continue
		}
		redacted[key] = redactAuditValue(value)
	}
	return redacted
}

func redactAuditValue(value any) any {
	switch typed := value.(type) {
	case string:
		return notify.SanitizeCommand(typed)
	case map[string]any:
		return redactMap(typed)
	case map[string]string:
		copyMap := make(map[string]any, len(typed))
		for key, item := range typed {
			copyMap[key] = item
		}
		return redactMap(copyMap)
	case []any:
		items := make([]any, len(typed))
		for i, item := range typed {
			items[i] = redactAuditValue(item)
		}
		return items
	case []string:
		return redactStrings(typed)
	default:
		return value
	}
}

func isSensitiveAuditKey(key string) bool {
	normalized := strings.Map(func(char rune) rune {
		if char >= 'A' && char <= 'Z' {
			return char + ('a' - 'A')
		}
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			return char
		}
		return -1
	}, key)
	switch normalized {
	case "authorization", "proxyauthorization", "password", "passwd", "passphrase",
		"token", "accesstoken", "refreshtoken", "idtoken", "apikey", "secret",
		"clientsecret", "cookie", "setcookie", "privatekey", "credential", "commandb64":
		return true
	}
	for _, suffix := range []string{"password", "token", "apikey", "secret", "privatekey"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}
