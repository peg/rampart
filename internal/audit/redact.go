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
func RedactEvent(event Event) Event {
	event.Request = redactMap(event.Request)
	event.ApprovalOwner = redactMap(event.ApprovalOwner)
	event.Decision.Message = notify.SanitizeCommand(event.Decision.Message)
	if event.Decision.Suggestions != nil {
		event.Decision.Suggestions = append([]string(nil), event.Decision.Suggestions...)
		for i := range event.Decision.Suggestions {
			event.Decision.Suggestions[i] = notify.SanitizeCommand(event.Decision.Suggestions[i])
		}
	}
	return event
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
		items := append([]string(nil), typed...)
		for i := range items {
			items[i] = notify.SanitizeCommand(items[i])
		}
		return items
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
