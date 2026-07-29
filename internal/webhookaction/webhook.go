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

// Package webhookaction executes policy webhook decisions for enforcement
// surfaces that can synchronously delegate allow/deny to an HTTP endpoint.
package webhookaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/peg/rampart/internal/engine"
)

const maxResponseBytes = 64 << 10

type request struct {
	Tool      string         `json:"tool"`
	Params    map[string]any `json:"params"`
	Agent     string         `json:"agent"`
	Session   string         `json:"session"`
	Policy    string         `json:"policy"`
	Timestamp string         `json:"timestamp"`
}

type response struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// Execute calls the configured webhook and returns a concrete allow or deny.
// Invalid, oversized, unavailable, or ambiguous responses follow the rule's
// explicit fail_open setting, which defaults to fail closed.
func Execute(logger *slog.Logger, call engine.ToolCall, decision engine.Decision) engine.Decision {
	if logger == nil {
		logger = slog.Default()
	}
	cfg := decision.WebhookConfig
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		logger.Error("webhook action missing config")
		return engine.Decision{Action: engine.ActionDeny, Message: "webhook action misconfigured; denying for safety"}
	}

	policyName := "unknown"
	if len(decision.MatchedPolicies) > 0 {
		policyName = decision.MatchedPolicies[0]
	}
	body, err := json.Marshal(request{
		Tool:      call.Tool,
		Params:    call.Params,
		Agent:     call.Agent,
		Session:   call.Session,
		Policy:    policyName,
		Timestamp: call.Timestamp.Format(time.RFC3339),
	})
	if err != nil {
		logger.Error("webhook marshal failed", "error", err)
		return fallback(logger, cfg, "marshal error")
	}

	client := &http.Client{
		Timeout: cfg.EffectiveTimeout(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// A redirect would let the configured endpoint delegate both the
			// sensitive tool-call payload and its authorization decision to a
			// different origin. Treat every redirect as an unavailable webhook.
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Post(cfg.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		// Webhook paths and query strings commonly contain bearer secrets. Never
		// copy the configured URL into logs; the policy name already identifies
		// which endpoint failed.
		logger.Error("webhook call failed", "policy", policyName, "error_type", fmt.Sprintf("%T", err))
		return fallback(logger, cfg, "webhook request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		logger.Error("webhook returned non-2xx", "policy", policyName, "status", resp.StatusCode)
		return fallback(logger, cfg, fmt.Sprintf("webhook returned HTTP %d", resp.StatusCode))
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		logger.Error("webhook response read failed", "error", err)
		return fallback(logger, cfg, "invalid webhook response")
	}
	if len(responseBody) > maxResponseBytes {
		logger.Error("webhook response too large", "bytes", len(responseBody), "limit", maxResponseBytes)
		return fallback(logger, cfg, "webhook response exceeds size limit")
	}

	var webhookResponse response
	if err := json.Unmarshal(responseBody, &webhookResponse); err != nil {
		logger.Error("webhook response parse failed", "error", err)
		return fallback(logger, cfg, "invalid webhook response")
	}

	switch strings.ToLower(strings.TrimSpace(webhookResponse.Decision)) {
	case "allow":
		logger.Info("webhook allowed", "policy", policyName, "tool", call.Tool)
		return engine.Decision{
			Action:          engine.ActionAllow,
			MatchedPolicies: decision.MatchedPolicies,
			Message:         "allowed by webhook",
		}
	case "deny":
		reason := strings.TrimSpace(webhookResponse.Reason)
		if reason == "" {
			reason = "denied by webhook"
		}
		logger.Info("webhook denied", "policy", policyName, "tool", call.Tool, "reason", reason)
		return engine.Decision{
			Action:          engine.ActionDeny,
			MatchedPolicies: decision.MatchedPolicies,
			Message:         reason,
		}
	default:
		logger.Error("webhook returned unknown decision", "decision", webhookResponse.Decision)
		return fallback(logger, cfg, fmt.Sprintf("unknown webhook decision: %q", webhookResponse.Decision))
	}
}

func fallback(logger *slog.Logger, cfg *engine.WebhookActionConfig, reason string) engine.Decision {
	if cfg.EffectiveFailOpen() {
		logger.Warn("webhook unavailable; failing open", "reason", reason)
		return engine.Decision{Action: engine.ActionAllow, Message: fmt.Sprintf("webhook unavailable, failing open: %s", reason)}
	}
	logger.Warn("webhook unavailable; failing closed", "reason", reason)
	return engine.Decision{Action: engine.ActionDeny, Message: fmt.Sprintf("webhook unavailable, failing closed: %s", reason)}
}
