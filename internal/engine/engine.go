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

package engine

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Engine evaluates tool calls against loaded policies.
//
// The evaluation model is deny-wins with explicit priority:
//   - All policies whose Match clause matches the tool call are collected.
//   - Within each policy, rules evaluate top-to-bottom; first match wins.
//   - Across policies: any deny → final deny. No deny + any log → final log.
//   - If nothing matches, the configured default action applies.
//
// Engine is safe for concurrent use.
type Engine struct {
	mu            sync.RWMutex
	config        *Config
	store         PolicyStore
	defaultAction Action
	responseRegex map[string]*regexp.Regexp
	logger        *slog.Logger
	stopReload    chan struct{} // closed to stop periodic reload goroutine
	stopOnce      sync.Once
}

// New creates an engine from a policy store.
// Returns an error if policies cannot be loaded or contain invalid entries.
func New(store PolicyStore, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	cfg, err := store.Load()
	if err != nil {
		return nil, err
	}

	e := &Engine{
		config: cfg,
		store:  store,
		logger: logger,
	}
	e.defaultAction = e.parseDefaultAction(cfg.DefaultAction)
	e.responseRegex = cfg.responseRegexCache

	logger.Info("engine: policies loaded",
		"count", len(cfg.Policies),
		"default_action", e.defaultAction,
		"path", store.Path(),
	)

	return e, nil
}

// Evaluate runs a tool call through all matching policies and returns
// the final decision.
//
// This is the hot path. It must complete in <0.1ms p99.
func (e *Engine) Evaluate(call ToolCall) Decision {
	start := time.Now()

	e.mu.RLock()
	cfg := e.config
	defaultAction := e.defaultAction
	e.mu.RUnlock()

	// Collect matching policies, sorted by priority.
	matching := e.collectMatching(cfg, call)

	if len(matching) == 0 {
		return Decision{
			Action:       defaultAction,
			Message:      "no matching policy; using default action",
			EvalDuration: time.Since(start),
		}
	}

	// Evaluate rules across all matching policies.
	// Deny wins. Then log. Then allow.
	// If policies match scope but no rules fire, fall through to default action.
	var (
		finalAction  = ActionAllow
		finalMessage string
		matched      []string
		anyRuleFired bool
	)

	var finalWebhookConfig *WebhookActionConfig

	for _, p := range matching {
		action, message, rule, ok := e.evaluatePolicy(p, call)
		if !ok {
			continue // no rule matched within this policy
		}

		anyRuleFired = true
		matched = append(matched, p.Name)

		switch action {
		case ActionDeny:
			// Deny wins immediately. No need to check further.
			return Decision{
				Action:          ActionDeny,
				MatchedPolicies: append(matched, e.remainingNames(matching, p.Name)...),
				Message:         message,
				EvalDuration:    time.Since(start),
			}
		case ActionWebhook:
			// Webhook wins over log and allow, but not deny.
			if finalAction != ActionDeny && finalAction != ActionWebhook {
				finalAction = ActionWebhook
				finalMessage = message
				if rule != nil {
					finalWebhookConfig = rule.Webhook
				}
			}
		case ActionRequireApproval:
			// Require approval wins over log and allow, but not deny or webhook.
			if finalAction != ActionDeny && finalAction != ActionWebhook && finalAction != ActionRequireApproval {
				finalAction = ActionRequireApproval
				finalMessage = message
			}
		case ActionWatch:
			if finalAction == ActionAllow {
				finalAction = ActionWatch
				finalMessage = message
			}
		case ActionAllow:
			if finalAction == ActionAllow && finalMessage == "" {
				finalMessage = message
			}
		}
	}

	// If policies matched scope but no rules actually fired,
	// fall through to the configured default action.
	if !anyRuleFired {
		return Decision{
			Action:       defaultAction,
			Message:      "no matching rule; using default action",
			EvalDuration: time.Since(start),
		}
	}

	return Decision{
		Action:          finalAction,
		MatchedPolicies: matched,
		Message:         finalMessage,
		EvalDuration:    time.Since(start),
		WebhookConfig:   finalWebhookConfig,
	}
}

// EvaluateResponse runs response-side evaluation against matching policies.
// Only response-specific conditions are considered.
// maxResponseMatchSize is the maximum response body size (in bytes) that will
// be evaluated against regex patterns. Larger responses are truncated to avoid
// pathological backtracking on user-defined regexes.
const maxResponseMatchSize = 1 << 20 // 1 MB

func (e *Engine) EvaluateResponse(call ToolCall, response string) Decision {
	start := time.Now()

	// Cap response size before regex matching to prevent ReDoS on large bodies.
	if len(response) > maxResponseMatchSize {
		response = response[:maxResponseMatchSize]
	}

	e.mu.RLock()
	cfg := e.config
	regexCache := e.responseRegex
	e.mu.RUnlock()

	matching := e.collectMatching(cfg, call)
	if len(matching) == 0 {
		return Decision{
			Action:       ActionAllow,
			Message:      "no matching policy; response allowed",
			EvalDuration: time.Since(start),
		}
	}

	action, message, matched, fired := e.evaluateResponsePolicies(matching, response, regexCache)
	if !fired {
		return Decision{
			Action:       ActionAllow,
			Message:      "no matching response rule; response allowed",
			EvalDuration: time.Since(start),
		}
	}

	return Decision{
		Action:          action,
		MatchedPolicies: matched,
		Message:         message,
		EvalDuration:    time.Since(start),
	}
}

// Reload re-reads the policy file and replaces the active configuration.
// Returns an error if the new file is invalid; the old config remains active.
func (e *Engine) Reload() error {
	cfg, err := e.store.Load()
	if err != nil {
		return fmt.Errorf("engine: reload failed: %w", err)
	}

	// Reject empty or clearly broken configs from hot-reload.
	// File watchers can fire on truncated files before new content is written.
	if cfg.DefaultAction == "" && len(cfg.Policies) == 0 {
		return fmt.Errorf("engine: reload rejected — empty config (file may be mid-write)")
	}

	// Reject configs where policy count drops to zero from a non-zero count.
	// This prevents accidental policy wipe from a bad config edit.
	e.mu.RLock()
	currentCount := len(e.config.Policies)
	e.mu.RUnlock()
	if currentCount > 0 && len(cfg.Policies) == 0 {
		return fmt.Errorf("engine: reload rejected — policy count dropped from %d to 0", currentCount)
	}

	e.mu.Lock()
	e.config = cfg
	e.defaultAction = e.parseDefaultAction(cfg.DefaultAction)
	e.responseRegex = cfg.responseRegexCache
	e.mu.Unlock()

	e.logger.Info("engine: policies reloaded",
		"count", len(cfg.Policies),
		"default_action", e.defaultAction,
	)

	return nil
}

// PolicyCount returns the number of loaded policies.
func (e *Engine) PolicyCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.config.Policies)
}

// RuleCount returns the total number of rules across all loaded policies.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	total := 0
	for _, p := range e.config.Policies {
		total += len(p.Rules)
	}
	return total
}

// GetDefaultAction returns the configured default action as a string.
func (e *Engine) GetDefaultAction() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.defaultAction.String()
}

// collectMatching returns all enabled policies whose Match clause matches
// the tool call, sorted by priority (lowest number first).
func (e *Engine) collectMatching(cfg *Config, call ToolCall) []Policy {
	var result []Policy

	for _, p := range cfg.Policies {
		if !p.IsEnabled() {
			continue
		}
		if !e.matchesScope(p.Match, call) {
			continue
		}
		result = append(result, p)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].EffectivePriority() < result[j].EffectivePriority()
	})

	return result
}

// matchesScope checks whether a tool call falls within a policy's scope
// (agent identity and tool name).
func (e *Engine) matchesScope(m Match, call ToolCall) bool {
	// Check agent identity.
	if !MatchGlob(m.EffectiveAgent(), call.Agent) {
		return false
	}

	// Check tool name. If no tools specified, match all.
	if len(m.Tool) == 0 {
		return true
	}
	return matchAny(m.Tool, call.Tool)
}

// evaluatePolicy runs through a policy's rules top-to-bottom and returns
// the first matching rule's action. Returns ok=false if no rule matches.
// The returned *Rule pointer is non-nil when a rule matched (for webhook config access).
func (e *Engine) evaluatePolicy(p Policy, call ToolCall) (Action, string, *Rule, bool) {
	for i, rule := range p.Rules {
		if !matchCondition(rule.When, call) {
			continue
		}

		action, err := rule.ParseAction()
		if err != nil {
			e.logger.Error("engine: invalid rule action",
				"policy", p.Name,
				"action", rule.Action,
				"error", err,
			)
			// Fail closed: invalid rule = deny.
			return ActionDeny, "invalid rule action; failing closed", nil, true
		}

		return action, rule.Message, &p.Rules[i], true
	}

	return ActionAllow, "", nil, false
}

func (e *Engine) evaluateResponsePolicies(
	policies []Policy,
	response string,
	regexCache map[string]*regexp.Regexp,
) (Action, string, []string, bool) {
	finalAction := ActionAllow
	finalMessage := ""
	matched := []string{}
	anyRuleFired := false

	for _, p := range policies {
		action, message, ok := e.evaluateResponsePolicy(p, response, regexCache)
		if !ok {
			continue
		}

		anyRuleFired = true
		matched = append(matched, p.Name)

		switch action {
		case ActionDeny:
			// Short-circuit on deny. Only report policies that actually fired,
			// not remaining unevaluated ones.
			return ActionDeny, message, matched, true
		case ActionWebhook:
			e.logger.Warn("engine: webhook action not supported for response rules, treating as deny",
				"policy", p.Name)
			return ActionDeny, message, matched, true
		case ActionRequireApproval:
			if finalAction != ActionDeny && finalAction != ActionRequireApproval {
				finalAction = ActionRequireApproval
				finalMessage = message
			}
		case ActionWatch:
			if finalAction == ActionAllow {
				finalAction = ActionWatch
				finalMessage = message
			}
		case ActionAllow:
			if finalAction == ActionAllow && finalMessage == "" {
				finalMessage = message
			}
		}
	}

	return finalAction, finalMessage, matched, anyRuleFired
}

func (e *Engine) evaluateResponsePolicy(
	p Policy,
	response string,
	regexCache map[string]*regexp.Regexp,
) (Action, string, bool) {
	for _, rule := range p.Rules {
		if !matchResponseCondition(rule.When, response, regexCache, e.logger) {
			continue
		}

		action, err := rule.ParseAction()
		if err != nil {
			e.logger.Error("engine: invalid rule action",
				"policy", p.Name,
				"action", rule.Action,
				"error", err,
			)
			return ActionDeny, "invalid rule action; failing closed", true
		}

		return action, rule.Message, true
	}

	return ActionAllow, "", false
}

// remainingNames collects policy names after a given name in the slice.
// Used to include all matching policy names in a deny decision even when
// we short-circuit on the first deny.
func (e *Engine) remainingNames(policies []Policy, after string) []string {
	var names []string
	found := false
	for _, p := range policies {
		if p.Name == after {
			found = true
			continue
		}
		if found {
			names = append(names, p.Name)
		}
	}
	return names
}

// StartPeriodicReload starts a background goroutine that reloads policies
// at the given interval. Call Stop() to terminate the goroutine.
// If interval is 0 or negative, no goroutine is started.
func (e *Engine) StartPeriodicReload(interval time.Duration) {
	if interval <= 0 {
		return
	}
	e.stopReload = make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := e.Reload(); err != nil {
					e.logger.Error("engine: periodic reload failed", "error", err)
				}
			case <-e.stopReload:
				return
			}
		}
	}()
	e.logger.Info("engine: periodic reload started", "interval", interval)
}

// Stop terminates the periodic reload goroutine, if running.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		if e.stopReload != nil {
			close(e.stopReload)
		}
	})
}

// parseDefaultAction converts a string default action to an Action constant.
func (e *Engine) parseDefaultAction(s string) Action {
	switch s {
	case "allow":
		return ActionAllow
	case "deny":
		return ActionDeny
	case "watch", "log": // "log" kept as deprecated alias
		return ActionWatch
	default:
		// If unspecified or invalid, default to deny (fail closed).
		return ActionDeny
	}
}
