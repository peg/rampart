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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
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
	mu              sync.RWMutex
	onceMu          sync.Mutex // serializes one-time rule claims with policy reloads
	config          *Config
	store           PolicyStore
	defaultAction   Action
	lastLoadedAt    time.Time
	lastConfigHash  string
	responseRegex   map[string]*regexp.Regexp
	logger          *slog.Logger
	callCounter     CallCounter   // enforcement state for call_count policy rules
	telemetryCalls  CallCounter   // best-effort status telemetry; never an authorization dependency
	stopReload      chan struct{} // closed to stop periodic reload goroutine
	startReloadOnce sync.Once
	stopOnce        sync.Once
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
		config:         cfg,
		store:          store,
		logger:         logger,
		callCounter:    NewSlidingWindowCounter(),
		telemetryCalls: NewSlidingWindowCounter(),
		stopReload:     make(chan struct{}),
	}
	e.defaultAction = e.parseDefaultAction(cfg.DefaultAction)
	e.lastLoadedAt = time.Now().UTC()
	e.lastConfigHash, err = configFingerprint(cfg)
	if err != nil {
		return nil, fmt.Errorf("engine: fingerprint config: %w", err)
	}
	e.responseRegex = cfg.responseRegexCache

	logger.Info("engine: policies loaded",
		"count", len(cfg.Policies),
		"default_action", e.defaultAction,
		"path", store.Path(),
	)

	return e, nil
}

// NotificationConfig returns a defensive copy of the notification settings
// from the same validated policy snapshot used for evaluation.
func (e *Engine) NotificationConfig() *NotifyConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.config == nil || e.config.Notify == nil {
		return nil
	}
	config := *e.config.Notify
	config.On = append([]string(nil), e.config.Notify.On...)
	return &config
}

// Evaluate runs a tool call through all matching policies and returns
// the final decision.
//
// This is the hot path. It must complete in <0.1ms p99.
// EvalOptions controls optional behavior for policy evaluation.
type EvalOptions struct {
	// PolicyFilter restricts evaluation to policies loaded from files whose
	// base name (without extension) matches this value. For example, "paranoid"
	// matches policies from paranoid.yaml. Empty means no filtering (all policies).
	PolicyFilter string

	// DefaultDeny overrides the engine's default action with deny when set.
	// Useful for agent tokens that should fail-closed on unmatched calls.
	DefaultDeny bool
}

func (e *Engine) Evaluate(call ToolCall) Decision {
	return e.EvaluateWith(call, EvalOptions{})
}

func (e *Engine) EvaluateWith(call ToolCall, opts EvalOptions) Decision {
	start := time.Now()
	if err := call.validateSecurityInput(); err != nil {
		return Decision{
			Action:       ActionDeny,
			Message:      fmt.Sprintf("ambiguous tool input (%v); failing closed", err),
			EvalDuration: time.Since(start),
		}
	}

	e.mu.RLock()
	cfg := e.config
	defaultAction := e.defaultAction
	e.mu.RUnlock()

	if field, size := oversizedMatchInput(cfg, call); field != "" {
		return Decision{
			Action:       ActionDeny,
			Message:      fmt.Sprintf("%s is %d bytes and exceeds the %d-byte policy matching limit; failing closed", field, size, maxGlobInputLen),
			EvalDuration: time.Since(start),
		}
	}

	if opts.DefaultDeny {
		defaultAction = ActionDeny
	}

	// Collect matching policies, sorted by priority.
	matching := e.collectMatching(cfg, call)

	// Durable human allow rules are not ordinary policy allows. They are explicit
	// operator carve-outs written by approval/allow workflows. They bypass broader
	// ask/approval policies, but hard deny policies still win.
	durableAllow, hasDurableAllow := e.evaluateDurableAllowOverride(matching, call, start)

	// Apply policy filter if set (per-agent token scoping). Durable operator
	// overrides are intentionally checked before this filter so human-approved
	// carve-outs stay global rather than disappearing under token profile scoping.
	if opts.PolicyFilter != "" {
		matching = filterByProfile(matching, opts.PolicyFilter)
	}

	if len(matching) == 0 {
		if hasDurableAllow {
			return durableAllow
		}
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
		finalAction        = ActionAllow
		finalMessage       string
		finalAudit         bool
		finalHeadlessOnly  bool
		finalFromProject   bool
		matched            []string
		anyRuleFired       bool
		anyGlobalRuleFired bool
		consumedOnce       bool
		consumedPolicy     string
		consumedRuleIdx    int
	)

	var finalWebhookConfig *WebhookActionConfig

	for _, p := range matching {
		res := e.evaluateMatchingPolicy(p, call)
		if !res.matched {
			continue // no rule matched within this policy
		}

		action, message, rule := res.action, res.message, res.rule
		anyRuleFired = true
		if p.Source != "project" {
			anyGlobalRuleFired = true
		}
		matched = append(matched, p.Name)

		switch action {
		case ActionDeny:
			// Deny wins immediately. No need to check further.
			return Decision{
				Action:            ActionDeny,
				FromProjectPolicy: p.Source == "project",
				MatchedPolicies:   append(matched, e.remainingNames(matching, p.Name)...),
				Message:           message,
				EvalDuration:      time.Since(start),
				Suggestions:       GenerateSuggestions(call),
			}
		case ActionWebhook:
			// Webhook wins over log and allow, but not deny.
			if finalAction != ActionDeny && finalAction != ActionWebhook {
				finalAction = ActionWebhook
				finalMessage = message
				finalFromProject = p.Source == "project"
				if rule != nil {
					finalWebhookConfig = rule.Webhook
				}
			}
		case ActionRequireApproval:
			// Require approval wins over log and allow, but not deny or webhook.
			if finalAction != ActionDeny && finalAction != ActionWebhook && finalAction != ActionRequireApproval {
				finalAction = ActionRequireApproval
				finalMessage = message
				finalFromProject = p.Source == "project"
				if rule != nil {
					finalAudit = rule.AskAuditEnabled()
					finalHeadlessOnly = false
				}
			}
		case ActionAsk:
			// Ask wins over log and allow, but not deny, webhook, or require_approval.
			// ActionAsk emits the Claude Code native permission dialog inline.
			if finalAction != ActionDeny && finalAction != ActionWebhook &&
				finalAction != ActionRequireApproval && finalAction != ActionAsk {
				finalAction = ActionAsk
				finalMessage = message
				finalFromProject = p.Source == "project"
				if rule != nil {
					finalAudit = rule.AskAuditEnabled()
					finalHeadlessOnly = rule.HeadlessOnlyEnabled()
				}
			}
		case ActionWatch:
			if finalAction == ActionAllow {
				finalAction = ActionWatch
				finalMessage = message
				finalFromProject = p.Source == "project"
				finalAudit = false
				finalHeadlessOnly = false
			}
		case ActionAllow:
			if finalAction == ActionAllow && finalMessage == "" {
				finalMessage = message
				finalFromProject = p.Source == "project"
				finalAudit = false
				finalHeadlessOnly = false
				if rule != nil && rule.Once {
					consumedOnce = true
					consumedPolicy = p.Name
					consumedRuleIdx = res.ruleIndex
				}
			}
		}
	}

	if hasDurableAllow {
		return durableAllow
	}

	// Repository-local policies are additive. If no global rule fired, they
	// must not turn a restrictive global default into a less restrictive
	// outcome. This matters most for default_action: deny: a checked-in allow
	// rule must never create authority the user's global policy did not grant.
	if !anyGlobalRuleFired {
		switch defaultAction {
		case ActionDeny:
			return Decision{
				Action:          ActionDeny,
				MatchedPolicies: matched,
				Message:         "project policy cannot weaken global default deny",
				EvalDuration:    time.Since(start),
				Suggestions:     GenerateSuggestions(call),
			}
		case ActionAsk:
			return Decision{
				Action:          ActionAsk,
				MatchedPolicies: matched,
				Message:         "project policy cannot weaken global default ask",
				EvalDuration:    time.Since(start),
			}
		case ActionWatch:
			if finalAction == ActionAllow {
				return Decision{
					Action:          ActionWatch,
					MatchedPolicies: matched,
					Message:         "project policy cannot weaken global default watch",
					EvalDuration:    time.Since(start),
				}
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
		Action:             finalAction,
		Audit:              finalAudit,
		HeadlessOnly:       finalHeadlessOnly,
		FromProjectPolicy:  finalFromProject,
		MatchedPolicies:    matched,
		Message:            finalMessage,
		EvalDuration:       time.Since(start),
		WebhookConfig:      finalWebhookConfig,
		ConsumedOnce:       consumedOnce,
		ConsumedRulePolicy: consumedPolicy,
		ConsumedRuleIndex:  consumedRuleIdx,
	}
}

// Enforce records an actual host tool invocation and atomically consumes any
// matching once:true authorization. Callers that are only previewing policy
// must use Evaluate or EvaluateWith instead.
//
// The engine owns the arrival timestamp so an untrusted host payload cannot
// move call_count events outside their real enforcement window. Counter-state
// failures deny the call rather than silently losing enforcement state.
// Status telemetry is deliberately best-effort and cannot deny a call.
func (e *Engine) Enforce(call ToolCall, opts EvalOptions) Decision {
	arrivalTime := time.Now().UTC()
	call.Timestamp = arrivalTime
	if e.telemetryCalls != nil {
		_ = e.telemetryCalls.Increment(call.Tool, arrivalTime)
	}
	if e.RequiresCallCount(call) {
		if err := e.IncrementCallCount(call.Tool, arrivalTime); err != nil {
			e.logger.Error("engine: call counter unavailable; denying call",
				"tool", call.Tool,
				"error", err,
			)
			return Decision{
				Action:      ActionDeny,
				Message:     "call counter capacity unavailable; refusing tool call",
				Suggestions: GenerateSuggestions(call),
			}
		}
	}
	return e.EvaluateAndConsume(call, opts)
}

// EvaluateAndConsume evaluates a tool call and atomically claims any matching
// once:true allow before returning it. Ordinary evaluations stay lock-free;
// only callers contending for a one-time allow are serialized.
//
// Enforcement paths should use this method. Preview and policy-test paths
// should continue to use Evaluate or EvaluateWith because they must not mutate
// policy state.
func (e *Engine) EvaluateAndConsume(call ToolCall, opts EvalOptions) Decision {
	decision := e.EvaluateWith(call, opts)
	if !isOnceAllow(decision) {
		return decision
	}
	filePath, _, err := e.onceRuleDetails(decision)
	if err != nil {
		return e.denyFailedOnceClaim(call, decision, err)
	}

	e.onceMu.Lock()
	defer e.onceMu.Unlock()

	err = withPolicyFileLock(filePath, func() error {
		// Every hook invocation owns a separate Engine. Refresh only after the
		// cross-process lock is held so a waiter observes the winner's removal.
		if reloadErr := e.reloadLocked(true); reloadErr != nil {
			return reloadErr
		}
		decision = e.EvaluateWith(call, opts)
		if !isOnceAllow(decision) {
			return nil
		}

		currentPath, expected, detailErr := e.onceRuleDetails(decision)
		if detailErr != nil {
			return detailErr
		}
		lockedCanonical, detailErr := canonicalPolicyPath(filePath)
		if detailErr != nil {
			return detailErr
		}
		currentCanonical, detailErr := canonicalPolicyPath(currentPath)
		if detailErr != nil {
			return detailErr
		}
		if currentCanonical != lockedCanonical {
			return fmt.Errorf("engine: one-time rule source changed while claiming")
		}
		return e.consumeOnceRulePersistenceLocked(decision, currentPath, expected)
	})
	if err != nil {
		return e.denyFailedOnceClaim(call, decision, err)
	}
	return decision
}

func isOnceAllow(decision Decision) bool {
	return decision.Action == ActionAllow && decision.ConsumedOnce && decision.ConsumedRulePolicy != ""
}

func (e *Engine) denyFailedOnceClaim(call ToolCall, decision Decision, err error) Decision {
	e.logger.Error("engine: failed to claim once rule; denying call",
		"policy", decision.ConsumedRulePolicy,
		"rule_index", decision.ConsumedRuleIndex,
		"error", err,
	)
	decision.Action = ActionDeny
	decision.Message = "one-time authorization could not be claimed; failing closed"
	decision.Suggestions = GenerateSuggestions(call)
	decision.ConsumedOnce = false
	decision.ConsumedRulePolicy = ""
	decision.ConsumedRuleIndex = 0
	return decision
}

func (e *Engine) evaluateMatchingPolicy(p Policy, call ToolCall) evaluatePolicyResult {
	if isDurableAllowPolicy(p) {
		return e.evaluateDurableAllowPolicy(p, call)
	}
	return e.evaluatePolicy(p, call)
}

func (e *Engine) evaluateDurableAllowOverride(matching []Policy, call ToolCall, start time.Time) (Decision, bool) {
	for _, p := range matching {
		if !isDurableAllowPolicy(p) {
			continue
		}

		res := e.evaluateDurableAllowPolicy(p, call)
		if !res.matched || res.action != ActionAllow {
			continue
		}

		message := res.message
		if message == "" {
			message = durableAllowMessage(p)
		}

		decision := Decision{
			Action:          ActionAllow,
			MatchedPolicies: []string{p.Name},
			Message:         message,
			EvalDuration:    time.Since(start),
		}
		if res.rule != nil && res.rule.Once {
			decision.ConsumedOnce = true
			decision.ConsumedRulePolicy = p.Name
			decision.ConsumedRuleIndex = res.ruleIndex
		}
		return decision, true
	}

	return Decision{}, false
}

func (e *Engine) evaluateDurableAllowPolicy(p Policy, call ToolCall) evaluatePolicyResult {
	for i, rule := range p.Rules {
		if rule.IsExpired() || !matchDurableAllowCondition(rule.When, call, e.callCounter) {
			continue
		}
		action, err := rule.ParseAction()
		if err != nil {
			e.logger.Error("engine: invalid durable allow action", "policy", p.Name, "action", rule.Action, "error", err)
			return evaluatePolicyResult{ActionDeny, "invalid rule action; failing closed", nil, i, true}
		}
		return evaluatePolicyResult{action, rule.Message, &p.Rules[i], i, true}
	}
	return evaluatePolicyResult{matched: false}
}

func matchDurableAllowCondition(cond Condition, call ToolCall, counter CallCounter) bool {
	if cond.Default || cond.IsEmpty() {
		return true
	}
	if len(cond.CommandMatches) == 0 && len(cond.CommandContains) == 0 && len(cond.CommandEnvAssignments) == 0 {
		return matchConditionForAction(cond, call, counter, ActionAllow)
	}
	if !matchStrictCommandCondition(cond, call) {
		return false
	}
	cond.CommandMatches = nil
	cond.CommandContains = nil
	cond.CommandEnvAssignments = nil
	cond.CommandNotMatches = nil
	if cond.IsEmpty() {
		return true
	}
	return matchConditionForAction(cond, call, counter, ActionAllow)
}

func matchStrictCommandCondition(cond Condition, call ToolCall) bool {
	cmd := call.Command()
	if cmd == "" {
		return false
	}
	analysis := analyzeGrantCommand(cmd)
	cmdMatch := false
	if len(cond.CommandMatches) > 0 || len(cond.CommandContains) > 0 {
		cmdMatch, _ = matchGrantCommandFieldWithAnalysis(cond, cmd, ActionAllow, analysis)
	}
	if !cmdMatch {
		cmdMatch = matchFirstCommandEnvAssignment(cond.CommandEnvAssignments, cmd) != ""
	}
	if !cmdMatch {
		return false
	}
	if len(cond.CommandNotMatches) > 0 {
		if matchCommandAnyForAction(cond.CommandNotMatches, cmd, ActionDeny) ||
			matchCommandAnyForAction(cond.CommandNotMatches, analysis.normalized, ActionDeny) {
			return false
		}
		for _, component := range analysis.components {
			if matchCommandAnyForAction(cond.CommandNotMatches, component, ActionDeny) {
				return false
			}
		}
	}
	return true
}

// isDurableAllowPolicy reports whether a policy came from Rampart's durable
// human allow files. These are intentional operator carve-outs created by
// `rampart allow`, approval persist/Always Allow, or legacy auto-allow flows.
// Policy names alone are not trusted here: project or custom policy files must
// not be able to self-declare high-precedence operator overrides.
func isDurableAllowPolicy(p Policy) bool {
	profile := strings.ToLower(profileNameFromPath(p.FilePath))
	return profile == "user-overrides" || profile == "auto-allowed"
}

// durableAllowMessage returns the default audit/test message for a durable
// human allow policy when the matching rule did not provide one.
func durableAllowMessage(p Policy) string {
	profile := strings.ToLower(profileNameFromPath(p.FilePath))
	if profile == "auto-allowed" {
		return "auto-allowed by user rule"
	}
	return "allowed by durable user override"
}

// EvaluateResponse runs response-side evaluation against matching policies.
// Only response-specific conditions are considered.
// maxResponseMatchSize is the maximum response body size (in bytes) that will
// be evaluated against regex patterns.
const maxResponseMatchSize = 1 << 20 // 1 MB

func (e *Engine) EvaluateResponse(call ToolCall, response string) Decision {
	start := time.Now()
	if err := call.validateSecurityInput(); err != nil {
		return Decision{
			Action:       ActionDeny,
			Message:      fmt.Sprintf("ambiguous tool input (%v); failing closed", err),
			EvalDuration: time.Since(start),
		}
	}

	e.mu.RLock()
	cfg := e.config
	regexCache := e.responseRegex
	e.mu.RUnlock()

	if field, size := oversizedMatchInput(cfg, call); field != "" {
		return Decision{
			Action:       ActionDeny,
			Message:      fmt.Sprintf("%s is %d bytes and exceeds the %d-byte policy matching limit; failing closed", field, size, maxGlobInputLen),
			EvalDuration: time.Since(start),
		}
	}
	matching := e.collectMatching(cfg, call)
	if len(matching) == 0 {
		return Decision{
			Action:       ActionAllow,
			Message:      "no matching policy; response allowed",
			EvalDuration: time.Since(start),
		}
	}
	// Never scan only a prefix: a deny signature could be hidden beyond the
	// boundary. Fail closed only when an applicable response rule exists; large
	// ordinary tool output with no response policy remains unaffected.
	if len(response) > maxResponseMatchSize && hasResponseRules(matching) {
		return Decision{
			Action:       ActionDeny,
			Message:      fmt.Sprintf("response exceeds the %d-byte policy matching limit; failing closed", maxResponseMatchSize),
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

func hasResponseRules(policies []Policy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if len(rule.When.ResponseMatches) > 0 {
				return true
			}
		}
	}
	return false
}

// oversizedMatchInput identifies values that can reach a glob matcher. It is
// checked once at enforcement entry points so oversized values cannot make a
// deny pattern silently miss or an allow pattern evaluate only a prefix.
func oversizedMatchInput(cfg *Config, call ToolCall) (string, int) {
	fields := []struct {
		name  string
		value string
	}{
		{"agent", call.Agent},
		{"session", call.Session},
		{"tool", call.Tool},
		{"command", call.Command()},
		{"path", call.Path()},
		{"url", call.URL()},
		{"domain", call.Domain()},
	}
	for _, field := range fields {
		if len(field.value) > maxGlobInputLen {
			return field.name, len(field.value)
		}
	}

	if cfg == nil {
		return "", 0
	}
	for _, policy := range cfg.Policies {
		for _, rule := range policy.Rules {
			for parameter := range rule.When.ToolParamMatches {
				value, ok := call.Input[parameter]
				if !ok {
					continue
				}
				text := fmt.Sprintf("%v", value)
				if len(text) > maxGlobInputLen {
					return "tool parameter " + parameter, len(text)
				}
			}
		}
	}
	return "", 0
}

// Reload re-reads the policy file and replaces the active configuration.
// Returns an error if the new file is invalid; the old config remains active.
func (e *Engine) Reload() error {
	e.onceMu.Lock()
	defer e.onceMu.Unlock()
	return e.reloadLocked(false)
}

// reloadLocked reloads policy state while the caller holds onceMu. The
// allowPolicyWipe exception is used only after Rampart has intentionally
// consumed the last one-time policy from a file; public reload behavior stays
// fail-closed for accidental empty/truncated edits.
func (e *Engine) reloadLocked(allowPolicyWipe bool) error {
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
	currentHash := e.lastConfigHash
	e.mu.RUnlock()
	if !allowPolicyWipe && currentCount > 0 && len(cfg.Policies) == 0 {
		return fmt.Errorf("engine: reload rejected — policy count dropped from %d to 0", currentCount)
	}
	nextHash, err := configFingerprint(cfg)
	if err != nil {
		return fmt.Errorf("engine: fingerprint reloaded config: %w", err)
	}
	if nextHash == currentHash {
		return nil
	}

	e.mu.Lock()
	e.config = cfg
	e.defaultAction = e.parseDefaultAction(cfg.DefaultAction)
	e.lastLoadedAt = time.Now().UTC()
	e.lastConfigHash = nextHash
	e.responseRegex = cfg.responseRegexCache
	e.mu.Unlock()

	e.logger.Info("engine: policies reloaded",
		"count", len(cfg.Policies),
		"default_action", e.defaultAction,
	)

	return nil
}

func configFingerprint(cfg *Config) (string, error) {
	// Hash the complete serializable policy document rather than a hand-picked
	// subset. This keeps reload detection aligned automatically as policy fields
	// are added, while yaml:"-" runtime metadata and compiled caches stay out.
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// PolicyCount returns the number of loaded policies.
func (e *Engine) PolicyCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.config.Policies)
}

// PolicySnapshot is a summary of a loaded policy for display purposes.
type PolicySnapshot struct {
	Name       string   `json:"name"`
	Priority   int      `json:"priority,omitempty"`
	SourceFile string   `json:"source_file"`
	MatchTools []string `json:"match_tools,omitempty"`
	MatchAgent string   `json:"match_agent,omitempty"`
	RuleCount  int      `json:"rule_count"`
}

// Snapshot returns the currently loaded policies with source file information.
func (e *Engine) Snapshot() ([]PolicySnapshot, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []PolicySnapshot
	for _, p := range e.config.Policies {
		out = append(out, PolicySnapshot{
			Name:       p.Name,
			Priority:   p.Priority,
			SourceFile: p.FilePath,
			MatchTools: p.Match.Tool,
			MatchAgent: p.Match.Agent,
			RuleCount:  len(p.Rules),
		})
	}
	return out, e.config.DefaultAction
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

// IncrementCallCount records one PreToolUse tool invocation.
func (e *Engine) IncrementCallCount(tool string, at time.Time) error {
	if e == nil || e.callCounter == nil {
		return nil
	}
	return e.callCounter.Increment(tool, at)
}

// CallCounts returns per-tool invocation counts for the provided window.
func (e *Engine) CallCounts(window time.Duration) map[string]int {
	if e == nil || e.telemetryCalls == nil {
		return map[string]int{}
	}
	return e.telemetryCalls.Snapshot(window, time.Now().UTC())
}

// PolicySummaryRule is a flattened policy rule summary for UI/API display.
type PolicySummaryRule struct {
	Name    string
	Action  string
	Summary string
}

// GetPolicySummary returns active default action and flattened rule summaries.
func (e *Engine) GetPolicySummary() (string, []PolicySummaryRule) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	defaultAction := e.defaultAction.String()
	rules := make([]PolicySummaryRule, 0)
	for _, p := range e.config.Policies {
		if !p.IsEnabled() {
			continue
		}
		for _, r := range p.Rules {
			summary := strings.TrimSpace(r.Message)
			if summary == "" {
				summary = deriveSummaryFromRuleName(p.Name)
			}
			rules = append(rules, PolicySummaryRule{
				Name:    p.Name,
				Action:  strings.TrimSpace(strings.ToLower(r.Action)),
				Summary: summary,
			})
		}
	}

	return defaultAction, rules
}

// LastLoadedAt returns the UTC timestamp of the last successful load/reload.
func (e *Engine) LastLoadedAt() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastLoadedAt
}

// EngineStats holds current engine statistics.
type EngineStats struct {
	PolicyCount int
	RuleCount   int
	LastReload  time.Time
}

// Stats returns current engine statistics in a single atomic read.
func (e *Engine) Stats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	total := 0
	for _, p := range e.config.Policies {
		total += len(p.Rules)
	}
	return EngineStats{
		PolicyCount: len(e.config.Policies),
		RuleCount:   total,
		LastReload:  e.lastLoadedAt,
	}
}

func deriveSummaryFromRuleName(name string) string {
	cleaned := strings.TrimSpace(name)
	if cleaned == "" {
		return "policy rule"
	}
	cleaned = strings.ReplaceAll(cleaned, "-", " ")
	cleaned = strings.ReplaceAll(cleaned, "_", " ")
	return cleaned
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

// filterByProfile keeps only policies whose source file matches the given profile name.
// A profile name "paranoid" matches policies loaded from files named "paranoid.yaml",
// or embedded stores with path "embedded:paranoid".
func filterByProfile(policies []Policy, profile string) []Policy {
	var filtered []Policy
	for _, p := range policies {
		if p.FilePath == "" {
			continue // skip unknown-origin policies
		}
		name := profileNameFromPath(p.FilePath)
		if strings.EqualFold(name, profile) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// profileNameFromPath extracts a profile name from a policy file path.
// Handles both regular paths ("/home/user/.rampart/policies/standard.yaml" → "standard")
// and embedded store paths ("embedded:standard" → "standard").
func profileNameFromPath(path string) string {
	// Handle "embedded:<name>" format only — not Windows drive letters like "C:\...".
	if strings.HasPrefix(path, "embedded:") {
		name := path[len("embedded:"):]
		return strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	}
	base := filepath.Base(path)
	return strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
}

// matchesScope checks whether a tool call falls within a policy's scope
// (agent identity, session identity, and tool name).
func (e *Engine) matchesScope(m Match, call ToolCall) bool {
	// Check agent identity.
	if !MatchGlob(m.EffectiveAgent(), call.Agent) {
		return false
	}

	// Check session identity.
	if !MatchGlob(m.EffectiveSession(), call.Session) {
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
// evaluatePolicyResult holds the result of evaluating a single policy.
type evaluatePolicyResult struct {
	action    Action
	message   string
	rule      *Rule
	ruleIndex int
	matched   bool
}

func (e *Engine) evaluatePolicy(p Policy, call ToolCall) evaluatePolicyResult {
	for i, rule := range p.Rules {
		// Skip expired temporal rules.
		if rule.IsExpired() {
			continue
		}

		action, err := rule.ParseAction()
		if err != nil {
			if !matchConditionForAction(rule.When, call, e.callCounter, ActionDeny) {
				continue
			}
			e.logger.Error("engine: invalid rule action",
				"policy", p.Name,
				"action", rule.Action,
				"error", err,
			)
			// Fail closed: invalid rule = deny.
			return evaluatePolicyResult{ActionDeny, "invalid rule action; failing closed", nil, i, true}
		}
		if !matchConditionForAction(rule.When, call, e.callCounter, action) {
			continue
		}

		return evaluatePolicyResult{action, rule.Message, &p.Rules[i], i, true}
	}

	return evaluatePolicyResult{matched: false}
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
		case ActionRequireApproval, ActionAsk:
			// Response evaluation happens after the tool has run. There is no safe
			// approval boundary left to wait at, so an approval-requiring match must
			// block/redact the response instead of being treated as an allowed result
			// by callers that only block ActionDeny.
			return ActionDeny, message, matched, true
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
	e.startReloadOnce.Do(func() {
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
	})
}

func (e *Engine) onceRuleDetails(decision Decision) (string, Rule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var (
		filePath string
		expected Rule
		found    bool
	)
	for _, p := range e.config.Policies {
		if p.Name != decision.ConsumedRulePolicy {
			continue
		}
		if decision.ConsumedRuleIndex >= 0 && decision.ConsumedRuleIndex < len(p.Rules) {
			filePath = p.FilePath
			expected = p.Rules[decision.ConsumedRuleIndex]
			found = true
		}
		break
	}

	if !found {
		return "", Rule{}, fmt.Errorf("engine: cannot consume once rule — rule %d not found in policy %q",
			decision.ConsumedRuleIndex, decision.ConsumedRulePolicy)
	}
	if !expected.Once {
		return "", Rule{}, fmt.Errorf("engine: cannot consume once rule — rule %d in policy %q is not one-time",
			decision.ConsumedRuleIndex, decision.ConsumedRulePolicy)
	}
	if filePath == "" {
		return "", Rule{}, fmt.Errorf("engine: cannot consume once rule — policy %q has no file path", decision.ConsumedRulePolicy)
	}
	return filePath, expected, nil
}

// consumeOnceRulePersistenceLocked persists removal of the exact rule and
// refreshes engine state. The caller must hold both onceMu and the source
// policy's cross-process lock.
func (e *Engine) consumeOnceRulePersistenceLocked(decision Decision, filePath string, expected Rule) error {
	if err := removeRule(filePath, decision.ConsumedRulePolicy, decision.ConsumedRuleIndex, &expected); err != nil {
		return fmt.Errorf("engine: consume once rule: %w", err)
	}

	// A normal reload rejects a drop from one policy to zero because that can
	// indicate a truncated file. Here the empty policy set is intentional.
	if err := e.reloadLocked(true); err != nil {
		return fmt.Errorf("engine: consume once rule reload: %w", err)
	}
	e.logger.Info("engine: consumed once rule",
		"policy", decision.ConsumedRulePolicy,
		"rule_index", decision.ConsumedRuleIndex,
		"file", filePath,
	)
	return nil
}

// CleanExpired removes expired temporal rules from all loaded policy files
// and reloads the engine. Returns the total number of rules removed.
func (e *Engine) CleanExpired() (int, error) {
	// Collect unique file paths from loaded policies.
	e.mu.RLock()
	fileSet := make(map[string]bool)
	for _, p := range e.config.Policies {
		if p.FilePath != "" {
			fileSet[p.FilePath] = true
		}
	}
	e.mu.RUnlock()

	totalRemoved := 0
	for path := range fileSet {
		removed, err := CleanExpiredRules(path)
		if err != nil {
			e.logger.Error("engine: clean expired failed", "path", path, "error", err)
			continue
		}
		totalRemoved += removed
	}

	if totalRemoved > 0 {
		e.logger.Info("engine: cleaned expired rules", "removed", totalRemoved)
		if reloadErr := e.Reload(); reloadErr != nil {
			return totalRemoved, fmt.Errorf("engine: reload after cleanup: %w", reloadErr)
		}
	}
	return totalRemoved, nil
}

// Stop terminates the periodic reload goroutine, if running.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		close(e.stopReload)
	})
}

// parseDefaultAction converts a string default action to an Action constant.
func (e *Engine) parseDefaultAction(s string) Action {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return ActionAllow
	case "deny":
		return ActionDeny
	case "watch", "log": // "log" kept as deprecated alias
		return ActionWatch
	case "ask", "require_approval": // "require_approval" kept as deprecated alias
		return ActionAsk
	default:
		// If unspecified or invalid, default to deny (fail closed).
		return ActionDeny
	}
}
