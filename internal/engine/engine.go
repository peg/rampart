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
	mu             sync.RWMutex
	config         *Config
	store          PolicyStore
	defaultAction  Action
	lastLoadedAt   time.Time
	lastConfigHash string
	responseRegex  map[string]*regexp.Regexp
	logger         *slog.Logger
	callCounter    CallCounter
	stopReload     chan struct{} // closed to stop periodic reload goroutine
	stopOnce       sync.Once
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
		config:      cfg,
		store:       store,
		logger:      logger,
		callCounter: NewSlidingWindowCounter(),
	}
	e.defaultAction = e.parseDefaultAction(cfg.DefaultAction)
	e.lastLoadedAt = time.Now().UTC()
	e.lastConfigHash = configFingerprint(cfg)
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

	e.mu.RLock()
	cfg := e.config
	defaultAction := e.defaultAction
	e.mu.RUnlock()

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
		finalAction       = ActionAllow
		finalMessage      string
		finalAudit        bool
		finalHeadlessOnly bool
		finalFromProject  bool
		matched           []string
		anyRuleFired      bool
		consumedOnce      bool
		consumedPolicy    string
		consumedRuleIdx   int
	)

	var finalWebhookConfig *WebhookActionConfig

	for _, p := range matching {
		res := e.evaluatePolicy(p, call)
		if !res.matched {
			continue // no rule matched within this policy
		}

		action, message, rule := res.action, res.message, res.rule
		anyRuleFired = true
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
	if len(cond.CommandMatches) == 0 && len(cond.CommandContains) == 0 {
		return matchCondition(cond, call, counter)
	}
	if !matchStrictCommandCondition(cond, call) {
		return false
	}
	cond.CommandMatches = nil
	cond.CommandContains = nil
	cond.CommandNotMatches = nil
	if cond.IsEmpty() {
		return true
	}
	return matchCondition(cond, call, counter)
}

func matchStrictCommandCondition(cond Condition, call ToolCall) bool {
	cmd := call.Command()
	if cmd == "" {
		return false
	}
	cmdMatch := false
	if len(cond.CommandMatches) > 0 {
		cmdMatch = matchAny(cond.CommandMatches, cmd)
		if norm := NormalizeCommand(cmd); !cmdMatch && norm != cmd {
			cmdMatch = matchAny(cond.CommandMatches, norm)
		}
	}
	if !cmdMatch {
		cmdLower := strings.ToLower(cmd)
		for _, sub := range cond.CommandContains {
			if strings.Contains(cmdLower, strings.ToLower(sub)) {
				cmdMatch = true
				break
			}
		}
	}
	if !cmdMatch {
		return false
	}
	return !matchAny(cond.CommandNotMatches, cmd) && !matchAny(cond.CommandNotMatches, NormalizeCommand(cmd))
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
	currentHash := e.lastConfigHash
	e.mu.RUnlock()
	if currentCount > 0 && len(cfg.Policies) == 0 {
		return fmt.Errorf("engine: reload rejected — policy count dropped from %d to 0", currentCount)
	}
	nextHash := configFingerprint(cfg)
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

func configFingerprint(cfg *Config) string {
	h := sha256.New()
	fmt.Fprintf(h, "default=%s|", cfg.DefaultAction)
	for _, p := range cfg.Policies {
		fmt.Fprintf(h, "policy:%s:%d{", p.Name, len(p.Rules))
		for _, r := range p.Rules {
			// Include rule content so changes to patterns, actions,
			// messages, etc. are detected even when rule count stays the same.
			fmt.Fprintf(h, "%s:%v:%s:%v;",
				r.Action,
				r.When,
				r.Message,
				r.Once,
			)
		}
		h.Write([]byte("}"))
	}
	return hex.EncodeToString(h.Sum(nil))
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
func (e *Engine) IncrementCallCount(tool string, at time.Time) {
	if e == nil || e.callCounter == nil {
		return
	}
	e.callCounter.Increment(tool, at)
}

// CallCounts returns per-tool invocation counts for the provided window.
func (e *Engine) CallCounts(window time.Duration) map[string]int {
	if e == nil || e.callCounter == nil {
		return map[string]int{}
	}
	return e.callCounter.Snapshot(window, time.Now().UTC())
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

		if !matchCondition(rule.When, call, e.callCounter) {
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
			return evaluatePolicyResult{ActionDeny, "invalid rule action; failing closed", nil, i, true}
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
		case ActionRequireApproval:
			if finalAction != ActionDeny && finalAction != ActionRequireApproval {
				finalAction = ActionRequireApproval
				finalMessage = message
			}
		case ActionAsk:
			// ask is a PreToolUse-only concept; in response rules treat like require_approval.
			if finalAction != ActionDeny && finalAction != ActionRequireApproval && finalAction != ActionAsk {
				finalAction = ActionAsk
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

// ConsumeOnceRule removes a once:true rule after it has been matched.
// This is called by the proxy after a decision with ConsumedOnce=true.
// The rule is removed from the on-disk policy file and the engine is reloaded.
func (e *Engine) ConsumeOnceRule(policyName string, ruleIndex int) error {
	// Look up the policy to find its source file path.
	e.mu.RLock()
	var filePath string
	for _, p := range e.config.Policies {
		if p.Name == policyName {
			filePath = p.FilePath
			break
		}
	}
	e.mu.RUnlock()

	if filePath == "" {
		return fmt.Errorf("engine: cannot consume once rule — policy %q has no file path", policyName)
	}
	if err := RemoveRule(filePath, policyName, ruleIndex); err != nil {
		return fmt.Errorf("engine: consume once rule: %w", err)
	}
	e.logger.Info("engine: consumed once rule",
		"policy", policyName,
		"rule_index", ruleIndex,
		"file", filePath,
	)
	// Reload to pick up the change.
	return e.Reload()
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
	case "ask", "require_approval": // "require_approval" kept as deprecated alias
		return ActionAsk
	default:
		// If unspecified or invalid, default to deny (fail closed).
		return ActionDeny
	}
}
