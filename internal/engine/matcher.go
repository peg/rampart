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
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
)

const responseRegexMatchTimeout = 100 * time.Millisecond

// regexMatchFunc is a TEST-ONLY override for regex matching behavior
// (e.g., to simulate slow matches for timeout testing). It MUST NOT be
// set in production code. Protected by regexMatchMu to avoid data races
// with concurrent goroutines spawned by matchRegexWithTimeout.
//
// Usage pattern (tests only):
//
//	regexMatchMu.Lock()
//	regexMatchFunc = func(re *regexp.Regexp, s string) bool { ... }
//	regexMatchMu.Unlock()
//	defer func() { regexMatchMu.Lock(); regexMatchFunc = nil; regexMatchMu.Unlock() }()
var (
	regexMatchFunc func(*regexp.Regexp, string) bool // test-only; see comment above
	regexMatchMu   sync.RWMutex
)

func regexMatchString(re *regexp.Regexp, value string) bool {
	regexMatchMu.RLock()
	fn := regexMatchFunc
	regexMatchMu.RUnlock()
	if fn != nil {
		return fn(re, value)
	}
	return re.MatchString(value)
}

// cleanPath canonicalizes a file path for policy matching. It applies
// filepath.Clean to resolve ".." and "." segments, then attempts
// filepath.EvalSymlinks to resolve symlinks. If the leaf does not exist yet,
// it resolves the longest existing ancestor and restores the missing suffix.
// This ensures that
// traversal tricks like "/etc/../etc/shadow" are normalized before
// glob matching, regardless of which entry point (proxy, interceptor,
// MCP, SDK) produced the path.
// cleanPaths returns both the cleaned path and the symlink-resolved path.
// On macOS, /etc -> /private/etc, so policies matching "/etc/**" need to
// check both forms.
func cleanPaths(p string) (cleaned string, resolved string) {
	return cleanPathsAt(p, "")
}

// cleanPathsAt canonicalizes p relative to the directory used by the host
// tool. Rampart often runs in a long-lived service or one-shot hook whose own
// process CWD is unrelated to the agent workspace.
func cleanPathsAt(p, workDir string) (cleaned string, resolved string) {
	if p == "" {
		return p, p
	}
	// Normalize backslashes to forward slashes BEFORE filepath.Clean.
	// This is critical for security: on Unix, backslash is a valid filename char,
	// so "/home/user\../etc/shadow" would NOT be cleaned by filepath.Clean.
	// By normalizing first, the ".." traversal is properly resolved.
	// This also enables cross-platform policy matching (Windows paths match
	// forward-slash patterns like "**/.ssh/id_*").
	p = strings.ReplaceAll(p, "\\", "/")
	workDir = strings.ReplaceAll(strings.TrimSpace(workDir), "\\", "/")
	if workDir != "" && !filepath.IsAbs(p) {
		p = filepath.Join(workDir, p)
	}
	cleaned = filepath.Clean(p)

	// Resolve the full path when it exists. For a not-yet-created leaf, walk
	// upward until EvalSymlinks can resolve an existing ancestor, then append
	// the missing components. This prevents writes through a symlinked parent
	// directory from bypassing policy matching.
	candidate := cleaned
	var missing []string
	for {
		r, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			resolved = r
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return cleaned, resolved
		}
		if !os.IsNotExist(err) {
			return cleaned, cleaned
		}

		parent := filepath.Dir(candidate)
		if parent == candidate {
			return cleaned, cleaned
		}
		missing = append(missing, filepath.Base(candidate))
		candidate = parent
	}
}

// pathCandidates returns canonical host-resolved forms first, followed by the
// normalized relative spelling when a host CWD was supplied. Keeping the
// latter preserves compatibility with project policies such as `secrets/**`,
// while absolute and symlink-resolved candidates ensure system-path denies see
// the file the host will actually access.
func pathCandidates(call ToolCall) []string {
	path := call.Path()
	workDir := call.WorkingDirectory()
	cleaned, resolved := cleanPathsAt(path, workDir)
	candidates := make([]string, 0, 3)
	appendUnique := func(value string) {
		if value == "" {
			return
		}
		for _, existing := range candidates {
			if existing == value {
				return
			}
		}
		candidates = append(candidates, value)
	}
	appendUnique(cleaned)
	appendUnique(resolved)

	raw := strings.ReplaceAll(path, "\\", "/")
	if workDir != "" && raw != "" && !filepath.IsAbs(raw) {
		appendUnique(filepath.Clean(raw))
	}
	return candidates
}

// MatchGlob reports whether name matches the glob pattern.
//
// This extends filepath.Match with support for "**" (matches any path depth)
// and command-style patterns where spaces separate arguments:
//
//	"git *"       matches "git push", "git push origin main"
//	"rm -rf *"    matches "rm -rf /", "rm -rf /tmp"
//	"cat ~/.ssh/*" matches "cat ~/.ssh/id_rsa"
//
// An empty pattern matches nothing. A "*" pattern matches everything.
// MatchGlob is intentionally bounded. Enforcement entry points reject
// oversized match inputs before evaluating any allow or deny rules; returning
// false here keeps non-enforcement helpers bounded without partially matching
// a truncated value.
const maxGlobInputLen = 8192

const (
	// Ordinary filepath/segment patterns can safely remain large enough for
	// generated exact command and path approvals. Double-star patterns use the
	// NFA and receive a tighter product bound.
	maxGlobPatternLen       = 8192
	maxDoubleGlobPatternLen = 256
)

// maxDoubleStarOccurrences bounds the complexity and ambiguity of policy
// patterns. MatchGlob also enforces this limit so callers which construct
// patterns outside Config validation still fail safely.
const maxDoubleStarOccurrences = 2

func validateGlobPatterns(field string, patterns []string) error {
	for _, pattern := range patterns {
		if len(pattern) > maxGlobPatternLen {
			return fmt.Errorf("%s pattern is %d bytes (max %d)", field, len(pattern), maxGlobPatternLen)
		}
		count := strings.Count(pattern, "**")
		if count > 0 && len(pattern) > maxDoubleGlobPatternLen {
			return fmt.Errorf("%s double-star pattern is %d bytes (max %d)", field, len(pattern), maxDoubleGlobPatternLen)
		}
		if count > maxDoubleStarOccurrences {
			return fmt.Errorf("%s pattern %q has %d ** occurrences (max %d)", field, pattern, count, maxDoubleStarOccurrences)
		}
	}
	return nil
}

func MatchGlob(pattern, name string) bool {
	if pattern == "" || len(pattern) > maxGlobPatternLen || len(name) > maxGlobInputLen {
		return false
	}
	if strings.Contains(pattern, "**") && len(pattern) > maxDoubleGlobPatternLen {
		return false
	}
	if pattern == "*" {
		return true
	}
	// Normalize path separators to forward slashes for cross-platform matching.
	// Windows paths use backslashes, but policy patterns use forward slashes.
	// This ensures "**/.ssh/id_*" matches "C:\Users\Trevor\.ssh\id_rsa".
	// Use strings.ReplaceAll instead of filepath.ToSlash because ToSlash only
	// converts on Windows, but we need this to work in tests on any platform.
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	name = strings.ReplaceAll(name, "\\", "/")

	// Handle "**" with a bounded NFA-style matcher. Each input rune advances a
	// fixed set of pattern states, so a non-match is O(len(pattern)*len(name))
	// rather than recursively retrying every suffix. No suffix strings are
	// allocated while matching.
	if strings.Contains(pattern, "**") {
		if strings.Count(pattern, "**") > maxDoubleStarOccurrences {
			return false
		}
		return matchDoubleGlob(pattern, name)
	}

	// For command patterns, a trailing "*" should match the rest of the string
	// regardless of slashes or spaces. filepath.Match treats "*" as a single
	// segment glob (no "/" crossing), which breaks patterns like "dd if=*"
	// matching "dd if=/dev/zero of=/dev/sda".
	if strings.HasSuffix(pattern, "*") && !strings.HasSuffix(pattern, "**") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	// For patterns with leading "*" (e.g. "*curl*webhook.site*"), use
	// substring matching. Split on "*" and verify all parts appear in
	// order within the name. filepath.Match can't handle these because
	// "*" doesn't cross "/" boundaries.
	if strings.HasPrefix(pattern, "*") {
		return matchWildcardSegments(pattern, name)
	}

	// Fall back to filepath.Match for standard glob patterns.
	matched, err := filepath.Match(pattern, name)
	if err != nil {
		return false // invalid pattern = no match, not a panic
	}
	return matched
}

// matchDoubleGlob matches a pattern containing at most two "**" wildcards.
// It uses NFA-style state propagation: every token is visited at most once per
// input rune and the state vectors are bounded by the pattern length. This is
// deliberately index-based; it never constructs a string for an input suffix.
//
// Examples:
//
//	"**/.ssh/id_*"      matches "/home/user/.ssh/id_rsa"
//	"/etc/**"           matches "/etc/passwd"
//	"**/*.go"           matches "/project/src/main.go"
//	"**pastebin.com**"  matches "https://pastebin.com/raw/abc"
//	"**/café/**"        matches "/home/user/café/notes.txt"
func matchDoubleGlob(pattern, name string) bool {
	tokens, ok := tokenizeDoubleStarGlob(pattern)
	if !ok {
		return false
	}
	if runGlobNFA(tokens, name) {
		return true
	}

	// Preserve the established gitignore-style zero-depth behavior for a
	// leading "**/": it matches both "project/.env" and bare ".env".
	if strings.HasPrefix(pattern, "**/") {
		trimmed, ok := tokenizeDoubleStarGlob(pattern[len("**/"):])
		return ok && runGlobNFA(trimmed, name)
	}
	return false
}

type globTokenKind uint8

const (
	globLiteral globTokenKind = iota
	globSingleStar
	globDoubleStar
	globQuestion
	globClass
)

type globRange struct {
	lo rune
	hi rune
}

type globToken struct {
	kind    globTokenKind
	literal rune
	ranges  []globRange
	negated bool
}

func tokenizeDoubleStarGlob(pattern string) ([]globToken, bool) {
	runes := []rune(pattern)
	tokens := make([]globToken, 0, len(runes))
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				tokens = append(tokens, globToken{kind: globDoubleStar})
				i++
			} else {
				tokens = append(tokens, globToken{kind: globSingleStar})
			}
		case '?':
			tokens = append(tokens, globToken{kind: globQuestion})
		case '[':
			token, next, ok := parseGlobClass(runes, i)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, token)
			i = next
		default:
			tokens = append(tokens, globToken{kind: globLiteral, literal: runes[i]})
		}
	}
	return tokens, true
}

func parseGlobClass(pattern []rune, start int) (globToken, int, bool) {
	i := start + 1
	token := globToken{kind: globClass}
	if i < len(pattern) && pattern[i] == '^' {
		token.negated = true
		i++
	}
	for i < len(pattern) && pattern[i] != ']' {
		lo := pattern[i]
		hi := lo
		if i+2 < len(pattern) && pattern[i+1] == '-' && pattern[i+2] != ']' {
			hi = pattern[i+2]
			i += 3
		} else {
			i++
		}
		if lo > hi {
			return globToken{}, 0, false
		}
		token.ranges = append(token.ranges, globRange{lo: lo, hi: hi})
	}
	if i >= len(pattern) || len(token.ranges) == 0 {
		return globToken{}, 0, false
	}
	return token, i, true
}

func runGlobNFA(tokens []globToken, name string) bool {
	current := make([]bool, len(tokens)+1)
	next := make([]bool, len(tokens)+1)
	current[0] = true
	closeGlobStars(tokens, current)

	for _, value := range name {
		clear(next)
		for i, token := range tokens {
			if !current[i] {
				continue
			}
			switch token.kind {
			case globDoubleStar:
				next[i] = true
			case globSingleStar:
				if value != '/' {
					next[i] = true
				}
			case globQuestion:
				if value != '/' {
					next[i+1] = true
				}
			case globLiteral:
				if value == token.literal {
					next[i+1] = true
				}
			case globClass:
				if value != '/' && token.matchesClass(value) {
					next[i+1] = true
				}
			}
		}
		closeGlobStars(tokens, next)
		current, next = next, current
	}
	return current[len(tokens)]
}

func closeGlobStars(tokens []globToken, states []bool) {
	for i, token := range tokens {
		if states[i] && (token.kind == globSingleStar || token.kind == globDoubleStar) {
			states[i+1] = true
		}
	}
}

func (t globToken) matchesClass(value rune) bool {
	matched := false
	for _, item := range t.ranges {
		if value >= item.lo && value <= item.hi {
			matched = true
			break
		}
	}
	if t.negated {
		return !matched
	}
	return matched
}

// matchAny reports whether name matches any of the given glob patterns.
func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if MatchGlob(p, name) {
			return true
		}
	}
	return false
}

func matchAnyFold(patterns []string, name string) bool {
	lower := strings.ToLower(name)
	for _, p := range patterns {
		if MatchGlob(strings.ToLower(p), lower) {
			return true
		}
	}
	return false
}

func matchAnyForOS(patterns []string, name, goos string) bool {
	if matchAny(patterns, name) {
		return true
	}
	return platformUsesCaseInsensitiveNames(goos) && matchAnyFold(patterns, name)
}

func matchCommandHeadFoldFirst(patterns []string, command string) string {
	foldedCommand := foldCommandHead(command)
	for _, pattern := range patterns {
		if MatchGlob(foldCommandHead(pattern), foldedCommand) {
			return pattern
		}
	}
	return ""
}

// foldCommandHead normalizes only the executable/cmdlet token. Command names
// follow host case rules, while arguments may identify case-sensitive remote
// resources such as URL paths and Git refs and must retain their exact bytes.
func foldCommandHead(command string) string {
	end := strings.IndexFunc(command, unicode.IsSpace)
	if end < 0 {
		return strings.ToLower(command)
	}
	return strings.ToLower(command[:end]) + command[end:]
}

// Windows and the default macOS filesystem resolve command and path names
// case-insensitively. Matching must be at least as conservative as the host
// filesystem or mixed-case spellings can bypass a lowercase deny pattern.
// Case-sensitive macOS volumes may consequently over-match, which is the safe
// failure mode for an enforcement boundary.
func platformUsesCaseInsensitiveNames(goos string) bool {
	return goos == "windows" || goos == "darwin"
}

func matchCommandAnyForAction(patterns []string, command string, action Action) bool {
	return matchCommandAnyForActionOS(patterns, command, runtime.GOOS, action)
}

func matchCommandAnyForActionOS(patterns []string, command, goos string, action Action) bool {
	return matchCommandFirstForActionOS(patterns, command, goos, action) != ""
}

func matchCommandFirstForAction(patterns []string, command string, action Action) string {
	return matchCommandFirstForActionOS(patterns, command, runtime.GOOS, action)
}

func matchCommandFirstForActionOS(patterns []string, command, goos string, action Action) string {
	if matched := matchFirst(patterns, command); matched != "" {
		return matched
	}
	if !platformUsesCaseInsensitiveNames(goos) {
		return ""
	}
	if actionRestrictsExecution(action) {
		// A restrictive false positive fails safely, so match the complete command
		// conservatively on hosts whose command lookup is case-insensitive.
		return matchFirstFold(patterns, command)
	}
	// Allow/watch/webhook matches can grant execution. Normalize only the
	// executable or cmdlet and preserve potentially case-sensitive arguments.
	return matchCommandHeadFoldFirst(patterns, command)
}

func actionRestrictsExecution(action Action) bool {
	return action == ActionDeny || action == ActionAsk || action == ActionRequireApproval
}

func matchPathAny(patterns []string, path string) bool {
	return matchAnyForOS(patterns, path, runtime.GOOS)
}

func matchDomainAny(patterns []string, domain string) bool {
	return matchDomainFirst(patterns, domain) != ""
}

func matchDomainFirst(patterns []string, domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return ""
	}
	for _, p := range patterns {
		pattern := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if pattern == "" {
			continue
		}
		matched, err := filepath.Match(pattern, domain)
		if err == nil && matched {
			return p
		}
	}
	return ""
}

// matchCondition evaluates whether a tool call satisfies a rule's condition.
//
// Matching logic:
//   - If Default is true, the condition always matches.
//   - If no conditions are specified (empty), the condition never matches.
//   - CommandMatches/PathMatches/etc. are OR within a field.
//   - CommandNotMatches/PathNotMatches exclude matches.
//   - Multiple field types are AND (e.g., CommandMatches AND PathMatches).
//
// ExplainCondition checks a condition using restrictive-action semantics and
// returns a human-readable detail string. Callers that know the rule action
// should use ExplainConditionForAction so explanations cannot claim that an
// execution-granting rule matched more broadly than enforcement.
func ExplainCondition(cond Condition, call ToolCall) (bool, string) {
	return ExplainConditionForAction(cond, call, ActionDeny)
}

// ExplainConditionForAction mirrors the enforcement match for action before
// rendering the first useful match detail. The upfront check is important for
// conditions with multiple fields, which are ANDed by enforcement.
func ExplainConditionForAction(cond Condition, call ToolCall, action Action) (bool, string) {
	if cond.Default {
		return true, "default: true"
	}
	if cond.IsEmpty() {
		// Empty when: block is unconditional — matches all tool calls.
		// This mirrors matchCondition which also returns true for empty conditions.
		return true, "unconditional (empty when:)"
	}
	if !matchConditionForAction(cond, call, nil, action) {
		return false, ""
	}

	if len(cond.CommandMatches) > 0 || len(cond.CommandContains) > 0 {
		cmd := call.Command()
		if cmd == "" {
			return false, ""
		}

		// command_matches (glob) — mirror matchCondition: try raw, normalized,
		// compound segments, and subcommands.
		if len(cond.CommandMatches) > 0 {
			if matched := matchCommandFirstForAction(cond.CommandMatches, cmd, action); matched != "" {
				return true, fmt.Sprintf("command_matches [%q]", matched)
			}
			// Try normalized form.
			norm := NormalizeCommand(cmd)
			if norm != cmd {
				if matched := matchCommandFirstForAction(cond.CommandMatches, norm, action); matched != "" {
					return true, fmt.Sprintf("command_matches [%q] (normalized)", matched)
				}
				for _, seg := range SplitCompoundCommand(norm) {
					if matched := matchCommandFirstForAction(cond.CommandMatches, seg, action); matched != "" {
						return true, fmt.Sprintf("command_matches [%q] (normalized compound segment)", matched)
					}
				}
			}
			// Try each segment of compound commands.
			for _, seg := range SplitCompoundCommand(cmd) {
				if matched := matchCommandFirstForAction(cond.CommandMatches, seg, action); matched != "" {
					return true, fmt.Sprintf("command_matches [%q] (compound segment)", matched)
				}
				nseg := NormalizeCommand(seg)
				if nseg != seg {
					if matched := matchCommandFirstForAction(cond.CommandMatches, nseg, action); matched != "" {
						return true, fmt.Sprintf("command_matches [%q] (normalized compound segment)", matched)
					}
				}
			}
			// Check subcommands (command substitution, backticks, eval).
			for _, sub := range ExtractSubcommands(cmd) {
				if matched := matchCommandFirstForAction(cond.CommandMatches, sub, action); matched != "" {
					return true, fmt.Sprintf("command_matches [%q] (subcommand)", matched)
				}
				nsub := NormalizeCommand(sub)
				if nsub != sub {
					if matched := matchCommandFirstForAction(cond.CommandMatches, nsub, action); matched != "" {
						return true, fmt.Sprintf("command_matches [%q] (normalized subcommand)", matched)
					}
				}
			}
		}

		// command_contains (case-insensitive substring) — catches patterns glob can't
		// express, e.g. bash <(curl URL) where the URL's / breaks glob * matching.
		// Case-insensitive so BASH <(CURL URL) doesn't bypass.
		for _, sub := range cond.CommandContains {
			contains := strings.Contains(cmd, sub)
			if actionRestrictsExecution(action) {
				contains = strings.Contains(strings.ToLower(cmd), strings.ToLower(sub))
			}
			if contains {
				return true, fmt.Sprintf("command_contains [%q]", sub)
			}
		}
		return false, ""
	}

	if len(cond.CommandEnvAssignments) > 0 {
		cmd := call.Command()
		if cmd == "" {
			return false, ""
		}
		if matched := matchFirstCommandEnvAssignment(cond.CommandEnvAssignments, cmd); matched != "" {
			return true, fmt.Sprintf("command_env_assignments [%q]", matched)
		}
		return false, ""
	}

	if len(cond.PathMatches) > 0 {
		candidates := pathCandidates(call)
		if len(candidates) == 0 {
			return false, ""
		}
		matched := ""
		for _, candidate := range candidates {
			if matched = matchPathFirst(cond.PathMatches, candidate); matched != "" {
				break
			}
		}
		if matched == "" {
			return false, ""
		}
		return true, fmt.Sprintf("path_matches [%q]", matched)
	}

	if len(cond.URLMatches) > 0 {
		url := call.Param("url")
		matched := matchFirst(cond.URLMatches, url)
		if matched == "" {
			return false, ""
		}
		return true, fmt.Sprintf("url_matches [%q]", matched)
	}

	if len(cond.DomainMatches) > 0 {
		domain := call.Param("domain")
		matched := matchDomainFirst(cond.DomainMatches, domain)
		if matched == "" {
			return false, ""
		}
		return true, fmt.Sprintf("domain_matches [%q]", matched)
	}

	if cond.AgentDepth != nil {
		if cond.AgentDepth.Gte != nil && call.AgentDepth < *cond.AgentDepth.Gte {
			return false, ""
		}
		if cond.AgentDepth.Lte != nil && call.AgentDepth > *cond.AgentDepth.Lte {
			return false, ""
		}
		if cond.AgentDepth.Eq != nil && call.AgentDepth != *cond.AgentDepth.Eq {
			return false, ""
		}
		return true, fmt.Sprintf("agent_depth [%d]", call.AgentDepth)
	}

	if len(cond.ToolParamMatches) > 0 {
		for param, pattern := range cond.ToolParamMatches {
			val, ok := call.Input[param]
			if !ok {
				continue
			}
			str := fmt.Sprintf("%v", val)
			if MatchGlob(strings.ToLower(pattern), strings.ToLower(str)) {
				return true, fmt.Sprintf("tool_param_matches [%s=%q]", param, pattern)
			}
		}
		return false, ""
	}

	if len(cond.SessionMatches) > 0 {
		return true, fmt.Sprintf("session_matches [%q]", matchFirst(cond.SessionMatches, call.Session))
	}
	if len(cond.SessionNotMatches) > 0 {
		return true, "session_not_matches (no exclusion matched)"
	}

	return false, ""
}

// matchFirst returns the first pattern that matches value, or "".
func matchFirst(patterns []string, value string) string {
	for _, p := range patterns {
		if MatchGlob(p, value) {
			return p
		}
	}
	return ""
}

func matchFirstFold(patterns []string, value string) string {
	lower := strings.ToLower(value)
	for _, p := range patterns {
		if MatchGlob(strings.ToLower(p), lower) {
			return p
		}
	}
	return ""
}

func matchFirstForOS(patterns []string, value, goos string) string {
	if matched := matchFirst(patterns, value); matched != "" {
		return matched
	}
	if platformUsesCaseInsensitiveNames(goos) {
		return matchFirstFold(patterns, value)
	}
	return ""
}

func matchPathFirst(patterns []string, path string) string {
	return matchFirstForOS(patterns, path, runtime.GOOS)
}

func matchFirstCommandEnvAssignment(patterns []string, cmd string) string {
	return matchFirstCommandEnvAssignmentForOS(patterns, cmd, runtime.GOOS)
}

func matchFirstCommandEnvAssignmentForOS(patterns []string, cmd, goos string) string {
	for _, name := range commandEnvAssignmentNames(cmd) {
		matched := matchFirst(patterns, name)
		// Environment variable names are case-insensitive on Windows, but remain
		// case-sensitive in macOS and Unix shells regardless of filesystem rules.
		if matched == "" && goos == "windows" {
			matched = matchFirstFold(patterns, name)
		}
		if matched != "" {
			return matched
		}
	}
	return ""
}

func commandEnvAssignmentNames(cmd string) []string {
	seen := map[string]bool{}
	names := make([]string, 0)

	var collect func(string, int)
	collect = func(raw string, depth int) {
		if depth > 4 || strings.TrimSpace(raw) == "" {
			return
		}
		segments := SplitCompoundCommand(raw)
		if len(segments) == 0 {
			segments = []string{raw}
		}
		for _, seg := range segments {
			tokens := tokenize(seg)
			collectEnvAssignmentNamesFromTokens(tokens, seen, &names)
			if unwrapped := stripShellWrapperOnce(tokens); !strSlicesEqual(unwrapped, tokens) {
				collect(strings.Join(unwrapped, " "), depth+1)
			}
		}
		for _, sub := range ExtractSubcommands(raw) {
			collect(sub, depth+1)
		}
	}

	collect(cmd, 0)
	return names
}

func collectEnvAssignmentNamesFromTokens(tokens []string, seen map[string]bool, names *[]string) {
	if len(tokens) == 0 {
		return
	}
	for i := 0; i < len(tokens); i++ {
		name, ok := envAssignmentName(tokens[i])
		if !ok {
			break
		}
		appendEnvAssignmentName(name, seen, names)
	}

	switch filepath.Base(tokens[0]) {
	case "env":
		for i := 1; i < len(tokens); i++ {
			tok := tokens[i]
			if tok == "--" {
				continue
			}
			if tok == "-u" || tok == "--unset" {
				i++
				continue
			}
			if strings.HasPrefix(tok, "--unset=") || strings.HasPrefix(tok, "-") {
				continue
			}
			name, ok := envAssignmentName(tok)
			if !ok {
				break
			}
			appendEnvAssignmentName(name, seen, names)
		}
	case "export", "declare", "typeset":
		for _, tok := range tokens[1:] {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			if name, ok := envAssignmentName(tok); ok {
				appendEnvAssignmentName(name, seen, names)
			}
		}
	}
}

func envAssignmentName(token string) (string, bool) {
	if !isEnvAssignment(token) {
		return "", false
	}
	name := token[:strings.IndexByte(token, '=')]
	return name, true
}

func appendEnvAssignmentName(name string, seen map[string]bool, names *[]string) {
	if name == "" || seen[name] {
		return
	}
	seen[name] = true
	*names = append(*names, name)
}

func matchCondition(cond Condition, call ToolCall, counter CallCounter) bool {
	return matchConditionForAction(cond, call, counter, ActionDeny)
}

func matchConditionForAction(cond Condition, call ToolCall, counter CallCounter, action Action) bool {
	if cond.Default {
		return true
	}
	if cond.IsEmpty() {
		return true
	}

	matched := false

	// Command matching (for exec tool calls).
	// Shell-aware: normalize the command to prevent evasion via quotes,
	// backslash escapes, and env var prefixes. Also match against each
	// segment of compound commands. We match against BOTH raw and
	// normalized forms for backward compatibility.
	if len(cond.CommandMatches) > 0 || len(cond.CommandContains) > 0 {
		cmd := call.Command()
		if cmd == "" {
			return false
		}
		cmdMatch := false
		positiveCommandMatch := func(patterns []string, command string) bool {
			return matchCommandAnyForAction(patterns, command, action)
		}
		negativeAction := ActionDeny
		if actionRestrictsExecution(action) {
			// Exclusions weaken a restrictive rule, so preserve argument casing.
			negativeAction = ActionAllow
		}
		negativeCommandMatch := func(patterns []string, command string) bool {
			return matchCommandAnyForAction(patterns, command, negativeAction)
		}

		if len(cond.CommandMatches) > 0 {
			cmdMatch = positiveCommandMatch(cond.CommandMatches, cmd)
			if !cmdMatch {
				// Try normalized form.
				norm := NormalizeCommand(cmd)
				if norm != cmd {
					cmdMatch = positiveCommandMatch(cond.CommandMatches, norm)
					if !cmdMatch {
						for _, seg := range SplitCompoundCommand(norm) {
							if positiveCommandMatch(cond.CommandMatches, seg) {
								cmdMatch = true
								break
							}
						}
					}
				}
				// Try each segment of compound commands.
				if !cmdMatch {
					for _, seg := range SplitCompoundCommand(cmd) {
						if positiveCommandMatch(cond.CommandMatches, seg) {
							cmdMatch = true
							break
						}
						nseg := NormalizeCommand(seg)
						if nseg != seg && positiveCommandMatch(cond.CommandMatches, nseg) {
							cmdMatch = true
							break
						}
					}
				}
				// Check subcommands (command substitution, backticks, eval).
				if !cmdMatch {
					for _, sub := range ExtractSubcommands(cmd) {
						if positiveCommandMatch(cond.CommandMatches, sub) {
							cmdMatch = true
							break
						}
						nsub := NormalizeCommand(sub)
						if nsub != sub && positiveCommandMatch(cond.CommandMatches, nsub) {
							cmdMatch = true
							break
						}
					}
				}
			}
		}

		// command_contains is ORed with command_matches. Restrictive actions use
		// conservative case-insensitive matching; execution-granting actions keep
		// argument bytes exact so case-sensitive remote resources are not widened.
		// Useful for patterns that globs can't express (e.g. bash <(curl URL)
		// where the URL's / prevents glob * from matching across separators).
		if !cmdMatch {
			for _, sub := range cond.CommandContains {
				contains := strings.Contains(cmd, sub)
				if actionRestrictsExecution(action) {
					contains = strings.Contains(strings.ToLower(cmd), strings.ToLower(sub))
				}
				if contains {
					cmdMatch = true
					break
				}
			}
		}

		if !cmdMatch {
			return false
		}
		// Exclusions: check raw, normalized, and segments.
		if negativeCommandMatch(cond.CommandNotMatches, cmd) {
			return false
		}
		norm := NormalizeCommand(cmd)
		if norm != cmd && negativeCommandMatch(cond.CommandNotMatches, norm) {
			return false
		}
		matched = true
	}

	if len(cond.CommandEnvAssignments) > 0 {
		cmd := call.Command()
		if cmd == "" {
			return false
		}
		if matchFirstCommandEnvAssignment(cond.CommandEnvAssignments, cmd) == "" {
			return false
		}
		negativeAction := ActionDeny
		if actionRestrictsExecution(action) {
			negativeAction = ActionAllow
		}
		if matchCommandAnyForAction(cond.CommandNotMatches, cmd, negativeAction) {
			return false
		}
		if norm := NormalizeCommand(cmd); norm != cmd && matchCommandAnyForAction(cond.CommandNotMatches, norm, negativeAction) {
			return false
		}
		matched = true
	}

	// Path matching (for read/write tool calls).
	// Canonicalize path to prevent traversal bypasses (e.g. /etc/../etc/shadow).
	if len(cond.PathMatches) > 0 {
		candidates := pathCandidates(call)
		if len(candidates) == 0 {
			return false
		}
		pathMatch := false
		for _, candidate := range candidates {
			if matchPathAny(cond.PathMatches, candidate) {
				pathMatch = true
				break
			}
		}
		if !pathMatch {
			return false
		}
		// Check exclusions against both forms too.
		for _, candidate := range candidates {
			if matchPathAny(cond.PathNotMatches, candidate) {
				return false
			}
		}
		matched = true
	}

	// URL matching (for fetch/web tool calls).
	if len(cond.URLMatches) > 0 {
		url := call.Param("url")
		if url == "" || !matchAny(cond.URLMatches, url) {
			return false
		}
		matched = true
	}

	// Domain matching.
	if len(cond.DomainMatches) > 0 {
		domain := call.Param("domain")
		if domain == "" || !matchDomainAny(cond.DomainMatches, domain) {
			return false
		}
		matched = true
	}

	// Nested sub-agent depth matching.
	if cond.AgentDepth != nil {
		if cond.AgentDepth.Gte != nil && call.AgentDepth < *cond.AgentDepth.Gte {
			return false
		}
		if cond.AgentDepth.Lte != nil && call.AgentDepth > *cond.AgentDepth.Lte {
			return false
		}
		if cond.AgentDepth.Eq != nil && call.AgentDepth != *cond.AgentDepth.Eq {
			return false
		}
		matched = true
	}

	// MCP tool input parameter matching (case-insensitive glob).
	if len(cond.ToolParamMatches) > 0 {
		paramMatched := false
		for param, pattern := range cond.ToolParamMatches {
			val, ok := call.Input[param]
			if !ok {
				continue
			}
			str := fmt.Sprintf("%v", val)
			if MatchGlob(strings.ToLower(pattern), strings.ToLower(str)) {
				paramMatched = true
				break
			}
		}
		if !paramMatched {
			return false
		}
		matched = true
	}

	// Per-tool call count matching over a sliding time window.
	if cond.CallCount != nil {
		if counter == nil {
			return false
		}

		window, err := time.ParseDuration(strings.TrimSpace(cond.CallCount.Window))
		if err != nil || window <= 0 {
			return false
		}

		targetTool := strings.TrimSpace(cond.CallCount.Tool)
		if targetTool == "" {
			targetTool = call.Tool
		}
		if targetTool == "" {
			return false
		}

		count := counter.Count(targetTool, window, time.Now().UTC())
		if count < cond.CallCount.Gte {
			return false
		}
		matched = true
	}

	// Session matching.
	if len(cond.SessionMatches) > 0 && !matchAny(cond.SessionMatches, call.Session) {
		return false
	}
	if len(cond.SessionNotMatches) > 0 && matchAny(cond.SessionNotMatches, call.Session) {
		return false
	}
	if len(cond.SessionMatches) > 0 {
		matched = true
	}

	return matched
}

// matchResponseCondition evaluates response-side matching for a rule.
//
// Matching logic:
//   - ResponseMatches must have at least one pattern and one must match.
//   - ResponseNotMatches excludes matches.
func matchResponseCondition(
	cond Condition,
	response string,
	regexCache map[string]*regexp.Regexp,
	logger *slog.Logger,
) bool {
	if len(cond.ResponseMatches) == 0 {
		return false
	}
	if response == "" {
		return false
	}
	if !matchAnyRegex(cond.ResponseMatches, response, regexCache, logger) {
		return false
	}
	if matchAnyRegex(cond.ResponseNotMatches, response, regexCache, logger) {
		return false
	}
	return true
}

// matchWildcardSegments handles patterns like "*curl*webhook.site*" by
// splitting on "*" and checking that all non-empty segments appear in order.
func matchWildcardSegments(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	remaining := name
	for _, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(remaining, part)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(part):]
	}
	return true
}

func matchAnyRegex(patterns []string, value string, cache map[string]*regexp.Regexp, logger *slog.Logger) bool {
	for _, pattern := range patterns {
		re, ok := cache[pattern]
		if !ok {
			continue
		}
		if matchRegexWithTimeout(pattern, re, value, logger) {
			return true
		}
	}
	return false
}

func matchRegexWithTimeout(pattern string, re *regexp.Regexp, value string, logger *slog.Logger) bool {
	ctx, cancel := context.WithTimeout(context.Background(), responseRegexMatchTimeout)
	defer cancel()

	resultCh := make(chan bool, 1)
	go func() {
		resultCh <- regexMatchString(re, value)
	}()

	select {
	case matched := <-resultCh:
		return matched
	case <-ctx.Done():
		if logger != nil {
			logger.Warn("engine: response regex match timed out",
				"pattern", pattern,
				"timeout", responseRegexMatchTimeout,
			)
		}
		// Fail closed: treat timeout as a match so deny rules still fire.
		// A slow/adversarial input should not bypass security checks.
		return true
	}
}
