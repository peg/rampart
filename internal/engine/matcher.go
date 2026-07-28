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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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
// filepath.EvalSymlinks to resolve symlinks (falling back to the
// cleaned path if the file doesn't exist yet). This ensures that
// traversal tricks like "/etc/../etc/shadow" are normalized before
// glob matching, regardless of which entry point (proxy, interceptor,
// MCP, SDK) produced the path.
// cleanPaths returns both the cleaned path and the symlink-resolved path.
// On macOS, /etc -> /private/etc, so policies matching "/etc/**" need to
// check both forms. For non-existent files, both values are the same.
func cleanPaths(p string) (cleaned string, resolved string) {
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
	cleaned = filepath.Clean(p)
	r, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return cleaned, cleaned
	}
	return cleaned, r
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
// maxGlobInputLen caps the input length for glob matching to prevent DoS
// with pathological patterns like **a**b**c on very long strings.
const maxGlobInputLen = 8192

func MatchGlob(pattern, name string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	// Cap input length to prevent DoS on pathological patterns.
	if len(name) > maxGlobInputLen {
		name = name[:maxGlobInputLen]
	}

	// Normalize path separators to forward slashes for cross-platform matching.
	// Windows paths use backslashes, but policy patterns use forward slashes.
	// This ensures "**/.ssh/id_*" matches "C:\Users\Trevor\.ssh\id_rsa".
	// Use strings.ReplaceAll instead of filepath.ToSlash because ToSlash only
	// converts on Windows, but we need this to work in tests on any platform.
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	name = strings.ReplaceAll(name, "\\", "/")

	// Handle "**" as a recursive wildcard.
	// matchDoubleGlob uses per-call memoization to keep complexity O(n·k)
	// where n = len(name) and k = number of "**" segments in the pattern.
	if strings.Contains(pattern, "**") {
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

// matchDoubleGlob handles "**" patterns by splitting on the first double-star
// and checking prefix matching + recursive suffix matching.
//
// Patterns with more than 2 "**" segments would require exponential
// backtracking without memoization proportional to input²; they are rejected
// at lint time and return false safely at runtime. Patterns with ≤2 segments
// cover all practical policy use-cases.
//
// When recursing, we slice at valid UTF-8 rune boundaries (detected via
// utf8.RuneStart) so the sub-string passed to each recursive call is always
// well-formed, preventing false negatives for non-ASCII paths.
//
// Examples:
//
//	"**/.ssh/id_*"      matches "/home/user/.ssh/id_rsa"
//	"/etc/**"           matches "/etc/passwd"
//	"**/*.go"           matches "/project/src/main.go"
//	"**pastebin.com**"  matches "https://pastebin.com/raw/abc"
//	"**/café/**"        matches "/home/user/café/notes.txt"
func matchDoubleGlob(pattern, name string) bool {
	// Bail out on patterns with >2 "**" segments. The recursive algorithm is
	// O(n^k) in the number of segments k; with k>2 on long inputs this becomes
	// pathological. Policy lint catches this at load time; runtime returns false
	// to fail safe rather than hang.
	if strings.Count(pattern, "**") > 2 {
		return false
	}

	parts := strings.SplitN(pattern, "**", 2)
	prefix := parts[0]
	suffix := parts[1]

	if prefix != "" && !strings.HasPrefix(name, prefix) {
		return false
	}

	if suffix == "" {
		return true
	}

	// Strip the matched prefix from name.
	remainder := name
	if prefix != "" {
		remainder = name[len(prefix):]
	}

	// If suffix contains more "**", recurse at each valid rune boundary.
	// Using utf8.RuneStart to skip continuation bytes ensures remainder[i:]
	// is always a valid UTF-8 string, avoiding false negatives for non-ASCII
	// paths (e.g. accented characters, CJK, emoji). Slicing the original
	// byte string at rune boundaries is O(1) and avoids the O(n²) allocation
	// that would result from converting to []rune and back.
	if strings.Contains(suffix, "**") {
		for i := 0; i <= len(remainder); i++ {
			// Skip continuation bytes of multi-byte runes so remainder[i:]
			// is always a valid UTF-8 string. The final position i==len(remainder)
			// is always a valid boundary (empty string), so only check when i>0
			// and i<len(remainder).
			if i > 0 && i < len(remainder) && !utf8.RuneStart(remainder[i]) {
				continue
			}
			if matchDoubleGlob(suffix, remainder[i:]) {
				return true
			}
		}
		return false
	}

	// When "**" is at the start (prefix is empty) and suffix starts with "/",
	// also try matching without the leading "/" to handle zero-depth paths.
	// This matches gitignore semantics: "**/.env" should match both
	// "project/.env" and bare ".env" (zero directory segments).
	if prefix == "" && strings.HasPrefix(suffix, "/") {
		trimmed := suffix[1:]
		if matched, _ := filepath.Match(trimmed, remainder); matched {
			return true
		}
	}

	return matchSuffixGlob(suffix, remainder)
}

// matchSuffixGlob checks if any tail of s matches the glob pattern.
// The pattern must not contain "**" (use matchDoubleGlob for that).
// Iterations are capped to prevent CPU exhaustion on long inputs.
//
// The string is converted to []rune before slicing so that each candidate
// tail is always a valid UTF-8 string, regardless of the characters in s.
// Slicing a UTF-8 string at an arbitrary byte offset can land in the middle
// of a multi-byte rune and produce an invalid string that filepath.Match
// will never match, causing false negatives for non-ASCII paths.
func matchSuffixGlob(pattern, s string) bool {
	const maxIter = 10000
	runes := []rune(s)
	limit := len(runes)
	if limit > maxIter {
		limit = maxIter
	}
	for i := 0; i <= limit; i++ {
		if matched, _ := filepath.Match(pattern, string(runes[i:])); matched {
			return true
		}
	}
	return false
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
// ExplainCondition checks if a condition matches a tool call, returning
// a human-readable detail string explaining what matched. Used by the
// `policy explain` CLI command.
func ExplainCondition(cond Condition, call ToolCall) (bool, string) {
	if cond.Default {
		return true, "default: true"
	}
	if cond.IsEmpty() {
		// Empty when: block is unconditional — matches all tool calls.
		// This mirrors matchCondition which also returns true for empty conditions.
		return true, "unconditional (empty when:)"
	}

	if len(cond.CommandMatches) > 0 || len(cond.CommandContains) > 0 {
		cmd := call.Command()
		if cmd == "" {
			return false, ""
		}

		// command_matches (glob) — mirror matchCondition: try raw, normalized,
		// compound segments, and subcommands.
		if len(cond.CommandMatches) > 0 {
			if matched := matchFirst(cond.CommandMatches, cmd); matched != "" {
				if !matchAny(cond.CommandNotMatches, cmd) {
					return true, fmt.Sprintf("command_matches [%q]", matched)
				}
			}
			// Try normalized form.
			norm := NormalizeCommand(cmd)
			if norm != cmd {
				if matched := matchFirst(cond.CommandMatches, norm); matched != "" {
					if !matchAny(cond.CommandNotMatches, cmd) && !matchAny(cond.CommandNotMatches, norm) {
						return true, fmt.Sprintf("command_matches [%q] (normalized)", matched)
					}
				}
				for _, seg := range SplitCompoundCommand(norm) {
					if matched := matchFirst(cond.CommandMatches, seg); matched != "" {
						return true, fmt.Sprintf("command_matches [%q] (normalized compound segment)", matched)
					}
				}
			}
			// Try each segment of compound commands.
			for _, seg := range SplitCompoundCommand(cmd) {
				if matched := matchFirst(cond.CommandMatches, seg); matched != "" {
					return true, fmt.Sprintf("command_matches [%q] (compound segment)", matched)
				}
				nseg := NormalizeCommand(seg)
				if nseg != seg {
					if matched := matchFirst(cond.CommandMatches, nseg); matched != "" {
						return true, fmt.Sprintf("command_matches [%q] (normalized compound segment)", matched)
					}
				}
			}
			// Check subcommands (command substitution, backticks, eval).
			for _, sub := range ExtractSubcommands(cmd) {
				if matched := matchFirst(cond.CommandMatches, sub); matched != "" {
					return true, fmt.Sprintf("command_matches [%q] (subcommand)", matched)
				}
				nsub := NormalizeCommand(sub)
				if nsub != sub {
					if matched := matchFirst(cond.CommandMatches, nsub); matched != "" {
						return true, fmt.Sprintf("command_matches [%q] (normalized subcommand)", matched)
					}
				}
			}
		}

		// command_contains (case-insensitive substring) — catches patterns glob can't
		// express, e.g. bash <(curl URL) where the URL's / breaks glob * matching.
		// Case-insensitive so BASH <(CURL URL) doesn't bypass.
		cmdLower := strings.ToLower(cmd)
		for _, sub := range cond.CommandContains {
			if strings.Contains(cmdLower, strings.ToLower(sub)) {
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
		cleaned, resolved := cleanPaths(call.Path())
		if cleaned == "" {
			return false, ""
		}
		matched := matchFirst(cond.PathMatches, cleaned)
		if matched == "" {
			matched = matchFirstFold(cond.PathMatches, cleaned)
		}
		if matched == "" && resolved != cleaned {
			matched = matchFirst(cond.PathMatches, resolved)
			if matched == "" {
				matched = matchFirstFold(cond.PathMatches, resolved)
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

	return false, ""
}

// ExplainConditionForAction keeps policy explanations aligned with the
// action-aware enforcement path. ExplainCondition retains the conservative
// restrictive-rule behavior for callers that do not know the action.
func ExplainConditionForAction(cond Condition, call ToolCall, action Action) (bool, string) {
	if !matchConditionForAction(cond, call, nil, action) {
		return false, ""
	}
	if actionGrantsExecution(action) &&
		(len(cond.CommandMatches) > 0 || len(cond.CommandContains) > 0) {
		return matchGrantCommandField(cond, call.Command())
	}
	return ExplainCondition(cond, call)
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

func matchFirstCommandEnvAssignment(patterns []string, cmd string) string {
	for _, name := range commandEnvAssignmentNames(cmd) {
		nameFold := strings.ToLower(name)
		for _, pattern := range patterns {
			if MatchGlob(strings.ToLower(pattern), nameFold) {
				return pattern
			}
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

// actionGrantsExecution reports whether a matching rule can permit the call to
// run. These actions must cover the complete shell expression; matching one
// harmless component must never authorize an unrelated sibling command.
func actionGrantsExecution(action Action) bool {
	return action == ActionAllow || action == ActionWatch || action == ActionWebhook
}

type grantCommandAnalysis struct {
	normalized string
	components []string
	composite  bool
}

// analyzeGrantCommand returns every independently executed command represented
// by a shell expression, including nested command substitutions.
func analyzeGrantCommand(command string) grantCommandAnalysis {
	normalized := NormalizeCommand(command)
	if normalized == "" {
		normalized = command
	}
	segments := SplitCompoundCommand(normalized)
	subcommands := ExtractSubcommands(command)
	analysis := grantCommandAnalysis{
		normalized: normalized,
		composite:  len(segments) > 1 || len(subcommands) > 0,
	}
	if !analysis.composite {
		if component := strings.TrimSpace(normalized); component != "" {
			analysis.components = []string{component}
		}
		return analysis
	}

	seen := make(map[string]bool)
	appendComponent := func(component string) {
		component = strings.TrimSpace(component)
		if component == "" || seen[component] {
			return
		}
		seen[component] = true
		analysis.components = append(analysis.components, component)
	}
	for _, segment := range segments {
		appendComponent(segment)
	}
	for _, subcommand := range subcommands {
		normalizedSubcommand := NormalizeCommand(subcommand)
		if normalizedSubcommand == "" {
			normalizedSubcommand = subcommand
		}
		for _, segment := range SplitCompoundCommand(normalizedSubcommand) {
			appendComponent(segment)
		}
	}
	return analysis
}

func isCompositeCommand(command string) bool {
	analysis := analyzeGrantCommand(command)
	return analysis.composite
}

func matchGrantComponent(cond Condition, component string) (bool, string) {
	if matched := matchFirst(cond.CommandMatches, component); matched != "" {
		return true, fmt.Sprintf("command_matches [%q]", matched)
	}
	componentLower := strings.ToLower(component)
	for _, substring := range cond.CommandContains {
		// An empty substring is rejected for execution-granting rules even when
		// a Condition is constructed programmatically instead of loaded.
		if substring != "" && strings.Contains(componentLower, strings.ToLower(substring)) {
			return true, fmt.Sprintf("command_contains [%q]", substring)
		}
	}
	return false, ""
}

// matchGrantCommandField requires an allow/watch/webhook rule to either match
// an explicitly composite pattern or cover every command the shell will run.
func matchGrantCommandField(cond Condition, command string) (bool, string) {
	analysis := analyzeGrantCommand(command)
	if len(analysis.components) == 0 {
		return false, ""
	}

	if matchAny(cond.CommandNotMatches, command) ||
		(analysis.normalized != command && matchAny(cond.CommandNotMatches, analysis.normalized)) {
		return false, ""
	}
	for _, component := range analysis.components {
		if matchAny(cond.CommandNotMatches, component) {
			return false, ""
		}
	}

	if analysis.composite {
		for _, pattern := range cond.CommandMatches {
			if !isCompositeCommand(pattern) {
				continue
			}
			if MatchGlob(pattern, command) ||
				(analysis.normalized != command && MatchGlob(pattern, analysis.normalized)) {
				return true, fmt.Sprintf("command_matches [%q] (explicit composite)", pattern)
			}
		}
	}

	detail := ""
	for _, component := range analysis.components {
		matched, componentDetail := matchGrantComponent(cond, component)
		if !matched {
			return false, ""
		}
		if detail == "" {
			detail = componentDetail
		}
	}
	if len(analysis.components) > 1 {
		detail += " (all executed components)"
	}
	return true, detail
}

func matchConditionForAction(cond Condition, call ToolCall, counter CallCounter, action Action) bool {
	if !actionGrantsExecution(action) ||
		(len(cond.CommandMatches) == 0 && len(cond.CommandContains) == 0) {
		return matchCondition(cond, call, counter)
	}
	if cond.Default || cond.IsEmpty() {
		return matchCondition(cond, call, counter)
	}
	commandMatched, _ := matchGrantCommandField(cond, call.Command())
	if !commandMatched {
		return false
	}

	// The command fields were evaluated above with whole-call semantics. Match
	// every remaining field once so counters and other stateful conditions are
	// not evaluated per shell component.
	remaining := cond
	remaining.CommandMatches = nil
	remaining.CommandContains = nil
	remaining.CommandNotMatches = nil
	if remaining.IsEmpty() {
		return true
	}
	return matchCondition(remaining, call, counter)
}

func matchCondition(cond Condition, call ToolCall, counter CallCounter) bool {
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

		if len(cond.CommandMatches) > 0 {
			cmdMatch = matchAny(cond.CommandMatches, cmd)
			if !cmdMatch {
				// Try normalized form.
				norm := NormalizeCommand(cmd)
				if norm != cmd {
					cmdMatch = matchAny(cond.CommandMatches, norm)
					if !cmdMatch {
						for _, seg := range SplitCompoundCommand(norm) {
							if matchAny(cond.CommandMatches, seg) {
								cmdMatch = true
								break
							}
						}
					}
				}
				// Try each segment of compound commands.
				if !cmdMatch {
					for _, seg := range SplitCompoundCommand(cmd) {
						if matchAny(cond.CommandMatches, seg) {
							cmdMatch = true
							break
						}
						nseg := NormalizeCommand(seg)
						if nseg != seg && matchAny(cond.CommandMatches, nseg) {
							cmdMatch = true
							break
						}
					}
				}
				// Check subcommands (command substitution, backticks, eval).
				if !cmdMatch {
					for _, sub := range ExtractSubcommands(cmd) {
						if matchAny(cond.CommandMatches, sub) {
							cmdMatch = true
							break
						}
						nsub := NormalizeCommand(sub)
						if nsub != sub && matchAny(cond.CommandMatches, nsub) {
							cmdMatch = true
							break
						}
					}
				}
			}
		}

		// command_contains: OR with command_matches — case-insensitive substring match.
		// Useful for patterns that globs can't express (e.g. bash <(curl URL)
		// where the URL's / prevents glob * from matching across separators).
		// Case-insensitive so adversarially-prompted agents can't bypass via CURL/BASH.
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
		// Exclusions: check raw, normalized, and segments.
		if matchAny(cond.CommandNotMatches, cmd) {
			return false
		}
		norm := NormalizeCommand(cmd)
		if norm != cmd && matchAny(cond.CommandNotMatches, norm) {
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
		if matchAny(cond.CommandNotMatches, cmd) {
			return false
		}
		if norm := NormalizeCommand(cmd); norm != cmd && matchAny(cond.CommandNotMatches, norm) {
			return false
		}
		matched = true
	}

	// Path matching (for read/write tool calls).
	// Canonicalize path to prevent traversal bypasses (e.g. /etc/../etc/shadow).
	if len(cond.PathMatches) > 0 {
		cleaned, resolved := cleanPaths(call.Path())
		if cleaned == "" {
			return false
		}
		pathMatch := matchAny(cond.PathMatches, cleaned)
		if !pathMatch {
			pathMatch = matchAnyFold(cond.PathMatches, cleaned)
		}
		if !pathMatch && resolved != cleaned {
			pathMatch = matchAny(cond.PathMatches, resolved)
			if !pathMatch {
				pathMatch = matchAnyFold(cond.PathMatches, resolved)
			}
		}
		if !pathMatch {
			return false
		}
		// Check exclusions against both forms too.
		if matchAny(cond.PathNotMatches, cleaned) ||
			matchAnyFold(cond.PathNotMatches, cleaned) ||
			(resolved != cleaned &&
				(matchAny(cond.PathNotMatches, resolved) || matchAnyFold(cond.PathNotMatches, resolved))) {
			return false
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
