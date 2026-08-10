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

	policyutil "github.com/peg/rampart/internal/policy"
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
	maxGlobPatternLen       = policyutil.MaxGlobPatternLen
	maxDoubleGlobPatternLen = policyutil.MaxDoubleGlobPatternLen
)

// maxDoubleStarOccurrences bounds the complexity and ambiguity of policy
// patterns. MatchGlob also enforces this limit so callers which construct
// patterns outside Config validation still fail safely.
const maxDoubleStarOccurrences = policyutil.MaxDoubleStarOccurrences

func validateGlobPatterns(field string, patterns []string) error {
	return policyutil.ValidateGlobPatterns(field, patterns)
}

func MatchGlob(pattern, name string) bool {
	pattern, name, ok := normalizeGlobInputs(pattern, name)
	if !ok {
		return false
	}
	if pattern == "*" {
		return true
	}

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

func normalizeGlobInputs(pattern, name string) (string, string, bool) {
	if pattern == "" || len(pattern) > maxGlobPatternLen || len(name) > maxGlobInputLen {
		return "", "", false
	}
	if strings.Contains(pattern, "**") && len(pattern) > maxDoubleGlobPatternLen {
		return "", "", false
	}
	// Use explicit replacement instead of filepath.ToSlash so Windows paths are
	// normalized consistently even when a policy is evaluated on another host.
	return strings.ReplaceAll(pattern, "\\", "/"), strings.ReplaceAll(name, "\\", "/"), true
}

// matchPathGlob applies the documented filesystem glob semantics: '*' and '?'
// stay within one path segment, while only '**' may cross a separator. Command
// patterns intentionally use MatchGlob's broader trailing/leading-star behavior
// because their wildcard commonly spans arguments and URL slashes.
func matchPathGlob(pattern, name string) bool {
	pattern, name, ok := normalizeGlobInputs(pattern, name)
	if !ok || strings.Count(pattern, "**") > maxDoubleStarOccurrences {
		return false
	}
	return matchDoubleGlob(pattern, name)
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

// matchRestrictiveAlternateCommandFirst tries native Windows command
// interpretations after the portable shell interpretation has failed. Agent
// harnesses can submit POSIX-shell, cmd.exe, or raw PowerShell payloads on the
// same host, so the host OS alone does not identify the language. Alternate
// interpretations are intentionally limited to restrictive actions: using an
// ambiguous parse to grant execution could widen an allow rule.
func matchRestrictiveAlternateCommandFirst(patterns []string, command string, action Action) string {
	if !actionRestrictsExecution(action) {
		return ""
	}
	if mayNeedRestrictiveCommandAliases(command) {
		for _, alias := range restrictiveCommandAliases(command) {
			if matched := matchCommandFirstForAction(patterns, alias, action); matched != "" {
				return matched
			}
		}
	}
	if looksLikeCmdWrapper(command) {
		if matched := matchRestrictiveCommandDialectFirst(patterns, command, action, "windows"); matched != "" {
			return matched
		}
	}
	if looksLikePowerShellWrapper(command) {
		if matched := matchRestrictiveCommandDialectFirst(patterns, command, action, "powershell"); matched != "" {
			return matched
		}
	}
	// Most commands have identical relevant structure in all three dialects.
	// Avoid reparsing every restrictive non-match unless the input contains a
	// construct whose meaning actually differs from the portable parse.
	cmdAmbiguous := strings.ContainsRune(command, '^') ||
		strings.Contains(command, "&>") ||
		(strings.ContainsRune(command, '\'') && strings.ContainsAny(command, "&|"))
	if cmdAmbiguous {
		if matched := matchRestrictiveCommandDialectFirst(patterns, command, action, "windows"); matched != "" {
			return matched
		}
	}
	if strings.ContainsRune(command, '`') {
		if matched := matchRestrictiveCommandDialectFirst(patterns, command, action, "powershell"); matched != "" {
			return matched
		}
	}
	return ""
}

func mayNeedRestrictiveCommandAliases(command string) bool {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return false
	}
	head := trimmed
	if end := strings.IndexAny(head, " \t\r\n"); end >= 0 {
		head = head[:end]
	}
	base := strings.ToLower(shellWrapperBasename(head))
	if base != strings.ToLower(head) {
		return true
	}
	switch base {
	case "rm", "find", "busybox", "toybox":
		return true
	case "bash", "sh", "zsh", "dash":
		return strings.Contains(command, "<<<")
	default:
		return false
	}
}

// restrictiveCommandAliases returns conservative semantic spellings used only
// by deny/ask matching. They let a compact policy describe an operation rather
// than every executable path, equivalent flag order, or multicall wrapper.
func restrictiveCommandAliases(command string) []string {
	normalized := NormalizeCommand(command)
	if normalized == "" {
		normalized = command
	}
	segments := SplitCompoundCommand(normalized)
	if len(segments) == 0 {
		segments = []string{normalized}
	}

	seen := make(map[string]bool)
	aliases := make([]string, 0, len(segments)*2)
	appendAlias := func(tokens []string) {
		if len(tokens) == 0 {
			return
		}
		alias := strings.TrimSpace(strings.Join(tokens, " "))
		if alias == "" || alias == command || seen[alias] {
			return
		}
		seen[alias] = true
		aliases = append(aliases, alias)
	}

	for _, segment := range segments {
		tokens := tokenizeForOS(segment, "posix")
		if len(tokens) == 0 {
			continue
		}
		base := strings.ToLower(shellWrapperBasename(tokens[0]))
		if (base == "busybox" || base == "toybox") && len(tokens) > 1 && !strings.HasPrefix(tokens[1], "-") {
			tokens = tokens[1:]
			base = strings.ToLower(shellWrapperBasename(tokens[0]))
		}
		tokens[0] = base
		appendAlias(tokens)

		if base == "rm" {
			if canonical := canonicalRestrictiveRM(tokens); canonical != nil {
				appendAlias(canonical)
			}
		}
		if base == "find" {
			if canonical := canonicalRestrictiveFindDelete(tokens); canonical != nil {
				appendAlias(canonical)
			}
		}
		if base == "bash" || base == "sh" || base == "zsh" || base == "dash" {
			for i, token := range tokens {
				if token != "<<<" || i+1 >= len(tokens) {
					continue
				}
				appendAlias(tokens[i+1:])
			}
		}
	}
	return aliases
}

func canonicalRestrictiveRM(tokens []string) []string {
	recursive := false
	force := false
	operands := make([]string, 0, len(tokens))
	optionsEnded := false
	for _, token := range tokens[1:] {
		if optionsEnded {
			operands = append(operands, token)
			continue
		}
		if token == "--" {
			optionsEnded = true
			continue
		}
		switch token {
		case "--recursive":
			recursive = true
			continue
		case "--force":
			force = true
			continue
		}
		if len(token) > 1 && token[0] == '-' && token[1] != '-' {
			for _, flag := range token[1:] {
				switch flag {
				case 'r', 'R':
					recursive = true
				case 'f':
					force = true
				}
			}
			continue
		}
		if strings.HasPrefix(token, "--") {
			continue
		}
		operands = append(operands, token)
	}
	if !recursive || !force {
		return nil
	}
	return append([]string{"rm", "-rf"}, operands...)
}

func canonicalRestrictiveFindDelete(tokens []string) []string {
	hasDelete := false
	target := ""
	for _, token := range tokens[1:] {
		if token == "-delete" {
			hasDelete = true
			continue
		}
		if target == "" && !strings.HasPrefix(token, "-") {
			target = token
		}
	}
	if !hasDelete || target == "" {
		return nil
	}
	return []string{"rm", "-rf", target}
}

func matchRestrictiveCommandDialectFirst(patterns []string, command string, action Action, dialect string) string {
	match := func(candidate string) string {
		return matchCommandFirstForActionOS(patterns, candidate, "windows", action)
	}

	norm := normalizeCommandForOS(command, dialect)
	if norm != command {
		if matched := match(norm); matched != "" {
			return matched
		}
		for _, segment := range splitCompoundCommandForOS(norm, dialect) {
			if matched := match(segment); matched != "" {
				return matched
			}
		}
	}
	for _, segment := range splitCompoundCommandForOS(command, dialect) {
		if matched := match(segment); matched != "" {
			return matched
		}
		normalizedSegment := normalizeCommandForOS(segment, dialect)
		if normalizedSegment != segment {
			if matched := match(normalizedSegment); matched != "" {
				return matched
			}
		}
	}
	for _, subcommand := range ExtractSubcommands(command) {
		if matched := match(subcommand); matched != "" {
			return matched
		}
		normalizedSubcommand := normalizeCommandForOS(subcommand, dialect)
		if normalizedSubcommand != subcommand {
			if matched := match(normalizedSubcommand); matched != "" {
				return matched
			}
		}
	}
	return ""
}

// grantCommandAnalysis describes every command that a non-restrictive rule
// would authorize. A broad glob matching the raw compound string is not enough:
// each independently executed segment and nested substitution must be covered.
// This prevents a rule such as "git *" from authorizing
// "git status && unrelated-command" merely because '*' spans shell operators.
type grantCommandAnalysis struct {
	normalized string
	components []string
	composite  bool
}

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

	// A plain command is overwhelmingly the common path. Avoid a map and a
	// second normalization pass when there is only one already-normalized
	// component.
	if !analysis.composite {
		candidate := strings.TrimSpace(normalized)
		if candidate != "" {
			analysis.components = []string{candidate}
		}
		return analysis
	}

	seen := make(map[string]bool)
	components := make([]string, 0, 4)
	appendComponent := func(candidate string, normalize bool) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		if normalize {
			if normalizedCandidate := NormalizeCommand(candidate); normalizedCandidate != "" {
				candidate = normalizedCandidate
			}
		}
		if !seen[candidate] {
			seen[candidate] = true
			components = append(components, candidate)
		}
	}

	for _, segment := range segments {
		appendComponent(segment, false)
	}
	for _, subcommand := range subcommands {
		for _, segment := range SplitCompoundCommand(subcommand) {
			appendComponent(segment, true)
		}
	}
	analysis.components = components
	return analysis
}

// matchRestrictiveCommandComponent reports whether one independently executed
// command component satisfies the positive command fields of a restrictive
// rule. Components are evaluated separately so a safe command exclusion cannot
// consume a shell operator and suppress a dangerous sibling.
func matchRestrictiveCommandComponent(cond Condition, component string, action Action) (bool, string) {
	if matched := matchCommandFirstForAction(cond.CommandMatches, component, action); matched != "" {
		return true, fmt.Sprintf("command_matches [%q]", matched)
	}
	if normalized := NormalizeCommand(component); normalized != component {
		if matched := matchCommandFirstForAction(cond.CommandMatches, normalized, action); matched != "" {
			return true, fmt.Sprintf("command_matches [%q] (normalized)", matched)
		}
	}
	if matched := matchRestrictiveAlternateCommandFirst(cond.CommandMatches, component, action); matched != "" {
		return true, fmt.Sprintf("command_matches [%q] (alternate shell normalization)", matched)
	}
	for _, substring := range cond.CommandContains {
		if strings.Contains(strings.ToLower(component), strings.ToLower(substring)) {
			return true, fmt.Sprintf("command_contains [%q]", substring)
		}
	}
	return false, ""
}

func restrictiveCommandComponentExcluded(patterns []string, component string) bool {
	// Exclusions weaken a restrictive rule, so retain granting-action matching
	// semantics: executable names may follow host case rules, but arguments keep
	// their exact bytes.
	if matchCommandAnyForAction(patterns, component, ActionAllow) {
		return true
	}
	normalized := NormalizeCommand(component)
	return normalized != component && matchCommandAnyForAction(patterns, normalized, ActionAllow)
}

// restrictiveCommandMatchAfterExclusions returns true when a restrictive rule
// still has at least one positively matched command that is not independently
// excluded. wholeCommandMatched is the result of the broader restrictive
// matcher, which may recognize wrapper or dialect forms that cannot be safely
// attributed to a single component; those cases fail closed.
func restrictiveCommandMatchAfterExclusions(
	cond Condition,
	command string,
	action Action,
	wholeCommandMatched bool,
) (bool, string) {
	analysis := analyzeGrantCommand(command)
	if !analysis.composite {
		matched, detail := matchRestrictiveCommandComponent(cond, command, action)
		if !matched {
			return wholeCommandMatched, ""
		}
		if restrictiveCommandComponentExcluded(cond.CommandNotMatches, command) {
			return false, ""
		}
		return true, detail
	}

	matchedComponent := false
	for _, component := range analysis.components {
		matched, detail := matchRestrictiveCommandComponent(cond, component, action)
		if !matched {
			continue
		}
		matchedComponent = true
		if !restrictiveCommandComponentExcluded(cond.CommandNotMatches, component) {
			return true, detail + " (unexcluded executed component)"
		}
	}
	if matchedComponent {
		return false, ""
	}

	// A positive whole-command match that cannot be assigned to a component must
	// not be weakened by a broad exclusion spanning shell syntax.
	return wholeCommandMatched, ""
}

func isCompositeCommand(command string) bool {
	return analyzeGrantCommand(command).composite
}

func matchExplicitCompositeGrant(patterns []string, command, normalized, goos string, action Action) string {
	for _, pattern := range patterns {
		if !isCompositeCommand(pattern) {
			continue
		}
		if matchCommandAnyForActionOS([]string{pattern}, command, goos, action) ||
			(normalized != command && matchCommandAnyForActionOS([]string{pattern}, normalized, goos, action)) {
			return pattern
		}
	}
	return ""
}

// matchGrantCommandField evaluates command_matches and command_contains for
// allow/watch/webhook rules. Composite calls are granted only when the policy
// explicitly matches the complete composite expression or every executed
// component is independently covered.
func matchGrantCommandField(cond Condition, command string, action Action) (bool, string) {
	return matchGrantCommandFieldWithAnalysis(cond, command, action, analyzeGrantCommand(command))
}

func matchGrantCommandFieldWithAnalysis(cond Condition, command string, action Action, analysis grantCommandAnalysis) (bool, string) {
	matchOS := runtime.GOOS
	if looksLikeCmdWrapper(command) || looksLikePowerShellWrapper(command) {
		matchOS = "windows"
	}

	if analysis.composite {
		if matched := matchExplicitCompositeGrant(cond.CommandMatches, command, analysis.normalized, matchOS, action); matched != "" {
			return true, fmt.Sprintf("command_matches [%q] (explicit composite)", matched)
		}
	}

	components := analysis.components
	if len(components) == 0 {
		return false, ""
	}
	firstDetail := ""
	for _, component := range components {
		matched := matchCommandFirstForActionOS(cond.CommandMatches, component, matchOS, action)
		if matched != "" {
			if firstDetail == "" {
				firstDetail = fmt.Sprintf("command_matches [%q]", matched)
			}
			continue
		}

		containsMatched := ""
		for _, substring := range cond.CommandContains {
			if substring != "" && strings.Contains(component, substring) {
				containsMatched = substring
				break
			}
		}
		if containsMatched == "" {
			return false, ""
		}
		if firstDetail == "" {
			firstDetail = fmt.Sprintf("command_contains [%q]", containsMatched)
		}
	}

	if len(components) > 1 {
		firstDetail += " (all executed components)"
	}
	return true, firstDetail
}

func resolvePathPattern(pattern string) string {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	meta := strings.IndexAny(pattern, "*?[")
	if meta < 0 {
		_, resolved := cleanPathsAt(pattern, "")
		return filepath.ToSlash(resolved)
	}
	separator := strings.LastIndex(pattern[:meta], "/")
	if separator < 0 {
		return pattern
	}
	base := pattern[:separator]
	if base == "" {
		base = "/"
	}
	_, resolvedBase := cleanPathsAt(base, "")
	if resolvedBase == "" {
		return pattern
	}
	return strings.TrimSuffix(filepath.ToSlash(resolvedBase), "/") + pattern[separator:]
}

func matchPathFirstForActionOS(patterns []string, path, workDir, goos string, action Action) string {
	for _, pattern := range patterns {
		candidatePatterns := []string{pattern}
		if workDir != "" && filepath.IsAbs(path) && !filepath.IsAbs(pattern) {
			candidatePatterns = append(candidatePatterns, filepath.Join(workDir, pattern))
		}
		for _, candidatePattern := range append([]string(nil), candidatePatterns...) {
			if resolvedPattern := resolvePathPattern(candidatePattern); resolvedPattern != candidatePattern {
				candidatePatterns = append(candidatePatterns, resolvedPattern)
			}
		}
		candidatePaths := []string{path}
		if workDir != "" && !filepath.IsAbs(path) && filepath.IsAbs(pattern) {
			candidatePaths = append(candidatePaths, filepath.Join(workDir, path))
		}
		for _, candidatePattern := range candidatePatterns {
			for _, candidatePath := range candidatePaths {
				if matchPathGlob(candidatePattern, candidatePath) {
					return pattern
				}
				// A case-folded path match can only make enforcement stricter. Granting
				// actions preserve exact spelling because macOS can use case-sensitive
				// volumes and remote paths may not share the host filesystem semantics.
				if actionRestrictsExecution(action) && platformUsesCaseInsensitiveNames(goos) &&
					matchPathGlob(strings.ToLower(candidatePattern), strings.ToLower(candidatePath)) {
					return pattern
				}
			}
		}
	}
	return ""
}

func matchPathFirstForAction(patterns []string, path, workDir string, action Action) string {
	return matchPathFirstForActionOS(patterns, path, workDir, runtime.GOOS, action)
}

// matchPathFieldForAction accounts for both the lexical and symlink-resolved
// destinations. Restrictive rules match if any spelling is protected. A
// granting rule must cover every spelling so a workspace symlink cannot grant
// access to a target outside the allowed tree.
func matchPathFieldForAction(patterns []string, call ToolCall, action Action, requireAll bool) (bool, string) {
	candidates := pathCandidates(call)
	if len(candidates) == 0 {
		return false, ""
	}
	workDir := call.WorkingDirectory()
	first := ""
	for _, candidate := range candidates {
		matched := matchPathFirstForAction(patterns, candidate, workDir, action)
		if matched != "" && first == "" {
			first = matched
		}
		if requireAll && matched == "" {
			return false, ""
		}
		if !requireAll && matched != "" {
			return true, matched
		}
	}
	return requireAll && first != "", first
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
		if !actionRestrictsExecution(action) {
			matched, detail := matchGrantCommandField(cond, cmd, action)
			if !matched {
				return false, ""
			}
			return true, detail
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
				if actionRestrictsExecution(action) {
					for _, seg := range SplitCompoundCommand(norm) {
						if matched := matchCommandFirstForAction(cond.CommandMatches, seg, action); matched != "" {
							return true, fmt.Sprintf("command_matches [%q] (normalized compound segment)", matched)
						}
					}
				}
			}
			if actionRestrictsExecution(action) {
				// A restrictive rule applies to the entire call when any command it
				// executes matches. Execution-granting rules must match the complete
				// call; matching one benign segment must never authorize its siblings.
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
			if matched := matchRestrictiveAlternateCommandFirst(cond.CommandMatches, cmd, action); matched != "" {
				return true, fmt.Sprintf("command_matches [%q] (alternate shell normalization)", matched)
			}
		}

		// command_contains (case-insensitive substring) — catches patterns glob can't
		// express, e.g. bash <(curl URL) where the URL's / breaks glob * matching.
		// Case-insensitive so BASH <(CURL URL) doesn't bypass.
		for _, sub := range cond.CommandContains {
			contains := sub != "" && strings.Contains(cmd, sub)
			if actionRestrictsExecution(action) {
				// Config validation rejects empty values. Keep direct/programmatic
				// restrictive conditions fail-closed: an empty literal therefore
				// retains strings.Contains semantics and matches every command.
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
		requireAll := !actionRestrictsExecution(action)
		ok, matched := matchPathFieldForAction(cond.PathMatches, call, action, requireAll)
		if !ok || matched == "" {
			return false, ""
		}
		detail := fmt.Sprintf("path_matches [%q]", matched)
		if requireAll && len(pathCandidates(call)) > 1 {
			detail += " (all resolved destinations)"
		}
		return true, detail
	}

	if len(cond.URLMatches) > 0 {
		url := call.URL()
		matched := matchFirst(cond.URLMatches, url)
		if matched == "" {
			return false, ""
		}
		return true, fmt.Sprintf("url_matches [%q]", matched)
	}

	if len(cond.DomainMatches) > 0 {
		domain := call.Domain()
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

	var collect func(string, string, int)
	collect = func(raw, dialect string, depth int) {
		if depth > 4 || strings.TrimSpace(raw) == "" {
			return
		}
		segments := splitCompoundCommandForOS(raw, dialect)
		if len(segments) == 0 {
			segments = []string{raw}
		}
		for _, seg := range segments {
			tokens := tokenizeForOS(seg, dialect)
			collectEnvAssignmentNamesFromTokens(tokens, dialect, seen, &names)
			if unwrapped, nextDialect := stripShellWrapperOnceForOS(tokens, dialect); !strSlicesEqual(unwrapped, tokens) {
				collect(strings.Join(unwrapped, " "), nextDialect, depth+1)
			}
		}
		for _, sub := range ExtractSubcommands(raw) {
			collect(sub, dialect, depth+1)
		}
	}

	// Tool calls can select a shell independently of the Rampart host OS.
	// Parsing all supported command languages is conservative for restrictive
	// env-mutation rules and still requires assignment syntax at command start.
	for _, dialect := range []string{"posix", "windows", "powershell"} {
		collect(cmd, dialect, 0)
	}
	return names
}

func collectEnvAssignmentNamesFromTokens(tokens []string, dialect string, seen map[string]bool, names *[]string) {
	if len(tokens) == 0 {
		return
	}
	if dialect == "windows" {
		collectCmdEnvAssignment(tokens, seen, names)
		return
	}
	if dialect == "powershell" {
		collectPowerShellEnvAssignment(tokens, seen, names)
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

func collectCmdEnvAssignment(tokens []string, seen map[string]bool, names *[]string) {
	command := strings.ToLower(shellWrapperBasename(tokens[0]))
	if command != "set" && command != "setx" {
		return
	}
	for _, token := range tokens[1:] {
		if strings.HasPrefix(token, "/") {
			continue
		}
		if name, ok := envAssignmentName(strings.Trim(token, `"`)); ok {
			appendEnvAssignmentName(name, seen, names)
		}
		return
	}
}

func collectPowerShellEnvAssignment(tokens []string, seen map[string]bool, names *[]string) {
	first := strings.TrimSpace(tokens[0])
	if name := powerShellSetEnvironmentVariableName(tokens); name != "" {
		appendEnvAssignmentName(name, seen, names)
		return
	}
	if name := powerShellEnvReferenceName(first); name != "" {
		if strings.Contains(first, "=") || (len(tokens) > 1 && tokens[1] == "=") {
			appendEnvAssignmentName(name, seen, names)
		}
		return
	}

	command := strings.ToLower(shellWrapperBasename(first))
	switch command {
	case "set-item", "new-item", "set-content":
		for i := 1; i < len(tokens); i++ {
			token := strings.Trim(tokens[i], `"'`)
			if strings.EqualFold(token, "-path") || strings.EqualFold(token, "-literalpath") {
				continue
			}
			if name := powerShellEnvReferenceName(token); name != "" {
				appendEnvAssignmentName(name, seen, names)
				return
			}
		}
	}
}

func powerShellSetEnvironmentVariableName(tokens []string) string {
	joined := strings.TrimSpace(strings.Join(tokens, " "))
	lower := strings.ToLower(joined)
	methodEnd := -1
	for _, prefix := range []string{
		"[environment]::setenvironmentvariable",
		"[system.environment]::setenvironmentvariable",
	} {
		if strings.HasPrefix(lower, prefix) {
			methodEnd = len(prefix)
			break
		}
	}
	if methodEnd < 0 {
		return ""
	}
	remainder := strings.TrimLeft(joined[methodEnd:], " \t(")
	remainder = strings.TrimLeft(remainder, `"'`)
	if end := strings.IndexAny(remainder, ",\"') \t"); end >= 0 {
		remainder = remainder[:end]
	}
	if !validEnvAssignmentName(remainder) {
		return ""
	}
	return remainder
}

func powerShellEnvReferenceName(token string) string {
	token = strings.TrimSpace(token)
	lower := strings.ToLower(token)
	prefixLen := 0
	switch {
	case strings.HasPrefix(lower, "$env:"):
		prefixLen = len("$env:")
	case strings.HasPrefix(lower, "${env:"):
		prefixLen = len("${env:")
	case strings.HasPrefix(lower, "env:"):
		prefixLen = len("env:")
	default:
		return ""
	}
	name := token[prefixLen:]
	if index := strings.IndexAny(name, "= "); index >= 0 {
		name = name[:index]
	}
	name = strings.TrimSuffix(name, "}")
	if !validEnvAssignmentName(name) {
		return ""
	}
	return name
}

func validEnvAssignmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, r := range name {
		if index == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
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

		var grantAnalysis grantCommandAnalysis
		if !actionRestrictsExecution(action) {
			grantAnalysis = analyzeGrantCommand(cmd)
			cmdMatch, _ = matchGrantCommandFieldWithAnalysis(cond, cmd, action, grantAnalysis)
		} else if len(cond.CommandMatches) > 0 {
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
				// Restrictive rules apply when any executed segment or subcommand
				// matches, so a dangerous child cannot hide inside a larger call.
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
				if !cmdMatch && matchRestrictiveAlternateCommandFirst(cond.CommandMatches, cmd, action) != "" {
					cmdMatch = true
				}
			}
		}

		// command_contains is ORed with command_matches. Restrictive actions use
		// conservative case-insensitive matching; execution-granting actions keep
		// argument bytes exact so case-sensitive remote resources are not widened.
		// Useful for patterns that globs can't express (e.g. bash <(curl URL)
		// where the URL's / prevents glob * from matching across separators).
		if !cmdMatch && actionRestrictsExecution(action) {
			for _, sub := range cond.CommandContains {
				// Loaded policies cannot contain an empty value. If an internal
				// caller constructs one anyway, matching it is the fail-closed
				// behavior for deny/ask actions.
				contains := strings.Contains(strings.ToLower(cmd), strings.ToLower(sub))
				if contains {
					cmdMatch = true
					break
				}
			}
		}

		if !cmdMatch {
			return false
		}
		// Exclusions weaken a rule. Skip all normalization and component work
		// when the policy has no exclusions (the normal case).
		if len(cond.CommandNotMatches) > 0 {
			if actionRestrictsExecution(action) {
				if remainsMatched, _ := restrictiveCommandMatchAfterExclusions(cond, cmd, action, cmdMatch); !remainsMatched {
					return false
				}
			} else {
				if negativeCommandMatch(cond.CommandNotMatches, cmd) {
					return false
				}
				norm := grantAnalysis.normalized
				if norm != cmd && negativeCommandMatch(cond.CommandNotMatches, norm) {
					return false
				}
				for _, component := range grantAnalysis.components {
					if negativeCommandMatch(cond.CommandNotMatches, component) {
						return false
					}
				}
			}
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
		restrictive := actionRestrictsExecution(action)
		pathMatch, _ := matchPathFieldForAction(cond.PathMatches, call, action, !restrictive)
		if !pathMatch {
			return false
		}
		// Exclusions weaken restrictive rules, so they apply only when every
		// lexical/resolved destination is excluded. For granting rules, any
		// excluded spelling safely narrows the grant.
		if len(cond.PathNotMatches) > 0 {
			exclusionAction := ActionDeny
			exclusionRequiresAll := false
			if restrictive {
				exclusionAction = ActionAllow
				exclusionRequiresAll = true
			}
			if excluded, _ := matchPathFieldForAction(
				cond.PathNotMatches,
				call,
				exclusionAction,
				exclusionRequiresAll,
			); excluded {
				return false
			}
		}
		matched = true
	}

	// URL matching (for fetch/web tool calls).
	if len(cond.URLMatches) > 0 {
		url := call.URL()
		if url == "" || !matchAny(cond.URLMatches, url) {
			return false
		}
		matched = true
	}

	// Domain matching.
	if len(cond.DomainMatches) > 0 {
		domain := call.Domain()
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
	if !matchAnyRegex(cond.ResponseMatches, response, regexCache, logger, true) {
		return false
	}
	// response_not_matches weakens a response rule. If an exclusion cannot be
	// evaluated within the bound, it must not suppress a restrictive match.
	if matchAnyRegex(cond.ResponseNotMatches, response, regexCache, logger, false) {
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

func matchAnyRegex(patterns []string, value string, cache map[string]*regexp.Regexp, logger *slog.Logger, timeoutResult bool) bool {
	for _, pattern := range patterns {
		re, ok := cache[pattern]
		if !ok {
			continue
		}
		if matchRegexWithTimeout(pattern, re, value, logger, timeoutResult) {
			return true
		}
	}
	return false
}

func matchRegexWithTimeout(pattern string, re *regexp.Regexp, value string, logger *slog.Logger, timeoutResult bool) bool {
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
		return timeoutResult
	}
}
