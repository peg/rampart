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
)

const responseRegexMatchTimeout = 100 * time.Millisecond

// regexMatchFunc can be set in tests to override regex matching behavior
// (e.g., to simulate slow matches). Must be set before any concurrent
// evaluation. Protected by a mutex to avoid races with goroutines.
var (
	regexMatchFunc  func(*regexp.Regexp, string) bool
	regexMatchMu    sync.RWMutex
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
func MatchGlob(pattern, name string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}

	// Handle "**" as a recursive wildcard.
	// Limit the number of "**" segments to prevent quadratic complexity.
	if strings.Contains(pattern, "**") {
		if strings.Count(pattern, "**") > 3 {
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

// matchDoubleGlob handles "**" patterns by splitting on the first double-star
// and checking prefix matching + recursive suffix matching.
//
// Examples:
//
//	"**/.ssh/id_*"      matches "/home/user/.ssh/id_rsa"
//	"/etc/**"           matches "/etc/passwd"
//	"**/*.go"           matches "/project/src/main.go"
//	"**pastebin.com**"  matches "https://pastebin.com/raw/abc"
func matchDoubleGlob(pattern, name string) bool {
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

	// If suffix contains more "**", recurse.
	if strings.Contains(suffix, "**") {
		// Try matching suffix pattern at every position in remainder.
		for i := 0; i <= len(remainder); i++ {
			if matchDoubleGlob(suffix, remainder[i:]) {
				return true
			}
		}
		return false
	}

	return matchSuffixGlob(suffix, remainder)
}

// matchSuffixGlob checks if any tail of s matches the glob pattern.
// The pattern must not contain "**" (use matchDoubleGlob for that).
func matchSuffixGlob(pattern, s string) bool {
	for i := 0; i <= len(s); i++ {
		if matched, _ := filepath.Match(pattern, s[i:]); matched {
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
		return false, ""
	}

	if len(cond.CommandMatches) > 0 {
		cmd := call.Command()
		if cmd == "" {
			return false, ""
		}
		matched := matchFirst(cond.CommandMatches, cmd)
		if matched == "" {
			return false, ""
		}
		if matchAny(cond.CommandNotMatches, cmd) {
			return false, ""
		}
		return true, fmt.Sprintf("command_matches [%q]", matched)
	}

	if len(cond.PathMatches) > 0 {
		cleaned, resolved := cleanPaths(call.Path())
		if cleaned == "" {
			return false, ""
		}
		matched := matchFirst(cond.PathMatches, cleaned)
		if matched == "" && resolved != cleaned {
			matched = matchFirst(cond.PathMatches, resolved)
		}
		if matched == "" {
			return false, ""
		}
		return true, fmt.Sprintf("path_matches [%q]", matched)
	}

	if len(cond.URLMatches) > 0 {
		url, _ := call.Params["url"].(string)
		matched := matchFirst(cond.URLMatches, url)
		if matched == "" {
			return false, ""
		}
		return true, fmt.Sprintf("url_matches [%q]", matched)
	}

	if len(cond.DomainMatches) > 0 {
		domain, _ := call.Params["domain"].(string)
		matched := matchFirst(cond.DomainMatches, domain)
		if matched == "" {
			return false, ""
		}
		return true, fmt.Sprintf("domain_matches [%q]", matched)
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

func matchCondition(cond Condition, call ToolCall) bool {
	if cond.Default {
		return true
	}
	if cond.IsEmpty() {
		return false
	}

	matched := false

	// Command matching (for exec tool calls).
	if len(cond.CommandMatches) > 0 {
		cmd := call.Command()
		if cmd == "" || !matchAny(cond.CommandMatches, cmd) {
			return false
		}
		if matchAny(cond.CommandNotMatches, cmd) {
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
		if !pathMatch && resolved != cleaned {
			pathMatch = matchAny(cond.PathMatches, resolved)
		}
		if !pathMatch {
			return false
		}
		// Check exclusions against both forms too.
		if matchAny(cond.PathNotMatches, cleaned) || (resolved != cleaned && matchAny(cond.PathNotMatches, resolved)) {
			return false
		}
		matched = true
	}

	// URL matching (for fetch/web tool calls).
	if len(cond.URLMatches) > 0 {
		url, _ := call.Params["url"].(string)
		if url == "" || !matchAny(cond.URLMatches, url) {
			return false
		}
		matched = true
	}

	// Domain matching.
	if len(cond.DomainMatches) > 0 {
		domain, _ := call.Params["domain"].(string)
		if domain == "" || !matchAny(cond.DomainMatches, domain) {
			return false
		}
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
		return false
	}
}
