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
	"strings"
	"unicode"
)

// ExtractSubcommands extracts commands embedded inside $(...), backticks,
// and eval "..." wrappers. It returns all extracted inner commands. This
// handles one level of nesting for $(...) — e.g. $(echo $(whoami)) yields
// both "echo $(whoami)" and "whoami". It does not attempt to handle deeply
// adversarial nesting; 90% coverage is the goal.
func ExtractSubcommands(cmd string) []string {
	var results []string

	// Extract $(...) substitutions (handling nested parens).
	results = append(results, extractDollarParen(cmd)...)

	// Extract backtick substitutions.
	results = append(results, extractBackticks(cmd)...)

	// Extract eval arguments.
	results = append(results, extractEval(cmd)...)

	return results
}

// extractDollarParen finds all $(...) in cmd and returns the inner commands.
// It handles nested parentheses by counting depth.
func extractDollarParen(cmd string) []string {
	var results []string
	i := 0
	for i < len(cmd)-1 {
		if cmd[i] == '$' && cmd[i+1] == '(' {
			// Find matching close paren.
			depth := 1
			start := i + 2
			j := start
			for j < len(cmd) && depth > 0 {
				if j+1 < len(cmd) && cmd[j] == '$' && cmd[j+1] == '(' {
					depth++
					j += 2
					continue
				}
				if cmd[j] == ')' {
					depth--
					if depth == 0 {
						inner := strings.TrimSpace(cmd[start:j])
						if inner != "" {
							results = append(results, inner)
							// Recurse to find nested subcommands.
							results = append(results, ExtractSubcommands(inner)...)
						}
					}
					j++
					continue
				}
				j++
			}
			i = j
		} else {
			i++
		}
	}
	return results
}

// extractBackticks finds all `...` in cmd and returns the inner commands.
func extractBackticks(cmd string) []string {
	var results []string
	i := 0
	for i < len(cmd) {
		if cmd[i] == '`' {
			j := i + 1
			for j < len(cmd) && cmd[j] != '`' {
				j++
			}
			if j < len(cmd) {
				inner := strings.TrimSpace(cmd[i+1 : j])
				if inner != "" {
					results = append(results, inner)
					results = append(results, ExtractSubcommands(inner)...)
				}
				i = j + 1
			} else {
				// Unclosed backtick — skip.
				i++
			}
		} else {
			i++
		}
	}
	return results
}

// extractEval detects eval "..." or eval '...' and extracts the argument.
func extractEval(cmd string) []string {
	var results []string
	// Tokenize to find "eval" as a command.
	trimmed := strings.TrimSpace(cmd)
	// Strip env var prefixes to find eval.
	tokens := tokenize(trimmed)
	start := 0
	for start < len(tokens) && isEnvAssignment(tokens[start]) {
		start++
	}
	tokens = tokens[start:]
	if len(tokens) >= 2 && tokens[0] == "eval" {
		inner := strings.Join(tokens[1:], " ")
		if inner != "" {
			results = append(results, inner)
			results = append(results, ExtractSubcommands(inner)...)
		}
	}
	return results
}

// SplitCompoundCommand splits a shell command on unquoted &&, ||, ;, and |
// operators, returning each segment trimmed. Escaped or quoted delimiters
// are not split on.
func SplitCompoundCommand(cmd string) []string {
	var segments []string
	var cur strings.Builder
	i := 0
	inSingle := false
	inDouble := false
	escaped := false

	for i < len(cmd) {
		ch := cmd[i]

		if escaped {
			cur.WriteByte(ch)
			escaped = false
			i++
			continue
		}

		if ch == '\\' && !inSingle {
			cur.WriteByte(ch)
			escaped = true
			i++
			continue
		}

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			cur.WriteByte(ch)
			i++
			continue
		}

		if ch == '"' && !inSingle {
			inDouble = !inDouble
			cur.WriteByte(ch)
			i++
			continue
		}

		if inSingle || inDouble {
			cur.WriteByte(ch)
			i++
			continue
		}

		// Check for &&, ||
		if i+1 < len(cmd) {
			two := cmd[i : i+2]
			if two == "&&" || two == "||" {
				s := strings.TrimSpace(cur.String())
				if s != "" {
					segments = append(segments, s)
				}
				cur.Reset()
				i += 2
				continue
			}
		}

		// Check for ; and |
		if ch == ';' || ch == '|' {
			s := strings.TrimSpace(cur.String())
			if s != "" {
				segments = append(segments, s)
			}
			cur.Reset()
			i++
			continue
		}

		cur.WriteByte(ch)
		i++
	}

	s := strings.TrimSpace(cur.String())
	if s != "" {
		segments = append(segments, s)
	}
	return segments
}

// NormalizeCommand takes a raw shell command string and returns a normalized
// version with shell metacharacter obfuscation removed. This handles the
// common evasion techniques:
//   - Quote stripping: 'rm' → rm, "rm" → rm
//   - Backslash removal: r\m → rm
//   - Env var prefix stripping: FOO=bar rm → rm
//   - Compound commands: each segment normalized independently, joined with " && "
//
// This is intentionally not a full bash parser — it handles the 90% case
// to prevent trivial policy evasion.
func NormalizeCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}

	segments := SplitCompoundCommand(cmd)
	if len(segments) == 0 {
		return ""
	}

	normalized := make([]string, 0, len(segments))
	for _, seg := range segments {
		n := normalizeSegment(seg)
		if n != "" {
			normalized = append(normalized, n)
		}
	}

	return strings.Join(normalized, " && ")
}

// normalizeSegment normalizes a single command (no compound operators).
func normalizeSegment(seg string) string {
	seg = strings.TrimSpace(seg)
	if seg == "" {
		return ""
	}

	tokens := tokenize(seg)
	if len(tokens) == 0 {
		return ""
	}

	// Strip leading env var assignments (VAR=value patterns before the command).
	start := 0
	for start < len(tokens) {
		if isEnvAssignment(tokens[start]) {
			start++
		} else {
			break
		}
	}
	tokens = tokens[start:]

	if len(tokens) == 0 {
		return ""
	}

	return strings.Join(tokens, " ")
}

// isEnvAssignment returns true if token looks like VAR=value.
func isEnvAssignment(token string) bool {
	eq := strings.IndexByte(token, '=')
	if eq <= 0 {
		return false
	}
	name := token[:eq]
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	// First char must be letter or underscore.
	first := rune(name[0])
	return unicode.IsLetter(first) || first == '_'
}

// tokenize splits a command into tokens, stripping quotes and backslash escapes.
func tokenize(cmd string) []string {
	var tokens []string
	var cur strings.Builder
	i := 0

	for i < len(cmd) {
		ch := cmd[i]

		// Skip whitespace between tokens.
		if ch == ' ' || ch == '\t' {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			i++
			continue
		}

		// Single-quoted string: everything literal until closing quote.
		if ch == '\'' {
			i++
			for i < len(cmd) && cmd[i] != '\'' {
				cur.WriteByte(cmd[i])
				i++
			}
			if i < len(cmd) {
				i++ // skip closing quote
			}
			continue
		}

		// Double-quoted string: backslash escapes work inside.
		if ch == '"' {
			i++
			for i < len(cmd) && cmd[i] != '"' {
				if cmd[i] == '\\' && i+1 < len(cmd) {
					i++
					cur.WriteByte(cmd[i])
					i++
					continue
				}
				cur.WriteByte(cmd[i])
				i++
			}
			if i < len(cmd) {
				i++ // skip closing quote
			}
			continue
		}

		// Backslash escape outside quotes.
		if ch == '\\' && i+1 < len(cmd) {
			i++
			cur.WriteByte(cmd[i])
			i++
			continue
		}

		cur.WriteByte(ch)
		i++
	}

	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}
