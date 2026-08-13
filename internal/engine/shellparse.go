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
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// ansiEscapeRE matches ANSI escape sequences (CSI and simple ESC[...m).
var ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

var (
	timeoutDurationRE = regexp.MustCompile(`^(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[smhd])?$`)
	stdbufModeRE      = regexp.MustCompile(`^(?:0|L|B|[0-9]+(?:[kKmMgGtTpPeEzZyY](?:i?[bB])?)?)$`)
)

// ExtractSubcommands extracts commands embedded inside $(...), backticks,
// and eval "..." wrappers. It returns all extracted inner commands. This
// handles one level of nesting for $(...) — e.g. $(echo $(whoami)) yields
// both "echo $(whoami)" and "whoami". It does not attempt to handle deeply
// adversarial nesting; 90% coverage is the goal.
// SanitizeCommand strips null bytes, ANSI escape sequences, and non-printable
// control characters (except \t and \n) from a command string. This prevents
// evasion via invisible characters that shells may ignore but policy matching
// would see as different bytes.
func SanitizeCommand(cmd string) string {
	// Strip ANSI escape sequences first.
	cmd = ansiEscapeRE.ReplaceAllString(cmd, "")

	var b strings.Builder
	b.Grow(len(cmd))
	for _, r := range cmd {
		// Skip null bytes.
		if r == 0 {
			continue
		}
		// Keep tabs and newlines.
		if r == '\t' || r == '\n' {
			b.WriteRune(r)
			continue
		}
		// Skip other control characters (0x01-0x1f).
		if r < 0x20 {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func ExtractSubcommands(cmd string) []string {
	cmd = SanitizeCommand(cmd)
	var results []string

	// Extract $(...) substitutions (handling nested parens).
	results = append(results, extractDollarParen(cmd)...)

	// Extract backtick substitutions.
	results = append(results, extractBackticks(cmd)...)

	// Extract eval arguments.
	results = append(results, extractEval(cmd)...)

	// Extract process substitutions <(...) and >(...).
	results = append(results, extractProcessSubstitution(cmd)...)

	return results
}

// extractProcessSubstitution finds <(...) and >(...) in cmd and returns inner commands.
func extractProcessSubstitution(cmd string) []string {
	var results []string
	i := 0
	for i < len(cmd)-1 {
		if (cmd[i] == '<' || cmd[i] == '>') && cmd[i+1] == '(' {
			depth := 1
			start := i + 2
			j := start
			for j < len(cmd) && depth > 0 {
				if cmd[j] == '(' {
					depth++
				} else if cmd[j] == ')' {
					depth--
					if depth == 0 {
						inner := strings.TrimSpace(cmd[start:j])
						if inner != "" {
							results = append(results, inner)
							results = append(results, ExtractSubcommands(inner)...)
						}
					}
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

// SplitCompoundCommand splits a shell command on unquoted &, &&, ||, ;, and |
// operators, returning each segment trimmed. Escaped or quoted delimiters
// are not split on.
func SplitCompoundCommand(cmd string) []string {
	// Tool calls describe the command language chosen by the agent, not the OS
	// running Rampart. Agents routinely invoke bash/sh through Git Bash, WSL,
	// containers, and remote shells from a Windows host. Treat the unwrapped
	// command as POSIX shell syntax; explicit cmd.exe wrappers switch their own
	// inner tokenization to Windows semantics in normalizeSegmentForOS.
	return splitCompoundCommandForOS(cmd, "posix")
}

// splitCompoundCommandForOS exposes shell-specific parsing to cross-platform
// tests. cmd.exe uses caret (not backslash) escaping, does not treat single
// quotes as quoting, and parses &> as a command separator followed by an output
// redirect. POSIX shells treat &> as a combined redirection operator.
func splitCompoundCommandForOS(cmd, goos string) []string {
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

		if goos == "windows" && ch == '^' {
			cur.WriteByte(ch)
			if i+1 < len(cmd) {
				cur.WriteByte(cmd[i+1])
				i += 2
			} else {
				i++
			}
			continue
		}

		if goos != "windows" && ch == '\\' && !inSingle {
			cur.WriteByte(ch)
			escaped = true
			i++
			continue
		}

		if goos != "windows" && ch == '\'' && !inDouble {
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

		// A single ampersand is a command separator in POSIX shells and cmd.exe.
		// Descriptor redirects such as 2>&1 and <&0 are not separators. POSIX
		// combined redirects (&> and &>>) stay intact; cmd.exe treats their
		// ampersand as a separator.
		if ch == '&' && !isAmpersandRedirect(cmd, i, goos) {
			s := strings.TrimSpace(cur.String())
			if s != "" {
				segments = append(segments, s)
			}
			cur.Reset()
			i++
			continue
		}

		// Check for ; and |
		// Pipe splits for independent evaluation of each command in the pipeline.
		if ch == '|' {
			s := strings.TrimSpace(cur.String())
			if s != "" {
				segments = append(segments, s)
			}
			cur.Reset()
			i++
			continue
		}

		// Newline as command separator (unquoted).
		if ch == '\n' {
			s := strings.TrimSpace(cur.String())
			if s != "" {
				segments = append(segments, s)
			}
			cur.Reset()
			i++
			continue
		}

		if ch == ';' {
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

func isAmpersandRedirect(cmd string, i int, goos string) bool {
	if i > 0 && (cmd[i-1] == '>' || cmd[i-1] == '<') {
		return true
	}
	return goos != "windows" && i+1 < len(cmd) && cmd[i+1] == '>'
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
	// Normalization follows the command's shell language rather than the host
	// OS. A Windows runner can receive POSIX commands from Git Bash, WSL, SSH,
	// containers, or an agent harness. Host-based tokenization would preserve
	// POSIX quote/backslash evasions and make policy behavior platform-dependent.
	return normalizeCommandForOS(cmd, "posix")
}

func normalizeCommandForOS(cmd, goos string) string {
	cmd = SanitizeCommand(cmd)
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}

	segments := splitCompoundCommandForOS(cmd, goos)
	if len(segments) == 0 {
		return ""
	}

	normalized := make([]string, 0, len(segments))
	for _, seg := range segments {
		n := normalizeSegmentForOS(seg, goos)
		if n != "" {
			normalized = append(normalized, n)
		}
	}

	return strings.Join(normalized, " && ")
}

func normalizeSegmentForOS(seg, goos string) string {
	seg = strings.TrimSpace(seg)
	if seg == "" {
		return ""
	}

	tokenOS := goos
	switch {
	case looksLikeCmdWrapper(seg):
		tokenOS = "windows"
	case looksLikePOSIXShellWrapper(seg):
		tokenOS = "posix"
	case looksLikePowerShellWrapper(seg):
		tokenOS = "powershell"
	}
	tokens := tokenizeForOS(seg, tokenOS)
	if len(tokens) == 0 {
		return ""
	}
	if tokenOS == "windows" {
		tokens = removeCmdCarets(tokens)
	}

	tokens = unwrapCommandTokensForOS(tokens, tokenOS)
	tokens = stripLeadingRedirections(tokens)
	if len(tokens) == 0 {
		return ""
	}

	return strings.Join(tokens, " ")
}

// unwrapCommandTokens repeatedly strips leading env assignments, transparent
// POSIX executors, and shell -c wrappers until the token stream stops changing.
// This catches nested forms like `env -i bash -c 'FOO=bar exec sh -c whoami'`.
func unwrapCommandTokensForOS(tokens []string, goos string) []string {
	for {
		next := stripLeadingEnvAssignments(tokens)
		if goos == "posix" {
			next = stripPOSIXTransparentExecutorOnce(next)
		}
		next, nextOS := stripShellWrapperOnceForOS(next, goos)
		if strSlicesEqual(next, tokens) {
			return next
		}
		tokens = next
		goos = nextOS
	}
}

// stripPOSIXTransparentExecutorOnce exposes the command executed by common
// shell builtins/utilities. Unknown or query-only options stay untouched so
// normalization cannot turn a non-executing invocation into a granting match.
func stripPOSIXTransparentExecutorOnce(tokens []string) []string {
	if len(tokens) < 2 {
		return tokens
	}
	name := filepath.Base(strings.ReplaceAll(tokens[0], "\\", "/"))
	switch name {
	case "command":
		i := 1
		for i < len(tokens) {
			switch tokens[i] {
			case "--":
				i++
				if i < len(tokens) {
					return tokens[i:]
				}
				return tokens
			case "-p":
				i++
			case "-v", "-V":
				return tokens
			default:
				if strings.HasPrefix(tokens[i], "-") {
					return tokens
				}
				return tokens[i:]
			}
		}
	case "exec":
		i := 1
		for i < len(tokens) {
			token := tokens[i]
			switch token {
			case "--":
				i++
			case "-a":
				if i+1 >= len(tokens) {
					return tokens
				}
				i += 2
			default:
				if isExecFlag(token) {
					i++
					continue
				}
				if strings.HasPrefix(token, "-") {
					return tokens
				}
				return tokens[i:]
			}
			if i < len(tokens) && token == "--" {
				return tokens[i:]
			}
		}
	case "env":
		return stripPOSIXEnvUtility(tokens)
	case "nohup":
		return stripPOSIXNohup(tokens)
	case "nice":
		return stripPOSIXNice(tokens)
	case "timeout":
		return stripPOSIXTimeout(tokens)
	case "setsid":
		return stripPOSIXSetsid(tokens)
	case "stdbuf":
		return stripPOSIXStdbuf(tokens)
	}
	return tokens
}

func isExecFlag(token string) bool {
	if len(token) < 2 || token[0] != '-' || token == "--" {
		return false
	}
	for _, flag := range token[1:] {
		if flag != 'c' && flag != 'l' {
			return false
		}
	}
	return true
}

func stripPOSIXEnvUtility(tokens []string) []string {
	i := 1
	for i < len(tokens) {
		token := tokens[i]
		switch {
		case token == "--":
			i++
			for i < len(tokens) && isEnvAssignment(tokens[i]) {
				i++
			}
			if i < len(tokens) {
				return tokens[i:]
			}
			return tokens
		case token == "-i" || token == "--ignore-environment" ||
			token == "-0" || token == "--null" || token == "-v" || token == "--debug":
			i++
		case token == "-u" || token == "--unset" || token == "-C" ||
			token == "--chdir" || token == "--argv0":
			if i+1 >= len(tokens) {
				return tokens
			}
			i += 2
		case strings.HasPrefix(token, "--unset=") ||
			strings.HasPrefix(token, "--chdir=") ||
			strings.HasPrefix(token, "--argv0="):
			i++
		case strings.HasPrefix(token, "-u") && len(token) > 2 &&
			!strings.ContainsRune(strings.TrimPrefix(token, "-u"), '='):
			// BSD env accepts the option argument without intervening
			// whitespace (for example, -uRAMPART_MODE).
			i++
		case strings.HasPrefix(token, "-C") && len(token) > 2:
			// Likewise, -C/tmp is the attached form of -C /tmp.
			i++
		case token == "-S" || token == "--split-string":
			if i+1 >= len(tokens) {
				return tokens
			}
			expanded := tokenizeForOS(tokens[i+1], "posix")
			if len(expanded) == 0 {
				return tokens
			}
			rewritten := append([]string{tokens[0]}, tokens[1:i]...)
			rewritten = append(rewritten, expanded...)
			rewritten = append(rewritten, tokens[i+2:]...)
			return rewritten
		case strings.HasPrefix(token, "--split-string="):
			expanded := tokenizeForOS(strings.TrimPrefix(token, "--split-string="), "posix")
			if len(expanded) == 0 {
				return tokens
			}
			rewritten := append([]string{tokens[0]}, tokens[1:i]...)
			rewritten = append(rewritten, expanded...)
			rewritten = append(rewritten, tokens[i+1:]...)
			return rewritten
		case strings.HasPrefix(token, "-S") && len(token) > 2:
			expanded := tokenizeForOS(strings.TrimPrefix(token, "-S"), "posix")
			if len(expanded) == 0 {
				return tokens
			}
			rewritten := append([]string{tokens[0]}, tokens[1:i]...)
			rewritten = append(rewritten, expanded...)
			rewritten = append(rewritten, tokens[i+1:]...)
			return rewritten
		case isEnvAssignment(token):
			i++
		default:
			if strings.HasPrefix(token, "-") {
				return tokens
			}
			return tokens[i:]
		}
	}
	return tokens
}

func stripPOSIXNohup(tokens []string) []string {
	i := 1
	if tokens[i] == "--help" || tokens[i] == "--version" {
		return tokens
	}
	if tokens[i] == "--" {
		i++
		if i < len(tokens) {
			return tokens[i:]
		}
		return tokens
	}
	if i >= len(tokens) || strings.HasPrefix(tokens[i], "-") {
		return tokens
	}
	return tokens[i:]
}

func stripPOSIXNice(tokens []string) []string {
	i := 1
	for i < len(tokens) {
		token := tokens[i]
		switch {
		case token == "--":
			i++
			if i < len(tokens) {
				return tokens[i:]
			}
			return tokens
		case token == "--help" || token == "--version":
			return tokens
		case token == "-n" || token == "--adjustment":
			if i+1 >= len(tokens) || !isSignedDecimal(tokens[i+1]) {
				return tokens
			}
			i += 2
		case strings.HasPrefix(token, "--adjustment="):
			if !isSignedDecimal(strings.TrimPrefix(token, "--adjustment=")) {
				return tokens
			}
			i++
		case strings.HasPrefix(token, "-n") && len(token) > 2:
			adjustment := strings.TrimPrefix(token, "-n")
			adjustment = strings.TrimPrefix(adjustment, "=")
			if !isSignedDecimal(adjustment) {
				return tokens
			}
			i++
		case len(token) > 1 && token[0] == '-' && isSignedDecimal(token):
			// Historical nice syntax accepts -N as an adjustment.
			i++
		case strings.HasPrefix(token, "-"):
			return tokens
		default:
			return tokens[i:]
		}
	}
	return tokens
}

func stripPOSIXTimeout(tokens []string) []string {
	i := 1
	for i < len(tokens) {
		token := tokens[i]
		switch {
		case token == "--":
			i++
			goto duration
		case token == "--help" || token == "--version":
			return tokens
		case token == "--preserve-status" || token == "--foreground" ||
			token == "--verbose" || token == "-v":
			i++
		case token == "-k" || token == "--kill-after":
			if i+1 >= len(tokens) || !isTimeoutDuration(tokens[i+1]) {
				return tokens
			}
			i += 2
		case strings.HasPrefix(token, "--kill-after="):
			if !isTimeoutDuration(strings.TrimPrefix(token, "--kill-after=")) {
				return tokens
			}
			i++
		case strings.HasPrefix(token, "-k") && len(token) > 2:
			if !isTimeoutDuration(strings.TrimPrefix(token, "-k")) {
				return tokens
			}
			i++
		case token == "-s" || token == "--signal":
			if i+1 >= len(tokens) || !isSignalName(tokens[i+1]) {
				return tokens
			}
			i += 2
		case strings.HasPrefix(token, "--signal="):
			if !isSignalName(strings.TrimPrefix(token, "--signal=")) {
				return tokens
			}
			i++
		case strings.HasPrefix(token, "-s") && len(token) > 2:
			if !isSignalName(strings.TrimPrefix(token, "-s")) {
				return tokens
			}
			i++
		case strings.HasPrefix(token, "-"):
			return tokens
		default:
			goto duration
		}
	}

duration:
	if i+1 >= len(tokens) || !isTimeoutDuration(tokens[i]) {
		return tokens
	}
	return tokens[i+1:]
}

func stripPOSIXSetsid(tokens []string) []string {
	i := 1
	for i < len(tokens) {
		token := tokens[i]
		switch {
		case token == "--":
			i++
			if i < len(tokens) {
				return tokens[i:]
			}
			return tokens
		case token == "--help" || token == "--version":
			return tokens
		case token == "--ctty" || token == "--fork" || token == "--wait" ||
			isSetsidShortOptions(token):
			i++
		case strings.HasPrefix(token, "-"):
			return tokens
		default:
			return tokens[i:]
		}
	}
	return tokens
}

func stripPOSIXStdbuf(tokens []string) []string {
	i := 1
	for i < len(tokens) {
		token := tokens[i]
		switch {
		case token == "--":
			i++
			if i < len(tokens) {
				return tokens[i:]
			}
			return tokens
		case token == "--help" || token == "--version":
			return tokens
		case token == "-i" || token == "-o" || token == "-e" ||
			token == "--input" || token == "--output" || token == "--error":
			if i+1 >= len(tokens) || !isStdbufMode(tokens[i+1]) {
				return tokens
			}
			i += 2
		case hasStdbufLongMode(token):
			i++
		case len(token) > 2 && token[0] == '-' &&
			(token[1] == 'i' || token[1] == 'o' || token[1] == 'e'):
			mode := strings.TrimPrefix(token[2:], "=")
			if !isStdbufMode(mode) {
				return tokens
			}
			i++
		case strings.HasPrefix(token, "-"):
			return tokens
		default:
			return tokens[i:]
		}
	}
	return tokens
}

func isSignedDecimal(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	if value == "" {
		return false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func isTimeoutDuration(value string) bool {
	return value == "inf" || value == "infinity" || timeoutDurationRE.MatchString(value)
}

func isSignalName(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') {
			return false
		}
	}
	return true
}

func isSetsidShortOptions(token string) bool {
	if len(token) < 2 || token[0] != '-' || strings.HasPrefix(token, "--") {
		return false
	}
	for _, option := range token[1:] {
		if option != 'c' && option != 'f' && option != 'w' {
			return false
		}
	}
	return true
}

func isStdbufMode(value string) bool {
	return stdbufModeRE.MatchString(value)
}

func hasStdbufLongMode(token string) bool {
	for _, prefix := range []string{"--input=", "--output=", "--error="} {
		if strings.HasPrefix(token, prefix) {
			return isStdbufMode(strings.TrimPrefix(token, prefix))
		}
	}
	return false
}

// shellBasenames lists shell binary names that commonly wrap commands via -c.
var shellBasenames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true,
}

var (
	cmdBasenames = map[string]bool{
		"cmd": true, "cmd.exe": true,
	}
	powerShellBasenames = map[string]bool{
		"powershell": true, "powershell.exe": true, "pwsh": true, "pwsh.exe": true,
	}
)

func looksLikeCmdWrapper(command string) bool {
	return looksLikeShellWrapper(command, cmdBasenames)
}

func looksLikePOSIXShellWrapper(command string) bool {
	return looksLikeShellWrapper(command, shellBasenames)
}

func looksLikePowerShellWrapper(command string) bool {
	return looksLikeShellWrapper(command, powerShellBasenames)
}

func looksLikeShellWrapper(command string, basenames map[string]bool) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}
	end := strings.IndexFunc(command, unicode.IsSpace)
	if end < 0 {
		end = len(command)
	}
	head := strings.Trim(command[:end], `"'`)
	return basenames[shellWrapperBasename(head)]
}

// isShellBinary checks if a token is a known shell binary, matching by basename
// to handle arbitrary paths (/bin/bash, /usr/local/bin/bash, etc.).
func isShellBinary(token string) bool {
	if shellBasenames[token] {
		return true
	}
	return shellBasenames[filepath.Base(token)]
}

func shellWrapperBasename(token string) string {
	return strings.ToLower(filepath.Base(strings.ReplaceAll(token, "\\", "/")))
}

// hasCFlag checks if a flag token contains -c, either standalone or combined
// (e.g. -lc, -ic). Returns true for any single-dash flag containing 'c'.
func hasCFlag(token string) bool {
	if !strings.HasPrefix(token, "-") || strings.HasPrefix(token, "--") {
		return false
	}
	// Single-dash flag: -c, -lc, -ic, etc.
	return strings.ContainsRune(token[1:], 'c')
}

func stripLeadingEnvAssignments(tokens []string) []string {
	start := 0
	for start < len(tokens) {
		if isEnvAssignment(tokens[start]) {
			start++
			continue
		}
		break
	}
	return tokens[start:]
}

func strSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stripShellWrapperOnceForOS(tokens []string, goos string) ([]string, string) {
	if len(tokens) < 2 {
		return tokens, goos
	}

	basename := shellWrapperBasename(tokens[0])
	switch {
	case isShellBinary(tokens[0]):
		// Scan for -c flag (or combined flag containing c) in positions 1+.
		// Skip other flags like --norc, -l, etc.
		for i := 1; i < len(tokens); i++ {
			tok := tokens[i]
			if !strings.HasPrefix(tok, "-") {
				// Reached a non-flag token without finding -c — not a wrapper.
				return tokens, goos
			}
			if hasCFlag(tok) {
				return unwrapInnerTokensForOS(tokens, i+1, "posix"), "posix"
			}
		}
	case cmdBasenames[basename]:
		// cmd.exe options are case-insensitive. /c executes and exits; /k
		// executes and remains open. Both wrap the remaining command string.
		for i := 1; i < len(tokens); i++ {
			tok := strings.ToLower(tokens[i])
			if tok == "/c" || tok == "/k" {
				return removeCmdCarets(unwrapInnerTokensForOS(tokens, i+1, "windows")), "windows"
			}
			if (strings.HasPrefix(tok, "/c") || strings.HasPrefix(tok, "/k")) && len(tok) > 2 {
				attached := tokens[i][2:]
				inner := append([]string{attached}, tokens[i+1:]...)
				if len(inner) == 1 {
					inner = unwrapInnerTokensForOS(inner, 0, "windows")
				}
				return removeCmdCarets(inner), "windows"
			}
			if !strings.HasPrefix(tok, "/") {
				return tokens, goos
			}
		}
	case powerShellBasenames[basename]:
		// PowerShell parameter names are case-insensitive. -Command and its
		// -c alias wrap the remaining command string.
		for i := 1; i < len(tokens); i++ {
			tok := strings.ToLower(tokens[i])
			if tok == "-command" || tok == "-c" {
				return unwrapInnerTokensForOS(tokens, i+1, "powershell"), "powershell"
			}
			if !strings.HasPrefix(tok, "-") {
				return tokens, goos
			}
		}
	}
	return tokens, goos
}

// removeCmdCarets removes cmd.exe's escape marker. It is intentionally
// conservative: a caret-obfuscated executable such as d^el must be evaluated
// as the command cmd.exe will run. Removing every caret is idempotent, which
// keeps nested wrapper normalization safe.
func removeCmdCarets(tokens []string) []string {
	for i := range tokens {
		tokens[i] = strings.ReplaceAll(tokens[i], "^", "")
	}
	return tokens
}

// stripLeadingRedirections removes redirect prefixes that may legally precede
// a command (for example cmd.exe's `>nul del file`). Leaving the prefix in
// place would hide the executable from command_matches rules.
func stripLeadingRedirections(tokens []string) []string {
	for len(tokens) > 0 {
		token := tokens[0]
		if token == ">" || token == ">>" || token == "<" || token == "<<" {
			if len(tokens) < 2 {
				return nil
			}
			tokens = tokens[2:]
			continue
		}
		if isAttachedRedirection(token) {
			tokens = tokens[1:]
			continue
		}
		return tokens
	}
	return tokens
}

func isAttachedRedirection(token string) bool {
	i := 0
	for i < len(token) && token[i] >= '0' && token[i] <= '9' {
		i++
	}
	if i >= len(token) || (token[i] != '>' && token[i] != '<') {
		return false
	}
	i++
	if i < len(token) && token[i] == token[i-1] {
		i++
	}
	return i < len(token)
}

func unwrapInnerTokensForOS(tokens []string, start int, goos string) []string {
	if start >= len(tokens) {
		return tokens
	}
	inner := tokens[start:]
	// If the wrapper got a single quoted command string, re-tokenize it so
	// nested wrappers and compound operators remain visible to matching.
	if len(inner) == 1 {
		if retokenized := tokenizeForOS(inner[0], goos); len(retokenized) > 0 {
			return retokenized
		}
	}
	return inner
}

func tokenizeForOS(cmd, goos string) []string {
	switch goos {
	case "windows":
		return tokenizeWindows(cmd)
	case "powershell":
		return tokenizePowerShell(cmd)
	default:
		return tokenize(cmd)
	}
}

// tokenizePowerShell handles the quoting rules needed to expose a wrapped
// -Command payload. Unlike POSIX shells, backslashes are ordinary path
// characters and the backtick is the escape marker. Both quote styles group
// whitespace.
func tokenizePowerShell(cmd string) []string {
	var tokens []string
	var cur strings.Builder
	var quote byte
	tokenStarted := false

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if quote == '\'' {
			if ch == '\'' {
				if i+1 < len(cmd) && cmd[i+1] == '\'' {
					cur.WriteByte('\'')
					i++
					continue
				}
				quote = 0
				continue
			}
			cur.WriteByte(ch)
			continue
		}
		if ch == '`' && i+1 < len(cmd) {
			i++
			cur.WriteByte(cmd[i])
			tokenStarted = true
			continue
		}
		if quote == '"' {
			if ch == '"' {
				quote = 0
				continue
			}
			cur.WriteByte(ch)
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			tokenStarted = true
			continue
		}
		if ch == ' ' || ch == '\t' {
			if tokenStarted {
				tokens = append(tokens, cur.String())
				cur.Reset()
				tokenStarted = false
			}
			continue
		}
		cur.WriteByte(ch)
		tokenStarted = true
	}
	if tokenStarted {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// tokenizeWindows handles the cmd.exe lexical rules relevant to policy
// matching. Backslashes and single quotes are ordinary characters; double
// quotes group whitespace; and caret escapes the following character outside
// double quotes.
func tokenizeWindows(cmd string) []string {
	var tokens []string
	var cur strings.Builder
	inDouble := false
	tokenStarted := false

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if ch == '^' && !inDouble && i+1 < len(cmd) {
			i++
			cur.WriteByte(cmd[i])
			tokenStarted = true
			continue
		}
		if ch == '"' {
			inDouble = !inDouble
			tokenStarted = true
			continue
		}
		if (ch == ' ' || ch == '\t') && !inDouble {
			if tokenStarted {
				tokens = append(tokens, cur.String())
				cur.Reset()
				tokenStarted = false
			}
			continue
		}
		cur.WriteByte(ch)
		tokenStarted = true
	}
	if tokenStarted {
		tokens = append(tokens, cur.String())
	}
	return tokens
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
					if cmd[i+1] == '\n' {
						i += 2
						continue
					}
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
			if cmd[i+1] == '\n' {
				i += 2
				continue
			}
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
