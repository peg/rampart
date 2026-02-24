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
	"path/filepath"
	"strings"
)

// isExtremelyDangerous returns true if the command is so dangerous that
// we should not suggest allowing it. These are commands that would cause
// severe, likely unrecoverable damage to the system.
func isExtremelyDangerous(cmd string) bool {
	cmdLower := strings.ToLower(cmd)

	// Filesystem destruction targeting root or home
	if strings.Contains(cmdLower, "rm -rf /") && !strings.Contains(cmdLower, "rm -rf /tmp") && !strings.Contains(cmdLower, "rm -rf /var") {
		// "rm -rf /" or "rm -rf /home" etc but not "rm -rf /tmp/foo"
		parts := strings.Fields(cmdLower)
		for i, p := range parts {
			if p == "/" || p == "/*" || p == "~" || p == "~/*" {
				return true
			}
			// Check for "rm -rf /something" where something is a root-level danger
			if i > 0 && (p == "/bin" || p == "/usr" || p == "/etc" || p == "/home" || p == "/root" || p == "/lib" || p == "/sbin") {
				return true
			}
		}
	}

	// Fork bomb
	if strings.Contains(cmd, ":(){ :|:& };:") {
		return true
	}

	// Disk wipe
	if strings.Contains(cmdLower, "> /dev/sd") || strings.Contains(cmdLower, ">/dev/sd") {
		return true
	}

	// Piped execution from URL
	if (strings.Contains(cmdLower, "curl ") || strings.Contains(cmdLower, "wget ")) &&
		(strings.Contains(cmdLower, "| bash") || strings.Contains(cmdLower, "| sh") ||
			strings.Contains(cmdLower, "|bash") || strings.Contains(cmdLower, "|sh")) {
		return true
	}

	return false
}

// dangerousBaseCommands lists command names whose wildcard expansions would be
// unsafe to suggest. We never suggest "rm *", "shred *", "dd *", etc.
var dangerousBaseCommands = []string{
	"rm", "shred", "dd", "wipefs", "mkfs", "fdisk", "parted",
	"truncate", "mv", // mv * could clobber anything
}

// sensitivePaths lists path prefixes where wildcard directory suggestions
// would expose credentials or system files. Only exact-match suggestions are
// generated for these paths.
var sensitivePaths = []string{
	"/etc/",
	"/root/",
	"/proc/",
	"/sys/",
	"/dev/",
	"/.ssh/",
	"/.gnupg/",
	"/.aws/",
	"/.config/",
	"id_rsa", "id_ed25519", "id_ecdsa", // ssh private key filenames
	".pem", ".key", ".p12", ".pfx", // certificate/key extensions
	"shadow", "passwd", // specific sensitive filenames
}

// transparentPrefixes are commands that wrap other commands and should be
// "looked through" when checking for dangerous base commands.
var transparentPrefixes = map[string]bool{
	"sudo": true, "env": true, "time": true, "nice": true, "ionice": true,
	"nohup": true, "timeout": true, "strace": true, "ltrace": true,
}

// isDangerousBaseCommand returns true if cmd (or the command it wraps) matches
// a known-dangerous command where wildcard expansion would be unsafe.
func isDangerousBaseCommand(cmd string) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	// Check if the first token is dangerous
	if isDangerousBase(parts[0]) {
		return true
	}

	// If first token is a transparent wrapper (sudo, env, etc.), check ALL
	// subsequent tokens for dangerous commands. This is a conservative approach
	// that handles cases like "sudo -u root rm file" or "nice -n 10 rm file"
	// where the dangerous command appears after flags and their arguments.
	base := filepath.Base(parts[0])
	if transparentPrefixes[base] {
		for i := 1; i < len(parts); i++ {
			tok := parts[i]
			// Skip flags and env var assignments
			if strings.HasPrefix(tok, "-") || strings.Contains(tok, "=") {
				continue
			}
			// Check every non-flag token
			if isDangerousBase(tok) {
				return true
			}
		}
	}
	return false
}

// isDangerousBase checks if a single token is a dangerous command.
func isDangerousBase(token string) bool {
	base := filepath.Base(token)
	for _, danger := range dangerousBaseCommands {
		if base == danger {
			return true
		}
		// Handle commands with suffixes like mkfs.ext4, mkfs.vfat, etc.
		if strings.HasPrefix(base, danger+".") {
			return true
		}
	}
	return false
}

// isSensitivePath returns true if the path contains a sensitive prefix or
// filename pattern that should not be expanded to a wildcard.
func isSensitivePath(path string) bool {
	lower := strings.ToLower(path)
	for _, sensitive := range sensitivePaths {
		if strings.Contains(lower, sensitive) {
			return true
		}
	}
	return false
}

// generalizeCommand returns a wildcard version of cmd by replacing the last
// meaningful argument with "*". Returns "" if no safe wildcard can be formed.
//
// Examples:
//
//	"npm install typescript" → "npm install *"
//	"git push origin main"   → "git push *"
//	"sudo apt update"        → "sudo apt *"
//	"cat /etc/passwd"        → ""  (sensitive path, no wildcard)
//	"rm -rf /tmp/foo"        → ""  (dangerous base command)
func generalizeCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}

	// Never suggest wildcards for dangerous commands.
	if isDangerousBaseCommand(cmd) {
		return ""
	}

	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		// Single token — nothing meaningful to wildcard.
		return ""
	}

	// Walk backwards to find the last non-flag argument to replace with *.
	// Skip trailing flags (args starting with "-") to produce cleaner patterns.
	lastMeaningful := -1
	for i := len(parts) - 1; i >= 1; i-- {
		if !strings.HasPrefix(parts[i], "-") {
			lastMeaningful = i
			break
		}
	}
	if lastMeaningful < 1 {
		// All args are flags — no safe wildcard target.
		return ""
	}

	// If the last meaningful arg looks like a sensitive path, skip wildcard.
	if isSensitivePath(parts[lastMeaningful]) {
		return ""
	}

	// Build wildcard command by replacing the last meaningful arg with "*".
	wildParts := make([]string, len(parts))
	copy(wildParts, parts)
	wildParts[lastMeaningful] = "*"

	wildCmd := strings.Join(wildParts, " ")

	// Avoid returning the exact same string (edge case where last arg is already "*").
	if wildCmd == cmd {
		return ""
	}

	return wildCmd
}

// generateSuggestions produces human-readable CLI suggestions for how to allow
// a denied tool call.
//
// For exec calls, it suggests:
//   - rampart allow "<exact command>"
//   - rampart allow "<wildcard command>"  (when safe)
//
// For file operations (read/write/edit), it suggests:
//   - rampart allow "<exact path>" --tool <tool>
//   - rampart allow "<wildcard path>" --tool <tool>  (when safe and not write)
func generateSuggestions(call ToolCall) []string {
	var suggestions []string

	cmd := call.Command()
	if cmd != "" && call.Tool == "exec" {
		// Skip suggestions for extremely dangerous commands.
		// These should almost never be allowed, so don't suggest it.
		if isExtremelyDangerous(cmd) {
			return []string{"⚠️  This command matches a high-risk pattern. Allowing it is not recommended."}
		}

		// 1. Exact command.
		suggestions = append(suggestions, fmt.Sprintf("rampart allow %q", cmd))

		// 2. Wildcard variant (if safe).
		if wildcard := generalizeCommand(cmd); wildcard != "" {
			suggestions = append(suggestions, fmt.Sprintf("rampart allow %q", wildcard))
		}
		return suggestions
	}

	path := call.Path()
	if path != "" {
		tool := call.Tool
		if tool == "" {
			tool = "read"
		}

		// 1. Exact path.
		suggestions = append(suggestions, fmt.Sprintf("rampart allow %q --tool %s", path, tool))

		// 2. Wildcard: replace the filename with * to allow all files in the
		//    same directory — but only for read operations on non-sensitive paths.
		if tool != "write" && !isSensitivePath(path) {
			dir := filepath.Dir(path)
			if dir != "" && dir != "." {
				wildcardPath := filepath.Join(dir, "*")
				suggestions = append(suggestions, fmt.Sprintf("rampart allow %q --tool %s", wildcardPath, tool))
			}
		}
		return suggestions
	}

	return suggestions
}
