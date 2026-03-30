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

package policy

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// BuildAllowPattern converts a literal command string into a smart glob pattern
// suitable for command_matches. It strips output redirection/pipes and replaces
// trailing arguments with wildcards so that similar commands (e.g. different
// package names) are covered by a single rule.
func BuildAllowPattern(cmd string) string {
	// Step 1: Strip output redirection and pipes.
	// Remove everything after the first |, 2>&1, >, >>, or 2>.
	clean := cmd
	for _, sep := range []string{" 2>&1", " |", " >>", " 2>", " >"} {
		if idx := strings.Index(clean, sep); idx != -1 {
			clean = clean[:idx]
		}
	}
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return cmd
	}

	// Step 2: Tokenize.
	tokens := strings.Fields(clean)
	if shouldKeepExact(clean, tokens) {
		return clean
	}

	// Step 3: For 3+ tokens, replace trailing argument(s) with *.
	if len(tokens) >= 3 {
		// Keep all tokens except the last, append *
		return strings.Join(tokens[:len(tokens)-1], " ") + " *"
	}

	// Step 4: For 1-2 tokens, keep as-is.
	// Append * if the last token looks like a filename (contains a dot or slash).
	if len(tokens) > 0 {
		last := tokens[len(tokens)-1]
		if strings.Contains(last, ".") || strings.Contains(last, "/") {
			return strings.Join(tokens, " ") + " *"
		}
	}

	return clean
}

// wrapperPrefixes are tokens that can precede a command without changing its semantics,
// e.g. "sudo docker run" should still match the "docker run" dangerous prefix.
var wrapperPrefixes = map[string]bool{
	"sudo": true, "env": true, "nice": true, "nohup": true,
	"time": true, "strace": true, "ltrace": true,
}

func shouldKeepExact(clean string, tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}

	// Strip leading wrapper prefixes so "sudo docker run" matches "docker run"
	effective := tokens
	for len(effective) > 0 && wrapperPrefixes[effective[0]] {
		effective = effective[1:]
	}

	if hasDangerousPrefix(effective, []string{"docker", "run"}) ||
		hasDangerousPrefix(effective, []string{"docker", "exec"}) ||
		hasDangerousPrefix(effective, []string{"kubectl", "apply"}) ||
		hasDangerousPrefix(effective, []string{"kubectl", "exec"}) ||
		hasDangerousPrefix(effective, []string{"kubectl", "delete"}) ||
		hasDangerousPrefix(effective, []string{"rm"}) ||
		hasDangerousPrefix(effective, []string{"dd"}) ||
		hasDangerousPrefix(effective, []string{"mkfs"}) {
		return true
	}

	if isExternalDownload(effective) {
		return true
	}

	if isSensitiveOwnershipChange(effective) {
		return true
	}

	return false
}

func hasDangerousPrefix(tokens, prefix []string) bool {
	if len(tokens) < len(prefix) {
		return false
	}
	for i := range prefix {
		if tokens[i] != prefix[i] {
			return false
		}
	}
	return true
}

func isExternalDownload(tokens []string) bool {
	if len(tokens) < 2 {
		return false
	}
	if tokens[0] != "curl" && tokens[0] != "wget" {
		return false
	}

	for _, token := range tokens[1:] {
		if !strings.Contains(token, "://") {
			continue
		}
		u, err := url.Parse(token)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
			continue
		}
		return true
	}
	return false
}

func isSensitiveOwnershipChange(tokens []string) bool {
	if len(tokens) < 2 {
		return false
	}
	if tokens[0] != "chmod" && tokens[0] != "chown" {
		return false
	}

	for _, token := range tokens[1:] {
		if strings.HasPrefix(token, "-") {
			continue
		}
		if isSensitivePathToken(token) {
			return true
		}
	}
	return false
}

func isSensitivePathToken(token string) bool {
	cleaned := strings.Trim(token, `"'`)
	if cleaned == "" || !strings.HasPrefix(cleaned, "/") {
		return false
	}

	// Normalize using forward slashes only (filepath.Clean uses backslashes on Windows)
	// path.Clean resolves .., ., and double slashes safely on all platforms.
	normalized := path.Clean(strings.ReplaceAll(cleaned, "\\", "/"))
	sensitiveRoots := []string{
		"/",
		"/boot",
		"/dev",
		"/etc",
		"/root",
		"/sys",
		"/usr",
		"/var",
	}
	for _, root := range sensitiveRoots {
		if normalized == root || strings.HasPrefix(normalized, root+"/") {
			return true
		}
	}
	return false
}

// HashPattern returns a hex string derived from a djb2 hash of the pattern,
// suitable for generating stable rule names like "user-allow-{hash}".
func HashPattern(s string) string {
	var hash uint32 = 5381
	for _, b := range []byte(s) {
		hash = hash*33 + uint32(b)
	}
	return fmt.Sprintf("%08x", hash)
}
