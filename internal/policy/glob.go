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

// HashPattern returns a hex string derived from a djb2 hash of the pattern,
// suitable for generating stable rule names like "user-allow-{hash}".
func HashPattern(s string) string {
	var hash uint32 = 5381
	for _, b := range []byte(s) {
		hash = hash*33 + uint32(b)
	}
	return fmt.Sprintf("%08x", hash)
}
