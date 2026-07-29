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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// MaxGlobPatternLen is the largest policy glob Rampart accepts. Keeping the
	// bound here gives every policy-writing path the same limit as enforcement.
	MaxGlobPatternLen = 8192
	// MaxDoubleGlobPatternLen is the tighter limit for patterns containing **,
	// whose matcher keeps state proportional to both pattern and input length.
	MaxDoubleGlobPatternLen = 256
	// MaxDoubleStarOccurrences bounds matcher complexity and ambiguity.
	MaxDoubleStarOccurrences = 2
)

// ValidateGlobPatterns applies the shared enforcement bounds to policy globs.
// Policy loaders and generated-policy writers must use this function so a
// successfully persisted rule is guaranteed to remain loadable by the engine.
func ValidateGlobPatterns(field string, patterns []string) error {
	for _, pattern := range patterns {
		if len(pattern) > MaxGlobPatternLen {
			return fmt.Errorf("%s pattern is %d bytes (max %d)", field, len(pattern), MaxGlobPatternLen)
		}
		count := strings.Count(pattern, "**")
		if count > 0 && len(pattern) > MaxDoubleGlobPatternLen {
			return fmt.Errorf("%s double-star pattern is %d bytes (max %d)", field, len(pattern), MaxDoubleGlobPatternLen)
		}
		if count > MaxDoubleStarOccurrences {
			return fmt.Errorf("%s pattern %q has %d ** occurrences (max %d)", field, pattern, count, MaxDoubleStarOccurrences)
		}
	}
	return nil
}

// BuildExactAllowPattern converts a literal command or path into a glob that
// matches the same value without treating shell wildcard characters as policy
// wildcards. Automatic "Always Allow" flows use this helper so a human approval
// never silently grants authority over related commands or paths.
//
// Explicit policy-authoring commands accept glob syntax directly and therefore
// must not pass user-provided patterns through this function.
func BuildExactAllowPattern(value string) string {
	var pattern strings.Builder
	pattern.Grow(len(value))
	for _, r := range value {
		switch r {
		case '*':
			pattern.WriteString("[*]")
		case '?':
			pattern.WriteString("[?]")
		case '[':
			pattern.WriteString("[[]")
		default:
			pattern.WriteRune(r)
		}
	}
	return pattern.String()
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

// ExactPatternHash returns a deterministic, collision-resistant identifier for
// an exact tool authority. It is intentionally separate from HashPattern:
// HashPattern's historical djb2 output is part of user-override rule identity
// and must remain stable for upgrade compatibility.
func ExactPatternHash(tool, pattern string) string {
	sum := sha256.Sum256([]byte(tool + "\x00" + pattern))
	// Ninety-six bits keeps generated names compact while making accidental
	// collisions unrealistic even across very large policy sets.
	return hex.EncodeToString(sum[:12])
}
