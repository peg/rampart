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
