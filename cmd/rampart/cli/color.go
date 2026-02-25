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

package cli

import (
	"fmt"
	"os"
	"strings"
)

const (
	colorDim    = "\033[2m"
	colorYellow = "\033[1;33m"
)

// noColor returns true when the NO_COLOR environment variable is set.
func noColor() bool {
	_, ok := os.LookupEnv("NO_COLOR")
	return ok
}

// stderrSupportsColor returns true when stderr supports ANSI colors.
// Respects the NO_COLOR convention (https://no-color.org/).
func stderrSupportsColor() bool {
	if noColor() {
		return false
	}
	return isTerminal(os.Stderr)
}

// formatDenyMessage returns a branded deny message suitable for stderr.
// The suggestions slice contains ready-to-run "rampart allow ..." commands.
func formatDenyMessage(command, reason string, suggestions []string) string {
	var sb strings.Builder
	if stderrSupportsColor() {
		sb.WriteString(fmt.Sprintf("🛡️ %sRampart blocked: %s%s\n   %sReason: %s%s\n",
			colorRed, command, colorReset,
			colorDim, reason, colorReset,
		))
		if len(suggestions) > 0 {
			sb.WriteString(fmt.Sprintf("   %sTo allow:%s\n", colorDim, colorReset))
			for _, s := range suggestions {
				sb.WriteString(fmt.Sprintf("     %s$ %s%s\n", colorDim, s, colorReset))
			}
		}
	} else {
		sb.WriteString(fmt.Sprintf("🛡️ Rampart blocked: %s\n   Reason: %s\n", command, reason))
		if len(suggestions) > 0 {
			sb.WriteString("   To allow:\n")
			for _, s := range suggestions {
				sb.WriteString(fmt.Sprintf("     $ %s\n", s))
			}
		}
	}
	return sb.String()
}

// formatApprovalRequiredMessage returns a branded approval-required message for stderr.
func formatApprovalRequiredMessage(command, reason string) string {
	if stderrSupportsColor() {
		return fmt.Sprintf("🛡️ %sRampart: approval required for: %s%s\n   %s%s%s\n",
			colorYellow, command, colorReset,
			colorDim, reason, colorReset,
		)
	}
	return fmt.Sprintf("🛡️ Rampart: approval required for: %s\n   %s\n", command, reason)
}
