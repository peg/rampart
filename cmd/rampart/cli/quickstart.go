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

	"github.com/spf13/cobra"
)

const quickstartRemovedMessage = "rampart quickstart was removed in 1.10.0; run `rampart protect <agent>` (for example `rampart protect claude-code`)"

// newQuickstartCmd returns a hidden tombstone for the removed onboarding
// command. It accepts and ignores every argument and flag so existing scripts
// receive the migration message instead of a flag-parsing error, and it always
// exits non-zero so a script cannot mistake the missing setup for success.
func newQuickstartCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "quickstart",
		Hidden:             true,
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), quickstartRemovedMessage)
			return exitCodeError{code: 1}
		},
	}
}
