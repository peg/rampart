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
	"io"
)

// printFirstRunTest prints a guided first-run test after setup or init.
// This gives the user an immediate "aha" moment by showing them how to
// verify Rampart is working.
func printFirstRunTest(w io.Writer) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "🧪 Try it — verify your protection:")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  rampart test \"rm -rf /\"           # should be denied")
	fmt.Fprintln(w, "  rampart test \"git status\"          # should be allowed")
	fmt.Fprintln(w, "  rampart test --tool read ~/.ssh/id_rsa  # should be denied")
	fmt.Fprintln(w, "")
}

// printNextStep prints a "→ Next:" breadcrumb hint.
func printNextStep(w io.Writer, step string) {
	fmt.Fprintf(w, "\n→ Next: %s\n", step)
}

// printStatusHints prints contextual hints based on the current state.
// Called after the status box to guide the user to the next action.
func printStatusHints(w io.Writer, serverRunning bool, protected []string, allow, deny, pending int) {
	total := allow + deny + pending

	switch {
	case !serverRunning && len(protected) == 0:
		// Nothing set up yet
		fmt.Fprintln(w, "\n→ Get started: rampart init && rampart setup claude-code && rampart serve")

	case !serverRunning:
		// Agent configured but serve not running
		fmt.Fprintln(w, "\n→ Next: rampart serve")

	case len(protected) == 0:
		// Serve running but no agents connected
		fmt.Fprintln(w, "\n→ Next: rampart setup claude-code")

	case total == 0:
		// Everything set up, no events yet
		fmt.Fprintln(w, "\n→ Use your agent normally. Events will appear here.")

	case deny > 0:
		fmt.Fprintf(w, "\n→ Review blocked commands: rampart log --deny\n")

	case pending > 0:
		fmt.Fprintf(w, "\n→ Pending approvals: rampart watch\n")

	default:
		// Everything is working, show live view option
		fmt.Fprintln(w, "\n→ Live view: rampart watch")
	}
}
