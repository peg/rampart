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
	fmt.Fprintln(w, "  Or ask your AI agent to run a dangerous command and watch Rampart block it.")
	fmt.Fprintln(w, "")
}
