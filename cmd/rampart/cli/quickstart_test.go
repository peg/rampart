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
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestQuickstartIsHiddenStubThatExitsNonZero(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := NewRootCmd(context.Background(), &out, &errOut)

	if found, _, err := cmd.Find([]string{"quickstart"}); err != nil || !found.Hidden {
		t.Fatalf("quickstart must stay registered but hidden: found=%v err=%v", found, err)
	}

	// Flags from the removed command must reach the message, not a flag error.
	cmd.SetArgs([]string{"quickstart", "--yes", "--agents", "none", "--profile=standard", "--unknown"})
	err := cmd.Execute()
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("quickstart error = %v (exit %d), want exit 1", err, ExitCode(err))
	}
	if got := errOut.String(); got != quickstartRemovedMessage+"\n" || !strings.Contains(got, "`rampart protect <agent>`") {
		t.Fatalf("stderr = %q, want the removal message on one line", got)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
}
