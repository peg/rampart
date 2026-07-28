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
	"errors"
	"testing"
	"time"
)

type failingCallCounter struct{}

func (failingCallCounter) Increment(string, time.Time) error          { return errors.New("state unavailable") }
func (failingCallCounter) Count(string, time.Duration, time.Time) int { return 0 }
func (failingCallCounter) Snapshot(time.Duration, time.Time) map[string]int {
	return map[string]int{}
}

func TestEnforceRecordsCallCountButEvaluateDoesNot(t *testing.T) {
	eng := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: fetch-limit
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          call_count:
            gte: 2
            window: 1h
`)
	call := ToolCall{Agent: "test", Tool: "fetch"}

	if got := eng.Evaluate(call).Action; got != ActionAllow {
		t.Fatalf("preview action = %s, want allow", got)
	}
	if got := eng.Evaluate(call).Action; got != ActionAllow {
		t.Fatalf("second preview action = %s, want allow", got)
	}
	if got := eng.Enforce(call, EvalOptions{}).Action; got != ActionAllow {
		t.Fatalf("first enforced action = %s, want allow", got)
	}
	if got := eng.Enforce(call, EvalOptions{}).Action; got != ActionDeny {
		t.Fatalf("second enforced action = %s, want deny", got)
	}
}

func TestEnforceFailsClosedWhenCounterStateFails(t *testing.T) {
	eng := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: fetch-limit
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          call_count:
            gte: 2
            window: 1h
`)
	eng.SetCallCounter(failingCallCounter{})

	decision := eng.Enforce(ToolCall{Agent: "test", Tool: "fetch"}, EvalOptions{})
	if decision.Action != ActionDeny {
		t.Fatalf("action = %s, want deny", decision.Action)
	}
}

func TestEnforceRecordsTelemetryWithoutCallCountPolicy(t *testing.T) {
	eng := setupEngine(t, `
version: "1"
default_action: allow
policies: []
`)

	if got := eng.Enforce(ToolCall{Agent: "test", Tool: "exec"}, EvalOptions{}).Action; got != ActionAllow {
		t.Fatalf("enforced action = %s, want allow", got)
	}
	if got := eng.CallCounts(time.Hour)["exec"]; got != 1 {
		t.Fatalf("exec call count = %d, want 1", got)
	}
}

func TestEnforceTelemetryFailureCannotDenyUnrelatedCall(t *testing.T) {
	eng := setupEngine(t, `
version: "1"
default_action: allow
policies: []
`)
	eng.telemetryCalls = failingCallCounter{}

	decision := eng.Enforce(ToolCall{Agent: "test", Tool: "future-tool"}, EvalOptions{})
	if decision.Action != ActionAllow {
		t.Fatalf("action = %s, want allow despite telemetry failure", decision.Action)
	}
}
