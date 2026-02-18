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

package intercept

import (
	"testing"

	"github.com/peg/rampart/internal/engine"
)

func setupExecInterceptor(t *testing.T, policy string) *ExecInterceptor {
	t.Helper()
	return NewExecInterceptor(setupEngine(t, policy))
}

func TestExecInterceptor_Evaluate(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		command string
		want    engine.Action
	}{
		{
			name: "rm -rf against deny rule is blocked",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-rm
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
        message: "blocked"
`,
			command: "rm -rf /",
			want:    engine.ActionDeny,
		},
		{
			name: "git push against allow rule passes through",
			policy: `
version: "1"
default_action: deny
policies:
  - name: allow-git
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
`,
			command: "git push origin main",
			want:    engine.ActionAllow,
		},
		{
			name: "no matching rule + default allow passes through",
			policy: `
version: "1"
default_action: allow
policies: []
`,
			command: "echo hi",
			want:    engine.ActionAllow,
		},
		{
			name: "no matching rule + default deny is blocked",
			policy: `
version: "1"
default_action: deny
policies: []
`,
			command: "echo hi",
			want:    engine.ActionDeny,
		},
		{
			name: "command matching: git * matches git push origin main",
			policy: `
version: "1"
default_action: deny
policies:
  - name: allow-git
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
`,
			command: "git push origin main",
			want:    engine.ActionAllow,
		},
		{
			name: "command matching: rm -rf * does NOT match rm file.txt",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-rm-rf
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
`,
			command: "rm file.txt",
			want:    engine.ActionAllow,
		},
		{
			name: "log action: tool call succeeds, decision is ActionWatch",
			policy: `
version: "1"
default_action: deny
policies:
  - name: log-git
    match:
      tool: exec
    rules:
      - action: log
        when:
          command_matches: ["git *"]
`,
			command: "git push origin main",
			want:    engine.ActionWatch,
		},
		{
			name: "command normalization: leading/trailing whitespace trimmed",
			policy: `
version: "1"
default_action: deny
policies:
  - name: allow-exact
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git push"]
`,
			command: "   git push   ",
			want:    engine.ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := setupExecInterceptor(t, tt.policy)
			got := interceptor.Evaluate("main", "s1", tt.command)
			if got.Action != tt.want {
				t.Fatalf("want %s, got %s", tt.want, got.Action)
			}
		})
	}
}

func TestExecInterceptor_BinaryExtraction(t *testing.T) {
	interceptor := &ExecInterceptor{}
	call := interceptor.toolCall("main", "s1", "git push")

	got, ok := call.Params["binary"].(string)
	if !ok {
		t.Fatalf("binary param missing or wrong type")
	}
	if got != "git" {
		t.Fatalf("want binary git, got %q", got)
	}
}
