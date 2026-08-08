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
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
)

func TestShippedPolicyFilesPassStrictValidation(t *testing.T) {
	patterns := []string{
		filepath.Join("..", "..", "policies", "*.yaml"),
		filepath.Join("..", "..", "policies", "community", "*.yaml"),
		filepath.Join("..", "..", "policies", "examples", "*.yaml"),
		filepath.Join("..", "..", "configs", "examples", "*.yaml"),
	}
	var files []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %q: %v", pattern, err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		t.Fatal("no shipped policy files found")
	}

	for _, path := range files {
		path := path
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			t.Parallel()
			if _, err := NewFileStore(path).Load(); err != nil {
				t.Fatalf("strict validation failed: %v", err)
			}
		})
	}
}

func TestStandardAndOpenClawProfilesHaveUniquePolicyNames(t *testing.T) {
	standard, err := NewFileStore(filepath.Join("..", "..", "policies", "standard.yaml")).Load()
	if err != nil {
		t.Fatalf("load standard policy: %v", err)
	}
	openclaw, err := NewFileStore(filepath.Join("..", "..", "policies", "openclaw.yaml")).Load()
	if err != nil {
		t.Fatalf("load OpenClaw policy: %v", err)
	}

	standardNames := make(map[string]struct{}, len(standard.Policies))
	for _, policy := range standard.Policies {
		standardNames[policy.Name] = struct{}{}
	}
	for _, policy := range openclaw.Policies {
		if _, duplicate := standardNames[policy.Name]; duplicate {
			t.Fatalf("standard.yaml and openclaw.yaml both define policy %q", policy.Name)
		}
	}
}

func TestStandardPolicyBlocksMixedCaseDestructiveCommandOnCaseInsensitiveHosts(t *testing.T) {
	if !platformUsesCaseInsensitiveNames(runtime.GOOS) {
		t.Skip("case-insensitive host behavior is covered on macOS and Windows CI")
	}

	path := filepath.Join("..", "..", "policies", "standard.yaml")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := New(NewFileStore(path), logger)
	if err != nil {
		t.Fatalf("load standard policy: %v", err)
	}

	decision := eng.Evaluate(ToolCall{
		Agent:  "claude-code",
		Tool:   "exec",
		Params: map[string]any{"command": "RM -RF /"},
	})
	if decision.Action != ActionDeny {
		t.Fatalf("mixed-case destructive command = %s, want deny", decision.Action)
	}
}

func TestStandardPolicyBlocksDestructiveCommandsBehindTransparentPOSIXLaunchers(t *testing.T) {
	path := filepath.Join("..", "..", "policies", "standard.yaml")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := New(NewFileStore(path), logger)
	if err != nil {
		t.Fatalf("load standard policy: %v", err)
	}

	commands := []string{
		"nohup rm -rf /",
		"nice --adjustment=5 rm -rf /",
		"timeout --foreground --kill-after=1s 5s rm -rf /",
		"setsid --fork --wait rm -rf /",
		"stdbuf --output=L rm -rf /",
		"env -uRAMPART_TOKEN -C/tmp nohup timeout -k1s 5s nice -n5 setsid -fw stdbuf -oL rm -rf /",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			decision := eng.Evaluate(ToolCall{
				Agent:  "claude-code",
				Tool:   "exec",
				Params: map[string]any{"command": command},
			})
			if decision.Action != ActionDeny {
				t.Fatalf("transparent launcher command %q = %s, want deny", command, decision.Action)
			}
		})
	}
}

func TestStandardPolicyGatesUnknownAndDangerousMCPTools(t *testing.T) {
	path := filepath.Join("..", "..", "policies", "standard.yaml")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := New(NewFileStore(path), logger)
	if err != nil {
		t.Fatalf("load standard policy: %v", err)
	}

	for _, tool := range []string{"mcp", "mcp-dangerous"} {
		decision := eng.Evaluate(ToolCall{Agent: "mcp-client", Tool: tool})
		if decision.Action != ActionAsk {
			t.Fatalf("standard %s decision = %s, want ask", tool, decision.Action)
		}
	}
	if decision := eng.Evaluate(ToolCall{Agent: "mcp-client", Tool: "mcp-destructive"}); decision.Action != ActionDeny {
		t.Fatalf("standard mcp-destructive decision = %s, want deny", decision.Action)
	}
}

func TestCIPolicyBlocksUnknownAndDangerousMCPTools(t *testing.T) {
	path := filepath.Join("..", "..", "policies", "ci.yaml")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := New(NewFileStore(path), logger)
	if err != nil {
		t.Fatalf("load CI policy: %v", err)
	}

	for _, tool := range []string{"mcp", "mcp-dangerous", "mcp-destructive"} {
		decision := eng.Evaluate(ToolCall{Agent: "ci", Tool: tool})
		if decision.Action != ActionDeny {
			t.Fatalf("CI %s decision = %s, want deny", tool, decision.Action)
		}
	}
}
