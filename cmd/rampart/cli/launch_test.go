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
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func fakeLookPath(found ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		for _, f := range found {
			if f == name {
				return "/usr/bin/" + name, nil
			}
		}
		return "", os.ErrNotExist
	}
}

type launchRecorder struct {
	protectErr error
	protected  string
	ran        bool
	bin        string
	args       []string
}

func (r *launchRecorder) deps(onPath ...string) launchDeps {
	return launchDeps{
		lookPath: fakeLookPath(onPath...),
		protect: func(_ *cobra.Command, _ *rootOptions, d integrationDriver, _ string, _ time.Duration) error {
			r.protected = d.ID
			return r.protectErr
		},
		run: func(_ *cobra.Command, bin string, args []string) error {
			r.ran, r.bin, r.args = true, bin, args
			return nil
		},
	}
}

func runLaunch(t *testing.T, deps launchDeps, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := newLaunchCmdWith(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String() + errOut.String(), err
}

func TestLaunchArgumentMapping(t *testing.T) {
	tests := []struct {
		name     string
		onPath   []string
		args     []string
		wantBin  string
		wantArgs []string
		wantErr  string
	}{
		{"claude via ollama", []string{"ollama"}, []string{"claude"}, "ollama", []string{"launch", "claude"}, ""},
		{"claude-code id with model", []string{"ollama"}, []string{"claude-code", "--model", "qwen3-coder"}, "ollama", []string{"launch", "claude", "--model", "qwen3-coder"}, ""},
		{"claude passthrough", []string{"ollama"}, []string{"claude", "--model", "m", "--", "-p", "hi"}, "ollama", []string{"launch", "claude", "--model", "m", "--", "-p", "hi"}, ""},
		{"codex via ollama", []string{"ollama", "codex"}, []string{"codex", "--model", "gpt-oss:20b"}, "ollama", []string{"launch", "codex", "--model", "gpt-oss:20b"}, ""},
		{"codex fallback", []string{"codex"}, []string{"codex", "--model", "gpt-oss:20b", "--", "--sandbox", "read-only"}, "codex", []string{"--oss", "-m", "gpt-oss:20b", "--sandbox", "read-only"}, ""},
		{"codex fallback no model", []string{"codex"}, []string{"codex"}, "codex", []string{"--oss"}, ""},
		{"claude without ollama", nil, []string{"claude"}, "", nil, "`ollama` was not found"},
		{"codex with nothing installed", nil, []string{"codex"}, "", nil, "neither `ollama` nor `codex`"},
		{"unknown agent", []string{"ollama"}, []string{"cursor"}, "", nil, "unsupported agent \"cursor\" (supported: claude, codex)"},
		{"flag-like model", []string{"ollama"}, []string{"claude", "--model=--yes"}, "", nil, "invalid --model"},
		{"two agents", []string{"ollama"}, []string{"claude", "codex"}, "", nil, "expected exactly one agent"},
		{"no agent", []string{"ollama"}, []string{"--", "claude"}, "", nil, "expected exactly one agent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &launchRecorder{}
			_, err := runLaunch(t, rec.deps(tt.onPath...), tt.args...)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if rec.protected != "" || rec.ran {
					t.Fatalf("protect/run reached on invalid input (protected=%q ran=%v)", rec.protected, rec.ran)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !rec.ran || rec.bin != tt.wantBin || !reflect.DeepEqual(rec.args, tt.wantArgs) {
				t.Fatalf("ran %v %q %q, want %q %q", rec.ran, rec.bin, rec.args, tt.wantBin, tt.wantArgs)
			}
		})
	}
}

func TestLaunchRefusesWhenProtectionFails(t *testing.T) {
	rec := &launchRecorder{protectErr: errors.New("verification did not pass (1 failed, 0 unverified of 3 checks)")}
	out, err := runLaunch(t, rec.deps("ollama"), "claude", "--model", "qwen3-coder")
	if ExitCode(err) != 1 {
		t.Fatalf("exit = %d (%v), want 1", ExitCode(err), err)
	}
	if rec.protected != "claude-code" {
		t.Fatalf("protect called for %q, want claude-code", rec.protected)
	}
	if rec.ran {
		t.Fatal("agent was started although protection failed")
	}
	if !strings.Contains(out, "refusing to start Claude Code") || !strings.Contains(out, "1 failed") {
		t.Fatalf("output missing refusal reason:\n%s", out)
	}
}

// With the real protection step and no agent installed, protection cannot be
// confirmed, so the agent must never be executed.
func TestLaunchRealProtectionNeverExecsUnconfirmedAgent(t *testing.T) {
	testSetHome(t, t.TempDir())
	t.Setenv("PATH", t.TempDir())
	ran := false
	deps := launchDeps{
		lookPath: fakeLookPath("ollama"),
		protect:  protectForLaunch,
		run:      func(*cobra.Command, string, []string) error { ran = true; return nil },
	}
	out, err := runLaunch(t, deps, "codex")
	if err == nil || ran {
		t.Fatalf("err = %v ran = %v, want refusal without exec", err, ran)
	}
	if !strings.Contains(out, "refusing to start Codex") {
		t.Fatalf("output missing refusal:\n%s", out)
	}
}

func TestLaunchVerificationErrorFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		summary verificationSummary
		wantErr bool
	}{
		{"all pass", verificationSummary{Checks: 3, Passed: 3}, false},
		{"failed", verificationSummary{Checks: 3, Passed: 2, Failed: 1}, true},
		{"unverified", verificationSummary{Checks: 3, Passed: 2, Unverified: 1}, true},
		{"no checks", verificationSummary{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := launchVerificationError(verificationReport{Summary: tt.summary})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
