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
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGeneralizeCommandPatterns(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // empty string means no wildcard should be produced
	}{
		{
			name:  "npm install package",
			input: "npm install typescript",
			want:  "npm install *",
		},
		{
			name:  "git push with remote and branch",
			input: "git push origin main",
			want:  "git push origin *", // last arg (branch) replaced with *
		},
		{
			name:  "sudo apt subcommand",
			input: "sudo apt update",
			want:  "sudo apt *",
		},
		{
			name:  "pip install package",
			input: "pip install requests",
			want:  "pip install *",
		},
		{
			name:  "echo with argument",
			input: "echo hello",
			want:  "echo *",
		},
		{
			name:  "single token no wildcard",
			input: "ls",
			want:  "",
		},
		{
			name:  "empty string no wildcard",
			input: "",
			want:  "",
		},
		// Safety: dangerous commands must never produce wildcards.
		{
			name:  "rm must not produce wildcard",
			input: "rm -rf /tmp/foo",
			want:  "",
		},
		{
			name:  "shred must not produce wildcard",
			input: "shred /dev/sda",
			want:  "",
		},
		{
			name:  "dd must not produce wildcard",
			input: "dd if=/dev/zero of=/dev/sda",
			want:  "",
		},
		// Safety: sensitive paths must not become wildcards.
		{
			name:  "cat /etc/passwd sensitive path no wildcard",
			input: "cat /etc/passwd",
			want:  "",
		},
		{
			name:  "cat /etc/shadow sensitive path no wildcard",
			input: "cat /etc/shadow",
			want:  "",
		},
		{
			name:  "path under root no wildcard",
			input: "cat /root/.bashrc",
			want:  "",
		},
		// Trailing flags only: no meaningful non-flag arg to wildcard.
		{
			name:  "all flags no wildcard",
			input: "git --version",
			want:  "",
		},
		// Last arg already a wildcard: no change.
		{
			name:  "last arg already wildcard",
			input: "npm install *",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := generalizeCommand(tc.input)
			if got != tc.want {
				t.Errorf("generalizeCommand(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestIsDangerousBaseCommand(t *testing.T) {
	dangerous := []string{
		"rm file",
		"/usr/bin/rm file",
		"shred -u secret.txt",
		"dd if=/dev/zero of=/dev/sda",
		"wipefs /dev/sda",
		"mkfs.ext4 /dev/sda1",
	}
	for _, cmd := range dangerous {
		if !isDangerousBaseCommand(cmd) {
			t.Errorf("isDangerousBaseCommand(%q) = false, want true", cmd)
		}
	}

	safe := []string{
		"git push",
		"npm install",
		"echo hello",
		"cat /etc/passwd",
	}
	for _, cmd := range safe {
		if isDangerousBaseCommand(cmd) {
			t.Errorf("isDangerousBaseCommand(%q) = true, want false", cmd)
		}
	}
}

func TestIsSensitivePath(t *testing.T) {
	sensitive := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/root/.bashrc",
		"/proc/1/maps",
		"/sys/firmware/efi",
		"/dev/sda",
		"/home/user/.ssh/id_rsa",
		"/home/user/.gnupg/secring.gpg",
		"/home/user/.aws/credentials",
		"/home/user/.config/secrets",
		"server.pem",
		"private.key",
	}
	for _, path := range sensitive {
		if !isSensitivePath(path) {
			t.Errorf("isSensitivePath(%q) = false, want true", path)
		}
	}

	notSensitive := []string{
		"/home/user/projects/main.go",
		"/tmp/output.txt",
		"/var/log/app.log",
		"README.md",
	}
	for _, path := range notSensitive {
		if isSensitivePath(path) {
			t.Errorf("isSensitivePath(%q) = true, want false", path)
		}
	}
}

func TestGenerateSuggestions_ExecCommand(t *testing.T) {
	tests := []struct {
		name          string
		command       string
		wantExact     string
		wantWildcard  string
		wantNoWild    bool // true if no wildcard suggestion expected
	}{
		{
			name:         "npm install package",
			command:      "npm install typescript",
			wantExact:    `rampart allow "npm install typescript"`,
			wantWildcard: `rampart allow "npm install *"`,
		},
		{
			name:         "git push command",
			command:      "git push origin main",
			wantExact:    `rampart allow "git push origin main"`,
			wantWildcard: `rampart allow "git push origin *"`, // last arg (branch) wildcarded
		},
		{
			name:       "cat sensitive file — exact only",
			command:    "cat /etc/passwd",
			wantExact:  `rampart allow "cat /etc/passwd"`,
			wantNoWild: true,
		},
		{
			name:       "rm command — exact only (dangerous)",
			command:    "rm -rf /tmp/foo",
			wantExact:  `rampart allow "rm -rf /tmp/foo"`,
			wantNoWild: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			call := ToolCall{
				ID:        "test",
				Tool:      "exec",
				Params:    map[string]any{"command": tc.command},
				Timestamp: time.Now(),
			}
			suggestions := generateSuggestions(call)
			if len(suggestions) == 0 {
				t.Fatalf("generateSuggestions() returned no suggestions, want at least exact match")
			}
			if suggestions[0] != tc.wantExact {
				t.Errorf("suggestions[0] = %q, want %q", suggestions[0], tc.wantExact)
			}
			if tc.wantNoWild {
				if len(suggestions) > 1 {
					t.Errorf("expected no wildcard suggestion, got %q", suggestions[1])
				}
			} else {
				if len(suggestions) < 2 {
					t.Errorf("expected wildcard suggestion %q, got none", tc.wantWildcard)
				} else if suggestions[1] != tc.wantWildcard {
					t.Errorf("suggestions[1] = %q, want %q", suggestions[1], tc.wantWildcard)
				}
			}
		})
	}
}

func TestGenerateSuggestions_FilePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix paths in test fixtures")
	}
	tests := []struct {
		name         string
		tool         string
		path         string
		wantExact    string
		wantWildcard string
		wantNoWild   bool
	}{
		{
			name:         "read normal file",
			tool:         "read",
			path:         "/home/user/project/main.go",
			wantExact:    `rampart allow "/home/user/project/main.go" --tool read`,
			wantWildcard: `rampart allow "/home/user/project/*" --tool read`,
		},
		{
			name:       "read ssh key — warning (extremely sensitive)",
			tool:       "read",
			path:       "/home/user/.ssh/id_rsa",
			wantExact:  "⚠️  This path is highly sensitive. Allowing access is not recommended.",
			wantNoWild: true,
		},
		{
			name:       "write — no wildcard (unsafe)",
			tool:       "write",
			path:       "/home/user/project/output.txt",
			wantExact:  `rampart allow "/home/user/project/output.txt" --tool write`,
			wantNoWild: true,
		},
		{
			name:       "read /etc/passwd — exact match only (sensitive but not extremely)",
			tool:       "read",
			path:       "/etc/passwd",
			wantExact:  `rampart allow "/etc/passwd" --tool read`,
			wantNoWild: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			call := ToolCall{
				ID:        "test",
				Tool:      tc.tool,
				Params:    map[string]any{"path": tc.path},
				Timestamp: time.Now(),
			}
			suggestions := generateSuggestions(call)
			if len(suggestions) == 0 {
				t.Fatalf("generateSuggestions() returned no suggestions")
			}
			if suggestions[0] != tc.wantExact {
				t.Errorf("suggestions[0] = %q, want %q", suggestions[0], tc.wantExact)
			}
			if tc.wantNoWild {
				if len(suggestions) > 1 {
					t.Errorf("expected no wildcard suggestion, got %q", suggestions[1])
				}
			} else {
				if len(suggestions) < 2 {
					t.Errorf("expected wildcard suggestion %q, got none", tc.wantWildcard)
				} else if suggestions[1] != tc.wantWildcard {
					t.Errorf("suggestions[1] = %q, want %q", suggestions[1], tc.wantWildcard)
				}
			}
		})
	}
}

func TestGenerateSuggestions_NoCommand(t *testing.T) {
	// A ToolCall with neither command nor path should return empty suggestions.
	call := ToolCall{
		ID:        "test",
		Tool:      "exec",
		Params:    map[string]any{},
		Timestamp: time.Now(),
	}
	suggestions := generateSuggestions(call)
	if len(suggestions) != 0 {
		t.Errorf("expected no suggestions for empty call, got %v", suggestions)
	}
}

func TestGenerateSuggestions_NoDangerousWildcards(t *testing.T) {
	// Ensure none of the generated suggestions produce dangerous patterns.
	dangerousInputs := []struct {
		tool    string
		command string
		path    string
	}{
		{tool: "exec", command: "rm -rf /"},
		{tool: "exec", command: "rm /home/user/file.txt"},
		{tool: "exec", command: "shred /dev/sda"},
		{tool: "exec", command: "dd if=/dev/zero of=/dev/sda"},
		{tool: "exec", command: "cat /etc/shadow"},
		{tool: "write", path: "/home/user/important.txt"},
		{tool: "read", path: "/etc/passwd"},
		// Transparent prefix commands (sudo, env, etc.) should also be caught
		{tool: "exec", command: "sudo rm -rf /tmp/foo"},
		{tool: "exec", command: "sudo shred /dev/sda"},
		{tool: "exec", command: "sudo dd if=/dev/zero of=/dev/sda"},
		{tool: "exec", command: "env VAR=x rm /home/user/file.txt"},
		{tool: "exec", command: "sudo -u root rm /var/log/file"},
		{tool: "exec", command: "nice -n 10 rm /tmp/file"},
	}
	for _, inp := range dangerousInputs {
		params := map[string]any{}
		if inp.command != "" {
			params["command"] = inp.command
		}
		if inp.path != "" {
			params["path"] = inp.path
		}
		call := ToolCall{
			ID:        "test",
			Tool:      inp.tool,
			Params:    params,
			Timestamp: time.Now(),
		}
		suggestions := generateSuggestions(call)
		for _, s := range suggestions {
			// No suggestion should contain a bare "**" wildcard that matches everything.
			if strings.Contains(s, `"**"`) {
				t.Errorf("dangerous ** wildcard suggestion for %+v: %q", inp, s)
			}
			// No suggestion should suggest a bare " *" at the end for any command.
			if strings.Contains(s, `" *"`) || strings.HasSuffix(s, ` *"`) {
				t.Errorf("dangerous trailing wildcard suggestion for %+v: %q", inp, s)
			}
			// No suggestion should suggest wildcards for rm/shred/dd (including via sudo/env).
			dangerousCmds := []string{`"rm `, `"shred `, `"dd `, `"sudo rm `, `"sudo shred `, `"sudo dd `, `"env `, `"nice `}
			for _, danger := range dangerousCmds {
				if strings.Contains(s, danger) && strings.HasSuffix(strings.TrimSpace(s), `*"`) {
					t.Errorf("dangerous wildcard suggestion for %q: %q", inp.command, s)
				}
			}
		}
	}
}

func TestEngineEvaluateDenyIncludesSuggestions(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: block-npm-install
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["npm install *"]
        message: "package installation blocked"
`)

	call := ToolCall{
		ID:        "test-001",
		Agent:     "main",
		Session:   "test-session",
		Tool:      "exec",
		Params:    map[string]any{"command": "npm install lodash"},
		Timestamp: time.Now(),
	}

	decision := e.Evaluate(call)
	if decision.Action != ActionDeny {
		t.Fatalf("expected deny, got %s", decision.Action)
	}
	if len(decision.Suggestions) == 0 {
		t.Fatal("expected suggestions on deny decision, got none")
	}
	// First suggestion should be exact command.
	wantExact := `rampart allow "npm install lodash"`
	if decision.Suggestions[0] != wantExact {
		t.Errorf("Suggestions[0] = %q, want %q", decision.Suggestions[0], wantExact)
	}
	// Second suggestion should be wildcard.
	wantWild := `rampart allow "npm install *"`
	if len(decision.Suggestions) < 2 || decision.Suggestions[1] != wantWild {
		t.Errorf("expected wildcard suggestion %q, got %v", wantWild, decision.Suggestions)
	}
}

func TestEngineEvaluateAllowHasNoSuggestions(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies: []
`)

	call := ToolCall{
		ID:        "test-001",
		Agent:     "main",
		Session:   "test-session",
		Tool:      "exec",
		Params:    map[string]any{"command": "git status"},
		Timestamp: time.Now(),
	}

	decision := e.Evaluate(call)
	if decision.Action == ActionDeny {
		t.Fatal("expected allow, got deny")
	}
	if len(decision.Suggestions) != 0 {
		t.Errorf("expected no suggestions on allow decision, got %v", decision.Suggestions)
	}
}
