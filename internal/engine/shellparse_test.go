// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package engine

import (
	"testing"
)

func TestNormalizeCommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		// Basic passthrough
		{"simple", "rm -rf /", "rm -rf /"},
		{"empty", "", ""},
		{"whitespace", "  ls  -la  ", "ls -la"},

		// Quote stripping — evasion vectors
		{"single quotes", "'rm' -rf /", "rm -rf /"},
		{"double quotes", `"rm" -rf /`, "rm -rf /"},
		{"mixed quotes", `'rm' "-rf" /`, "rm -rf /"},
		{"quotes around arg", `rm '-rf' /`, "rm -rf /"},
		{"quoted spaces", `echo "hello world"`, "echo hello world"},
		{"single quoted spaces", `echo 'hello world'`, "echo hello world"},

		// Backslash escaping — evasion vector
		{"backslash escape", `r\m -rf /`, "rm -rf /"},
		{"backslash in middle", `ca\t /etc/passwd`, "cat /etc/passwd"},
		{"multiple backslashes", `r\m -r\f /`, "rm -rf /"},

		// Env var prefix stripping
		{"env prefix", "FOO=bar rm -rf /", "rm -rf /"},
		{"multiple env", "FOO=bar BAZ=qux rm -rf /", "rm -rf /"},
		{"env with path", "PATH=/usr/bin:/bin ls", "ls"},
		{"only env", "FOO=bar", ""},

		// Compound commands
		{"and", "rm -rf / && echo done", "rm -rf / && echo done"},
		{"or", "rm -rf / || echo failed", "rm -rf / && echo failed"},
		{"semicolon", "rm -rf /; echo done", "rm -rf / && echo done"},
		{"pipe", "cat /etc/passwd | grep root", "cat /etc/passwd && grep root"},
		{"complex compound", "'rm' -rf / && echo done", "rm -rf / && echo done"},

		// Edge cases
		{"empty quotes", `'' ls`, "ls"},
		{"nested double in single", `'he said "hi"' arg`, `he said "hi" arg`},
		{"escaped delimiter", `echo 'a&&b'`, "echo a&&b"},
		{"backticks preserved", "echo `whoami`", "echo `whoami`"},
		{"dollar expansion preserved", "echo $(whoami)", "echo $(whoami)"},
		{"backslash at end", `rm\`, `rm\`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeCommand(tt.cmd)
			if got != tt.want {
				t.Errorf("NormalizeCommand(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestSplitCompoundCommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{"simple", "ls", []string{"ls"}},
		{"and", "a && b", []string{"a", "b"}},
		{"or", "a || b", []string{"a", "b"}},
		{"semicolon", "a ; b", []string{"a", "b"}},
		{"pipe", "a | b", []string{"a", "b"}},
		{"mixed", "a && b | c ; d", []string{"a", "b", "c", "d"}},
		{"quoted pipe", "echo 'a|b'", []string{"echo 'a|b'"}},
		{"quoted and", `echo "a&&b"`, []string{`echo "a&&b"`}},
		{"empty", "", nil},
		{"empty segments", "a ;; b", []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitCompoundCommand(tt.cmd)
			if len(got) != len(tt.want) {
				t.Fatalf("SplitCompoundCommand(%q) = %v (len %d), want %v (len %d)",
					tt.cmd, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("segment %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractSubcommands(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{"dollar paren", "$(rm -rf /)", []string{"rm -rf /"}},
		{"backtick", "`rm -rf /`", []string{"rm -rf /"}},
		{"echo with dollar paren", "echo $(cat /etc/shadow)", []string{"cat /etc/shadow"}},
		{"eval double quotes", `eval "rm -rf /"`, []string{"rm -rf /"}},
		{"eval single quotes", `eval 'rm -rf /'`, []string{"rm -rf /"}},
		{"nested dollar paren", "$(echo $(whoami))", []string{"echo $(whoami)", "whoami"}},
		{"multiple substitutions", "$(ls) && $(pwd)", []string{"ls", "pwd"}},
		{"empty dollar paren", "$()", nil},
		{"unclosed dollar paren", "$(rm -rf /", nil},
		{"unclosed backtick", "`rm -rf /", nil},
		{"no substitution", "echo hello", nil},
		{"dollar without paren", "$HOME/bin/test", nil},
		{"eval with env prefix", `FOO=bar eval "rm -rf /"`, []string{"rm -rf /"}},
		{"backtick in echo", "echo `whoami`", []string{"whoami"}},
		{"mixed backtick and dollar", "echo `uname` $(id)", []string{"id", "uname"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSubcommands(tt.cmd)
			if len(got) != len(tt.want) {
				t.Fatalf("ExtractSubcommands(%q) = %v (len %d), want %v (len %d)",
					tt.cmd, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("result %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func FuzzExtractSubcommands(f *testing.F) {
	f.Add("$(rm -rf /)")
	f.Add("`rm -rf /`")
	f.Add("echo $(cat /etc/shadow)")
	f.Add(`eval "rm -rf /"`)
	f.Add("$(echo $(whoami))")
	f.Add("$()")
	f.Add("$(")
	f.Add("`")
	f.Add("")
	f.Add("normal command")
	f.Add("$$$$(((())))")
	f.Add("`nested `backtick``")

	f.Fuzz(func(t *testing.T, cmd string) {
		// Should never panic.
		results := ExtractSubcommands(cmd)
		for _, r := range results {
			if r == "" {
				t.Error("ExtractSubcommands returned empty string")
			}
		}
	})
}

func TestNormalizeCommand_EvasionVectors(t *testing.T) {
	// All of these should normalize to "rm -rf /"
	evasions := []string{
		"rm -rf /",
		"'rm' -rf /",
		`"rm" -rf /`,
		`r\m -rf /`,
		`'r'm -rf /`,
		`FOO=bar rm -rf /`,
	}
	for _, cmd := range evasions {
		got := NormalizeCommand(cmd)
		if got != "rm -rf /" {
			t.Errorf("NormalizeCommand(%q) = %q, want %q", cmd, got, "rm -rf /")
		}
	}
}
