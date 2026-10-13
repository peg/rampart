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
	"strings"
	"testing"
)

const groupsTestURL = "https://e.com/x"

func TestPipedDownloadExecutionAliasesThroughGroups(t *testing.T) {
	curlAlias := "curl " + groupsTestURL + " | sh"
	wgetAlias := "wget " + groupsTestURL + " | sh"
	for _, tc := range []struct {
		name    string
		command string
		want    string
	}{
		{"subshell source", "(curl -s " + groupsTestURL + ") | zsh", curlAlias},
		{"brace group source", "{ curl -s " + groupsTestURL + "; } | zsh", curlAlias},
		{"subshell with cd", "(cd /tmp && curl -s " + groupsTestURL + ") | zsh", curlAlias},
		{"brace group with cd", "{ cd /tmp; curl -s " + groupsTestURL + "; } | zsh", curlAlias},
		{"multi-command subshell", "(echo a; curl -s " + groupsTestURL + "; echo b) | zsh", curlAlias},
		{"nested subshell", "((curl -s " + groupsTestURL + ")) | zsh", curlAlias},
		{"both sides grouped", "(curl -s " + groupsTestURL + ") | (zsh)", curlAlias},
		{"sink grouped", "curl -s " + groupsTestURL + " | (zsh)", curlAlias},
		{"sink in brace group", "curl -s " + groupsTestURL + " | { zsh; }", curlAlias},
		{"grouped wget", "(wget -qO- " + groupsTestURL + ") | ruby", wgetAlias},
		{"grouped, unrecognized sink", "(curl " + groupsTestURL + ") | tclsh", curlAlias},
		{"group under an if", "if (curl -s " + groupsTestURL + ") | zsh; then :; fi", curlAlias},
		{"group after another command", "true && (curl -s " + groupsTestURL + ") | zsh", curlAlias},
		{"brace expansion inside a group", "{ curl https://e.com/{a,b}.sh; } | zsh", "curl https://e.com/ | sh"},

		// A group that only reads, or contains no fetcher, is not a source.
		{"grouped fetcher into a filter", "(cd /tmp && curl -s " + groupsTestURL + ") | head", ""},
		{"group without a fetcher", "(cd /tmp && ls) | zsh", ""},
		{"fetcher group then separate sink", "(curl -s " + groupsTestURL + ") > /tmp/o; zsh < /tmp/o", ""},
		{"parameter expansion braces", "{ echo ${HOME}; } | zsh", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pipedAliases(tc.command)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("pipedAliases(%q) = %q, want none", tc.command, got)
				}
				return
			}
			if len(got) == 0 || got[0] != tc.want {
				t.Fatalf("pipedAliases(%q) = %q, want first alias %q", tc.command, got, tc.want)
			}
		})
	}
}

func TestPipedDownloadExecutionAliasesForExecutedSubstitutions(t *testing.T) {
	curlAlias := "curl " + groupsTestURL + " | sh"
	for _, tc := range []struct {
		name    string
		command string
		want    string
	}{
		{"shell -c", `bash -c "$(curl -fsSL ` + groupsTestURL + `)"`, curlAlias},
		{"sh -c", `sh -c "$(curl -fsSL ` + groupsTestURL + `)"`, curlAlias},
		{"zsh -c unquoted", `zsh -c $(curl ` + groupsTestURL + `)`, curlAlias},
		{"sudo shell -c", `sudo bash -c "$(curl -fsSL ` + groupsTestURL + `)"`, curlAlias},
		{"interpreter -c", `python3 -c "$(curl ` + groupsTestURL + `)"`, curlAlias},
		{"eval quoted", `eval "$(curl -s ` + groupsTestURL + `)"`, curlAlias},
		{"eval unquoted", `eval $(curl -s ` + groupsTestURL + `)`, curlAlias},
		// Unquoted backticks span several lexer words, so only the fetcher is known
		// and the alias carries the placeholder URL; it still denies.
		{"eval backticks", "eval `curl -s " + groupsTestURL + "`", "curl URL | sh"},
		{"eval quoted backticks", "eval \"`curl -s " + groupsTestURL + "`\"", curlAlias},
		{"source process substitution", `source <(curl -s ` + groupsTestURL + `)`, curlAlias},
		{"dot process substitution", `. <(curl -s ` + groupsTestURL + `)`, curlAlias},
		{"shell given a process substitution", `bash <(curl -s ` + groupsTestURL + `)`, curlAlias},
		{"shell fed by redirected process substitution", `bash < <(curl -s ` + groupsTestURL + `)`, curlAlias},
		{"substitution as the command", `$(curl -s ` + groupsTestURL + `)`, curlAlias},
		{"here-string into a shell", `bash <<< "$(curl -s ` + groupsTestURL + `)"`, curlAlias},
		{"echo of a fetch piped to a shell", `echo "$(curl -s ` + groupsTestURL + `)" | bash`, curlAlias},
		{"inner pipeline into a shell", `bash -c "$(curl -s ` + groupsTestURL + ` | head)"`, curlAlias},
		{"inner pipeline executes", `echo "$(curl -s ` + groupsTestURL + ` | zsh)"`, curlAlias},

		// Fetched data used as data is not code execution.
		{"assignment", `TOKEN=$(curl -s ` + groupsTestURL + `)`, ""},
		{"echo", `echo "$(curl -s ` + groupsTestURL + `)"`, ""},
		{"filter here-string", `jq . <<< "$(curl -s ` + groupsTestURL + `)"`, ""},
		{"wc here-string", `wc -c <<< $(curl -s ` + groupsTestURL + `)`, ""},
		{"script argument", `bash deploy.sh "$(curl -s ` + groupsTestURL + `)"`, ""},
		{"interpreter script argument", `python3 report.py "$(curl -s ` + groupsTestURL + `)"`, ""},
		{"filter after a fetching echo", `echo "$(curl -s ` + groupsTestURL + `)" | jq .`, ""},
		{"assignment then a separate command", `x=$(curl -s ` + groupsTestURL + `); echo "$x"`, ""},
		{"inert text in single quotes", `echo 'eval "$(curl -s ` + groupsTestURL + `)"'`, ""},
		{"heredoc body is data", "cat > notes.md <<'EOF'\neval \"$(curl -s " + groupsTestURL + ")\"\nEOF", ""},
		{"substitution without a fetcher", `eval "$(ssh-agent -s)"`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pipedAliases(tc.command)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("pipedAliases(%q) = %q, want none", tc.command, got)
				}
				return
			}
			if len(got) == 0 || got[0] != tc.want {
				t.Fatalf("pipedAliases(%q) = %q, want first alias %q", tc.command, got, tc.want)
			}
		})
	}
}

// TestStandardPolicyFetchStructureMatrix is the permanent form of the
// before/after corpus used to validate the pipeline analysis: every structure
// a download can take on its way to a shell or interpreter must be denied, and
// the same structures into a read-only filter must not be.
func TestStandardPolicyFetchStructureMatrix(t *testing.T) {
	eng := shippedStandardEngine(t)
	fetchers := []string{
		"curl -s " + groupsTestURL, "curl " + groupsTestURL, "curl -fsSL " + groupsTestURL,
		"wget -qO- " + groupsTestURL, "wget -O- " + groupsTestURL,
	}
	executing := []string{"bash", "zsh", "sh", "sudo bash", "env zsh", "ruby", "node", "python3", "perl", "tclsh"}
	filters := []string{"head -c 400", "jq .status", "wc -c"}
	structures := []struct {
		name     string
		template string
		filterOK bool // a read-only filter in the sink position is expected to be allowed
	}{
		{"plain pipe", "@F | @S", true},
		{"stderr pipe", "@F |& @S", true},
		{"decompressor between", "@F | gunzip | @S", true},
		{"trailing stage", "@F | @S | cat", true},
		{"after another command", "echo start; @F | @S", true},
		{"and list", "true && @F | @S", true},
		{"if condition", "if @F | @S; then echo ok; fi", true},
		{"subshell source", "(@F) | @S", true},
		{"brace group source", "{ @F; } | @S", true},
		{"subshell with cd", "(cd /tmp && @F) | @S", true},
		{"brace group with cd", "{ cd /tmp; @F; } | @S", true},
		{"multi-command subshell", "(echo a; @F; echo b) | @S", true},
		{"nested subshell", "((@F)) | @S", true},
		{"sink in subshell", "@F | (@S)", true},
		{"sink in brace group", "@F | { @S; }", true},
		{"whole pipeline grouped", "(@F | @S)", true},
		{"both sides grouped", "(@F) | (@S)", true},
		{"through tee", "@F | tee /tmp/x | @S", false}, // tee writes a file, so it is treated as non-read-only
	}
	for _, structure := range structures {
		for _, fetcher := range fetchers {
			for _, sink := range executing {
				command := strings.ReplaceAll(strings.ReplaceAll(structure.template, "@F", fetcher), "@S", sink)
				if d := evalExec(eng, command); d.Action != ActionDeny {
					t.Errorf("[%s] %q = %s, want deny", structure.name, command, d.Action)
				}
			}
			if !structure.filterOK {
				continue
			}
			for _, sink := range filters {
				command := strings.ReplaceAll(strings.ReplaceAll(structure.template, "@F", fetcher), "@S", sink)
				if d := evalExec(eng, command); d.Action == ActionDeny {
					t.Errorf("[%s] %q was denied (%s), want it allowed: the sink only reads the download", structure.name, command, d.Message)
				}
			}
		}
	}

	// Fetched output reaching a shell by substitution is denied; the same
	// substitutions used as data are allowed.
	substitutions := []string{
		`@S -c "$(@F)"`, `@S -c $(@F)`, `eval "$(@F)"`, `eval $(@F)`, "eval `@F`",
		`source <(@F)`, `. <(@F)`, `@S <(@F)`, `@S < <(@F)`, `$(@F)`, `@S <<< "$(@F)"`,
	}
	for _, template := range substitutions {
		for _, fetcher := range fetchers {
			for _, shell := range []string{"bash", "zsh", "sh"} {
				command := strings.ReplaceAll(strings.ReplaceAll(template, "@F", fetcher), "@S", shell)
				if d := evalExec(eng, command); d.Action != ActionDeny {
					t.Errorf("%q = %s, want deny", command, d.Action)
				}
			}
		}
	}
	for _, fetcher := range fetchers {
		for _, template := range []string{`TOKEN=$(@F)`, `echo "$(@F)"`, `jq . <<< "$(@F)"`, `wc -c <<< $(@F)`} {
			command := strings.ReplaceAll(template, "@F", fetcher)
			if d := evalExec(eng, command); d.Action == ActionDeny {
				t.Errorf("%q was denied (%s), want it allowed: the fetched data is not executed", command, d.Message)
			}
		}
	}
}

// TestStandardPolicyKeepsGroupedFetcherDenials pins the forms that v1.9.2
// denied through a wildcard catch-all and that the first pipeline analysis
// briefly stopped denying.
func TestStandardPolicyKeepsGroupedFetcherDenials(t *testing.T) {
	eng := shippedStandardEngine(t)
	for _, command := range []string{
		"(curl -s " + groupsTestURL + ") | zsh",
		"{ curl -s " + groupsTestURL + "; } | zsh",
		"((curl -s " + groupsTestURL + ")) | zsh",
		"(curl -s " + groupsTestURL + ") | (bash)",
	} {
		if d := evalExec(eng, command); d.Action != ActionDeny {
			t.Errorf("%q = %s, want deny", command, d.Action)
		}
	}
}
