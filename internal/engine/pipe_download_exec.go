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
)

// pipelineFetchers write a remote response to stdout. The value is the program
// name used in the restrictive alias, so the existing `curl ** | sh` and
// `wget ** | sh` rules apply to every fetcher.
var pipelineFetchers = map[string]string{
	"curl":  "curl",
	"wget":  "wget",
	"fetch": "curl",
	"http":  "curl",
	"https": "curl",
	"xh":    "curl",
}

// pipelineInertReaders only filter, hash, count, decode or display their
// input. They cannot turn a fetched response into code, so piping a download
// into them is not code execution. The list is deliberately an allowlist:
// any other later stage (a shell, an interpreter, sed or awk, which can run
// their input, xargs, a while-read loop, a program Rampart has never heard of)
// is treated as potentially executing what it receives.
var pipelineInertReaders = map[string]bool{
	"head": true, "tail": true, "wc": true, "cat": true, "tac": true, "rev": true,
	"sort": true, "uniq": true, "cut": true, "tr": true, "nl": true, "fold": true,
	"grep": true, "egrep": true, "fgrep": true, "rg": true,
	"jq": true, "yq": true,
	"sha1sum": true, "sha224sum": true, "sha256sum": true, "sha384sum": true, "sha512sum": true,
	"shasum": true, "md5sum": true, "md5": true, "b2sum": true, "cksum": true,
	"xxd": true, "od": true, "hexdump": true,
	"gunzip": true, "zcat": true, "bzcat": true, "xzcat": true, "bunzip2": true, "unxz": true,
	"base64": true,
}

// pipelinePrivilegeWrappers run another program under a different identity.
// They are not transparent for matching, but a fetcher or an executor launched
// through one is still that fetcher or executor.
var pipelinePrivilegeWrappers = map[string]bool{"sudo": true, "doas": true, "pkexec": true}

// pipelineShellKeywords may precede a command inside a compound statement.
var pipelineShellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "while": true, "until": true,
	"do": true, "time": true, "!": true,
}

// pipelineCodeExecutors run program text they are handed as an argument, a
// here-string or a process substitution. Fetched output reaching one of them by
// command substitution is code execution; reaching echo, an assignment or a
// filter is not.
var pipelineCodeExecutors = map[string]bool{
	"eval": true, ".": true, "source": true, "exec": true,
	"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true,
	"fish": true, "csh": true, "tcsh": true,
	"ruby": true, "perl": true, "php": true, "lua": true, "luajit": true, "julia": true,
	"node": true, "nodejs": true, "deno": true, "bun": true, "Rscript": true,
	"pwsh": true, "powershell": true, "osascript": true, "tclsh": true,
}

func pipelineExecutorBase(base string) bool {
	return pipelineCodeExecutors[base] || strings.HasPrefix(base, "python") || strings.HasPrefix(base, "pypy")
}

type pipelineStage struct {
	args    []string // wrappers and leading keywords removed
	unknown bool     // the executable could not be established
	fetcher string   // alias program name when the stage is, or is fed by, a fetch
	url     string
	payload string // literal `sh -c` command string, analyzed as its own command

	// A group ( ... ) or { ...; } used as a stage. As a source it carries the
	// fetcher found anywhere inside; as a sink it is inert only when everything
	// inside is.
	group         bool
	nonInertGroup bool

	// The result of a command substitution that fetches remote content is part
	// of this command's arguments or standard input.
	tainted    bool
	taintProc  bool // arrives as a process substitution, <(...)
	hereString bool
}

func (s pipelineStage) inert() bool {
	if s.group {
		return !s.nonInertGroup
	}
	if s.unknown {
		return false
	}
	if len(s.args) == 0 {
		return true
	}
	return pipelineInertReaders[shellWrapperBasename(s.args[0])]
}

// executesTaintedInput reports whether a command that received fetched content
// by substitution runs it as code: the executable is itself the substitution;
// eval, the dot and source builtins; a shell or interpreter given the content
// as an inline program (-c, -e), a process substitution or a here-string
// (including under sudo); or a here-string into any program that is not a
// read-only filter. Passing fetched data as an ordinary argument to a script,
// an assignment, echo or a filter is not.
func (s pipelineStage) executesTaintedInput() bool {
	if !s.tainted || s.group {
		return false
	}
	if s.unknown {
		return true
	}
	args := s.args
	if len(args) > 0 && pipelinePrivilegeWrappers[shellWrapperBasename(args[0])] {
		for i, arg := range args[1:] {
			if pipelineExecutorBase(shellWrapperBasename(arg)) {
				args = args[i+1:]
				break
			}
		}
	}
	if len(args) == 0 {
		return false
	}
	base := shellWrapperBasename(args[0])
	if !pipelineExecutorBase(base) {
		return s.hereString && !s.inert()
	}
	switch base {
	case "eval", ".", "source", "exec":
		return true
	}
	if s.taintProc || s.hereString {
		return true
	}
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && hasCFlag(arg) {
			return true
		}
		switch arg {
		case "-e", "-E", "--eval", "-command", "-Command", "-r":
			return true
		}
	}
	return false
}

func classifyPipelineStage(stage []literalShellWord) pipelineStage {
	var result pipelineStage
	inv, _ := parseLiteralInvocation(stage)
	args := inv.args
	if len(args) > 0 {
		unwrapped := unwrapLiteralExecutor(args)
		if unwrapped == nil {
			// An ambiguous wrapper (env -S, --chdir) hides the executable.
			result.unknown = true
		}
		args = unwrapped
	}
	for len(args) > 0 && pipelineShellKeywords[args[0]] {
		args = args[1:]
	}
	result.args = args
	if len(args) == 0 {
		return result
	}
	if payload, wrapper := literalShellPayload(args); wrapper {
		result.payload = payload
	}
	// The executable word itself must be literal, or nothing is known about it.
	// Non-literal arguments to a filter (jq "$expr") do not change what it is.
	for _, word := range stage {
		if word.operator {
			continue
		}
		if word.value == args[0] {
			if !word.literal {
				result.unknown = true
			}
			break
		}
	}

	base := shellWrapperBasename(args[0])
	candidates := args[:1]
	if pipelinePrivilegeWrappers[base] {
		limit := len(args)
		if limit > 8 {
			limit = 8
		}
		candidates = args[1:limit]
	}
	for _, candidate := range candidates {
		if name, ok := pipelineFetchers[shellWrapperBasename(candidate)]; ok {
			result.fetcher = name
			break
		}
	}
	if result.fetcher != "" {
		for _, arg := range args[1:] {
			if strings.HasPrefix(arg, "https://") || strings.HasPrefix(arg, "http://") {
				result.url = arg
				break
			}
		}
	}
	return result
}

// backtickFetcher finds a legacy backtick command substitution that starts with
// a fetcher, such as eval `curl -s URL`. The lexer keeps backticks inside words.
func backtickFetcher(stage []literalShellWord) (string, bool) {
	for _, word := range stage {
		if word.operator {
			continue
		}
		if index := strings.Index(word.value, "`"); index >= 0 {
			rest := strings.TrimSpace(word.value[index+1:])
			if cut := strings.IndexAny(rest, " \t"); cut >= 0 {
				rest = rest[:cut]
			}
			if name, ok := pipelineFetchers[shellWrapperBasename(rest)]; ok {
				return name, true
			}
		}
	}
	return "", false
}

// extractSubstitutions returns the command strings of $(...) and backtick
// substitutions inside a word. The lexer keeps a double-quoted word opaque, so
// "$(curl u)" is one word whose text still has to be analyzed as a command.
func extractSubstitutions(value string) []string {
	var found []string
	for i := 0; i < len(value); i++ {
		switch {
		case value[i] == '$' && i+1 < len(value) && value[i+1] == '(':
			depth, j := 1, i+2
			for ; j < len(value) && depth > 0; j++ {
				switch value[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
			}
			if depth == 0 {
				found = append(found, value[i+2:j-1])
				i = j - 1
			} else {
				found = append(found, value[i+2:])
				i = len(value)
			}
		case value[i] == '`':
			if end := strings.IndexByte(value[i+1:], '`'); end >= 0 {
				found = append(found, value[i+1:i+1+end])
				i += end + 1
			} else {
				found = append(found, value[i+1:])
				i = len(value)
			}
		}
	}
	return found
}

type pipelineFrame struct {
	kind      byte // 0 top level, '(' subshell, '{' brace group, '$' command substitution, '<' process substitution
	stages    []pipelineStage
	cur       []literalShellWord
	pending   *pipelineStage // a group that just closed and is the current stage
	subst     string         // fetcher name found inside a substitution in the current command
	substURL  string
	substProc bool   // ...and it arrived as a process substitution
	fetcher   string // first fetcher found anywhere in the frame
	url       string
	nonInert  bool // something in the frame is not a read-only filter
}

// visitPipedDownloadExecutionAliases recognizes fetched content that reaches a
// non-filter stage and emits the restrictive alias `<fetcher> <url> | sh` so the
// existing download-and-execute rules apply. The alias is only ever used to
// deny; it is never a replacement command or an approval identity.
//
// Covered shapes: a fetcher feeding a later pipeline stage that is not a known
// read-only filter; the same through groups such as `(cd d && curl u) | sh` and
// `{ curl u; } | sh`; and a command substitution or process substitution that
// fetches, handed to eval, source, a shell or an interpreter, to a here-string,
// or used as the command itself.
//
// It is a bounded lexical view, not a shell interpreter: a here-document is
// data when only a read-only filter reads it and code otherwise, quoted text
// never splits a stage, and an unclear executable is treated as potentially
// executing.
func visitPipedDownloadExecutionAliases(command string, visit func(string) bool) {
	if len(command) > maxGlobInputLen || !strings.ContainsAny(command, "|$`<") {
		return
	}
	// walk analyzes one command string. It reports whether the visitor wants more
	// aliases, plus the first fetcher found anywhere in the string, so a caller
	// can tell that the text of a substitution fetches remote content.
	var walk func(string, int) (bool, string, string)
	walk = func(command string, depth int) (bool, string, string) {
		if depth > 16 {
			return true, "", ""
		}
		words, ok := literalShellWords(command)
		if !ok {
			// The shell runs the lines before a syntax error, so analyze each
			// line on its own rather than skipping the whole command.
			if !strings.Contains(command, "\n") {
				return true, "", ""
			}
			fetcher, url := "", ""
			for _, line := range strings.Split(command, "\n") {
				more, f, u := walk(line, depth+1)
				if fetcher == "" {
					fetcher, url = f, u
				}
				if !more {
					return false, fetcher, url
				}
			}
			return true, fetcher, url
		}
		for _, word := range words {
			if !word.operator || !strings.HasPrefix(word.value, "<<") || word.value == "<<<" {
				continue
			}
			// Analyze the command without here-document bodies, and a body as
			// code whenever its reader may execute it.
			stripped, docs, ok := splitHereDocuments(command)
			if !ok || stripped == command {
				break
			}
			more, fetcher, url := walk(stripped, depth+1)
			if !more {
				return false, fetcher, url
			}
			for _, doc := range docs {
				if hereDocumentIsData(doc.line) {
					continue
				}
				if more, _, _ = walk(doc.body, depth+1); !more {
					return false, fetcher, url
				}
			}
			return true, fetcher, url
		}

		alias := func(name, target string) string {
			if target == "" {
				target = "URL"
			}
			return name + " " + target + " | sh"
		}
		stack := []*pipelineFrame{{}}
		top := func() *pipelineFrame { return stack[len(stack)-1] }

		finishStage := func(f *pipelineFrame) bool {
			var stage pipelineStage
			switch {
			case f.pending != nil:
				stage = *f.pending
				f.pending = nil
			case len(f.cur) > 0:
				stage = classifyPipelineStage(f.cur)
				for _, word := range f.cur {
					if word.operator && word.value == "<<<" {
						stage.hereString = true
					}
					// A double-quoted word is opaque to the lexer, so substitutions
					// inside it are analyzed as command strings of their own.
					if !word.operator && !word.literal && strings.ContainsAny(word.value, "$`") {
						for _, inner := range extractSubstitutions(word.value) {
							more, name, url := walk(inner, depth+1)
							if !more {
								return false
							}
							if name != "" && f.subst == "" {
								f.subst, f.substURL = name, url
							}
						}
					}
				}
				if f.subst == "" {
					if name, found := backtickFetcher(f.cur); found {
						f.subst = name
					}
				}
			default:
				f.subst, f.substURL, f.substProc = "", "", false
				return true
			}
			if f.subst != "" {
				stage.tainted = true
				stage.taintProc = f.substProc
				if stage.fetcher == "" {
					stage.fetcher, stage.url = f.subst, f.substURL
				}
			}
			f.cur, f.subst, f.substURL, f.substProc = nil, "", "", false
			if stage.payload != "" {
				if more, _, _ := walk(stage.payload, depth+1); !more {
					return false
				}
			}
			if stage.executesTaintedInput() && !visit(alias(stage.fetcher, stage.url)) {
				return false
			}
			f.stages = append(f.stages, stage)
			if stage.fetcher != "" && f.fetcher == "" {
				f.fetcher, f.url = stage.fetcher, stage.url
			}
			if !stage.inert() {
				f.nonInert = true
			}
			return true
		}
		evaluate := func(f *pipelineFrame) bool {
			stages := f.stages
			f.stages = nil
			first := -1
			for i, stage := range stages {
				if stage.fetcher != "" {
					first = i
					break
				}
			}
			if first < 0 {
				return true
			}
			for _, later := range stages[first+1:] {
				if !later.inert() {
					return visit(alias(stages[first].fetcher, stages[first].url))
				}
			}
			return true
		}
		closeFrame := func() bool {
			child := top()
			if !finishStage(child) || !evaluate(child) {
				return false
			}
			stack = stack[:len(stack)-1]
			parent := top()
			switch child.kind {
			case '(', '{':
				parent.pending = &pipelineStage{
					group:         true,
					fetcher:       child.fetcher,
					url:           child.url,
					nonInertGroup: child.nonInert,
				}
			default:
				if child.fetcher != "" {
					parent.subst, parent.substURL = child.fetcher, child.url
					parent.substProc = child.kind == '<'
				}
			}
			return true
		}
		commandPosition := func(i int) bool {
			if i == 0 {
				return true
			}
			previous := words[i-1]
			if previous.operator {
				switch previous.value {
				case ";", "&&", "||", "&", "|", "\n", "(", "{":
					return true
				}
				return false
			}
			return pipelineShellKeywords[previous.value]
		}

		for i := 0; i < len(words); i++ {
			word := words[i]
			if !word.operator {
				top().cur = append(top().cur, word)
				continue
			}
			switch word.value {
			case "|":
				if !finishStage(top()) {
					return false, "", ""
				}
				if i+1 < len(words) && words[i+1].operator && words[i+1].value == "&" {
					i++ // |& pipes stderr as well
				}
			case ";", "&&", "||", "&", "\n":
				if !finishStage(top()) || !evaluate(top()) {
					return false, "", ""
				}
			case "(":
				kind := byte('(')
				if i > 0 {
					previous := words[i-1]
					switch {
					case !previous.operator && previous.value == "$":
						kind = '$'
					case previous.operator && (previous.value == "<" || previous.value == ">"):
						kind = '<'
					}
				}
				stack = append(stack, &pipelineFrame{kind: kind})
			case ")":
				if len(stack) > 1 && !closeFrame() {
					return false, "", ""
				}
			case "{":
				// Brace tokens also split words such as https://host/{a,b}.sh and
				// ${VAR}; only a brace at the start of a command opens a group.
				if commandPosition(i) {
					stack = append(stack, &pipelineFrame{kind: '{'})
				}
			case "}":
				if len(stack) > 1 && top().kind == '{' && i > 0 && words[i-1].operator {
					if !closeFrame() {
						return false, "", ""
					}
				}
			default:
				top().cur = append(top().cur, word) // redirections stay inside their stage
			}
		}
		for len(stack) > 1 {
			if !closeFrame() {
				return false, "", ""
			}
		}
		root := top()
		more := finishStage(root) && evaluate(root)
		return more, root.fetcher, root.url
	}
	walk(command, 0)
}
