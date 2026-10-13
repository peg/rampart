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
// They are not transparent for matching, but a fetcher launched through one is
// still a fetcher.
var pipelinePrivilegeWrappers = map[string]bool{"sudo": true, "doas": true, "pkexec": true}

// pipelineShellKeywords may precede a command inside a compound statement.
var pipelineShellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "while": true, "until": true,
	"do": true, "time": true, "!": true,
}

type pipelineStage struct {
	args    []string // wrappers and leading keywords removed
	unknown bool     // the executable could not be established
	fetcher string   // alias program name when the stage fetches a remote response
	url     string
	payload string // literal `sh -c` command string, analyzed as its own command
}

func (s pipelineStage) inert() bool {
	if s.unknown {
		return false
	}
	if len(s.args) == 0 {
		return true
	}
	return pipelineInertReaders[shellWrapperBasename(s.args[0])]
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

// visitPipedDownloadExecutionAliases recognizes a network fetcher whose
// response is piped into a later stage that is not a known read-only filter,
// and emits the restrictive alias `<fetcher> <url> | sh` so the existing
// download-and-execute rules apply. The alias is only ever used to deny; it is
// never a replacement command or an approval identity.
//
// It is a bounded lexical view, not a shell interpreter: here-documents are
// data and are skipped, quoted text never splits a stage, and an unclear
// executable is treated as potentially executing. Command substitutions and
// process substitutions that never form a pipeline are handled by other rules.
func visitPipedDownloadExecutionAliases(command string, visit func(string) bool) {
	if len(command) > maxGlobInputLen || !strings.Contains(command, "|") {
		return
	}
	var walk func(string, int) bool
	walk = func(command string, depth int) bool {
		if depth > 16 {
			return true
		}
		all, ok := literalShellWords(command)
		if !ok {
			return true
		}
		words := make([]literalShellWord, 0, len(all))
		for _, word := range all {
			if word.operator && strings.Contains(word.value, "<<") {
				return true // here-document contents are data
			}
			if word.operator && (word.value == "{" || word.value == "}") {
				// Brace tokens also split words such as https://host/{a,b}.sh and
				// never separate stages.
				continue
			}
			if word.operator && word.value == "(" {
				// A subshell group such as `curl x | (bash)` stays one pipeline, so
				// its opening parenthesis is dropped. Only `$(` starts a new command.
				if len(words) == 0 || words[len(words)-1].operator || words[len(words)-1].value != "$" {
					continue
				}
			}
			words = append(words, word)
		}

		var stages []pipelineStage
		evaluate := func() bool {
			defer func() { stages = nil }()
			// A shell -c payload, wherever it sits in the pipeline, is its own
			// command string.
			for _, stage := range stages {
				if stage.payload != "" && !walk(stage.payload, depth+1) {
					return false
				}
			}
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
					target := stages[first].url
					if target == "" {
						target = "URL"
					}
					return visit(stages[first].fetcher + " " + target + " | sh")
				}
			}
			return true
		}

		start := 0
		for i := 0; i <= len(words); i++ {
			if i < len(words) && !words[i].operator {
				continue
			}
			op := ""
			if i < len(words) {
				op = words[i].value
			}
			switch op {
			case "|":
				stages = append(stages, classifyPipelineStage(words[start:i]))
				start = i + 1
				if start < len(words) && words[start].operator && words[start].value == "&" {
					start++ // |& pipes stderr as well
					i++
				}
			case ";", "&&", "||", "&", "\n", "(", ")", "":
				stages = append(stages, classifyPipelineStage(words[start:i]))
				start = i + 1
				if !evaluate() {
					return false
				}
			default:
				// Redirections stay inside their stage.
			}
		}
		return true
	}
	walk(command, 0)
}
