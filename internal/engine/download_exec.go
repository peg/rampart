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

// literalShellWord preserves the distinction between an operand and shell
// syntax. NormalizeCommand deliberately removes that distinction for glob
// matching, so its output cannot establish download/output operand identity.
type literalShellWord struct {
	value    string
	literal  bool
	operator bool
}

// literalShellWords is a bounded lexical view, not a shell interpreter. It
// recognizes words, redirections, separators and comments without evaluating
// expansions. The existing transparent-executor parsers are reused below.
func literalShellWords(command string) ([]literalShellWord, bool) {
	var words []literalShellWord
	var value strings.Builder
	var quote byte
	started, literal, plain := false, true, true
	flush := func() {
		if started {
			words = append(words, literalShellWord{value: value.String(), literal: literal})
			value.Reset()
			started, literal, plain = false, true, true
		}
	}
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if quote == '\'' {
			if ch == '\'' {
				quote = 0
			} else {
				value.WriteByte(ch)
			}
			continue
		}
		if ch == '\\' {
			plain = false
			if i+1 == len(command) {
				return nil, false
			}
			next := command[i+1]
			if quote == '"' && !strings.ContainsRune("$`\"\\\n", rune(next)) {
				value.WriteByte(ch)
				continue
			}
			i++
			if next != '\n' {
				value.WriteByte(next)
				started = true
			}
			continue
		}
		if ch == '$' || ch == '`' {
			literal = false
		}
		if quote == '"' {
			if ch == '"' {
				quote = 0
			} else {
				value.WriteByte(ch)
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote, started = ch, true
			plain = false
			continue
		}
		if ch == '#' && !started {
			for i < len(command) && command[i] != '\n' {
				i++
			}
			if i == len(command) {
				break
			}
			ch = '\n'
		}
		if ch == ' ' || ch == '\t' || ch == '\r' {
			flush()
			continue
		}
		if strings.ContainsRune(";&|\n<>(){}", rune(ch)) {
			prefix := ""
			if (ch == '<' || ch == '>') && started && plain && literal && isUnsignedDigits(value.String()) {
				prefix = value.String()
				value.Reset()
				started = false
			}
			flush()
			op := prefix + string(ch)
			if i+1 < len(command) {
				two := command[i : i+2]
				if two == "&&" || two == "||" || two == ">>" || two == "<<" || two == ">&" || two == "<&" || two == "&>" {
					op = prefix + two
					i++
					if i+1 < len(command) && (two == "<<" && command[i+1] == '<' || two == "&>" && command[i+1] == '>') {
						op += string(command[i+1])
						i++
					}
				}
			}
			words = append(words, literalShellWord{value: op, operator: true})
			continue
		}
		if strings.ContainsRune("*?[~", rune(ch)) {
			literal = false
		}
		value.WriteByte(ch)
		started = true
	}
	if quote != 0 {
		return nil, false
	}
	flush()
	return words, true
}

func isUnsignedDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

type literalInvocation struct {
	args         []string
	stdin        string
	stdout       string
	stdoutAppend bool
	writes       []string
}

func parseLiteralInvocation(words []literalShellWord) (literalInvocation, bool) {
	var result literalInvocation
	literal := true
	for i := 0; i < len(words); i++ {
		word := words[i]
		if !word.operator {
			if !word.literal {
				literal = false
			}
			result.args = append(result.args, word.value)
			continue
		}
		if i+1 == len(words) || words[i+1].operator {
			return result, false
		}
		i++
		if !words[i].literal {
			literal = false
			continue
		}
		switch word.value {
		case ">", "1>", "&>":
			result.writes = append(result.writes, words[i].value)
			result.stdout = words[i].value
			result.stdoutAppend = false
		case ">>", "1>>", "&>>":
			result.stdout = words[i].value
			result.stdoutAppend = true
		case "<", "0<":
			result.stdin = words[i].value
		case "2>":
			result.writes = append(result.writes, words[i].value)
		case "2>>", "2>&":
			// Stderr is not a downloaded response body.
		default:
			// Here documents, descriptor indirection and shell grammar need
			// more than literal operands; do not infer a destination from them.
			return result, false
		}
	}
	return result, literal
}

// unwrapLiteralExecutor uses the shared option-aware wrapper handling, but
// excludes cwd/environment rewriting and env -S retokenization. Those can
// change which file an identical relative spelling refers to.
func unwrapLiteralExecutor(args []string) []string {
	for len(args) > 0 {
		next := stripLeadingEnvAssignments(args)
		if len(next) == 0 {
			return nil
		}
		if shellWrapperBasename(next[0]) == "env" {
			for _, arg := range next[1:] {
				if arg == "--chdir" || strings.HasPrefix(arg, "--chdir=") || strings.HasPrefix(arg, "-C") ||
					arg == "--split-string" || strings.HasPrefix(arg, "--split-string=") || strings.HasPrefix(arg, "-S") {
					return nil
				}
			}
		}
		next = unwrapRestrictiveExecutor(next)
		if strSlicesEqual(next, args) {
			return next
		}
		args = next
	}
	return nil
}

type downloadedFile struct {
	downloader string
	url        string
	path       string
	stdout     bool
}

// visitDownloadExecutionAliases recognizes a literal downloaded file executed
// later in the same represented POSIX command. The pipeline is a restrictive
// policy equivalent, never a replacement command or an approval identity.
// No URL-to-filename guessing, filesystem access or cross-call state is used.
func visitDownloadExecutionAliases(command string, visit func(string) bool) {
	if len(command) > maxGlobInputLen || !strings.ContainsAny(command, ";&|\n") {
		return
	}
	downloads := make(map[string][]downloadedFile)
	var walk func(string, string, int) bool
	walk = func(command, cwd string, depth int) bool {
		if depth > 16 {
			return true
		}
		words, ok := literalShellWords(command)
		if !ok {
			return true
		}
		for _, word := range words {
			if word.operator && (strings.Contains(word.value, "<<") || word.value == "|" || word.value == "&" ||
				word.value == "(" || word.value == ")" || word.value == "{" || word.value == "}") {
				// Here-document contents are data. Pipelines and background jobs
				// have different process/cwd scopes from sequential commands.
				// Grouping/function definitions require execution-scope analysis.
				return true
			}
		}
		start := 0
		for end := 0; end <= len(words); end++ {
			if end < len(words) && (!words[end].operator || !strings.Contains("; && || & | \n", words[end].value)) {
				continue
			}
			inv, ok := parseLiteralInvocation(words[start:end])
			start = end + 1
			// Shell redirections apply to the outer invocation, including
			// wrappers and commands whose argument expansions are unknown.
			for _, written := range inv.writes {
				delete(downloads, literalOperandPath(written, cwd))
			}
			if !ok {
				continue
			}
			args := unwrapLiteralExecutor(inv.args)
			if len(args) == 0 {
				continue
			}
			base := shellWrapperBasename(args[0])
			switch base {
			case "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "select", "function":
				return true // Do not interpret conditional/loop bodies as top-level commands.
			}
			if base == "cd" {
				if len(args) == 2 && args[1] != "-" {
					cwd = literalOperandPath(args[1], cwd)
				} else {
					// Give an unknown directory a distinct lexical scope.
					cwd += "\x00"
				}
				continue
			}
			if payload, wrapper := literalShellPayload(args); wrapper {
				if payload != "" && !walk(payload, cwd, depth+1) {
					return false
				}
				continue
			}
			// One wget -O or a shared stdout stream can contain multiple
			// responses. Preserve every source so a later benign URL cannot
			// hide an earlier source from a restrictive domain-specific rule.
			fresh := make(map[string][]downloadedFile)
			for _, file := range invocationDownloads(args, inv.stdout) {
				file.path = literalOperandPath(file.path, cwd)
				if file.downloader == "wget" || file.stdout {
					fresh[file.path] = append(fresh[file.path], file)
				} else {
					fresh[file.path] = []downloadedFile{file} // explicit curl output replaces the file
				}
			}
			for target, files := range fresh {
				if inv.stdoutAppend && files[0].stdout {
					downloads[target] = append(downloads[target], files...)
				} else {
					downloads[target] = files
				}
			}
			operand := executedFileOperand(args, inv.stdin)
			if operand == "" {
				continue
			}
			path := literalOperandPath(operand, cwd)
			for _, file := range downloads[path] {
				if !visit(file.downloader + " " + file.url + " | sh") {
					return false
				}
			}
		}
		return true
	}
	walk(command, "", 0)
}

func literalOperandPath(value, cwd string) string {
	if !strings.HasPrefix(value, "/") && cwd != "" {
		value = cwd + "/" + value
	}
	// Remove only redundant '.' components. Collapsing '..' could conflate
	// different files when an intermediate directory is a symlink.
	parts := strings.Split(value, "/")
	cleaned := parts[:0]
	for i, part := range parts {
		if part != "." && (part != "" || i == 0) {
			cleaned = append(cleaned, part)
		}
	}
	return strings.Join(cleaned, "/")
}

func invocationDownloads(args []string, stdout string) []downloadedFile {
	if len(args) == 0 {
		return nil
	}
	base := shellWrapperBasename(args[0])
	if base != "curl" && base != "wget" {
		return nil
	}
	var outputs, urls []string
	options := true
	globoff := false
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg, "=")
			if base == "curl" && name == "--globoff" {
				globoff = true
			}
			output := base == "curl" && name == "--output" || base == "wget" && name == "--output-document"
			urlOption := base == "curl" && name == "--url"
			if output || urlOption || downloadLongOptionValue(base, name) {
				if !attached {
					if i+1 == len(args) {
						return nil
					}
					i++
					value = args[i]
				}
				if output {
					outputs = append(outputs, value)
				} else if urlOption {
					urls = append(urls, value)
				}
				continue
			}
			if !downloadLongOptionFlag(base, name) || attached {
				return nil
			}
			continue
		}
		if options && len(arg) > 1 && arg[0] == '-' {
			for j := 1; j < len(arg); j++ {
				flag := arg[j]
				if base == "curl" && flag == 'g' {
					globoff = true
				}
				output := base == "curl" && flag == 'o' || base == "wget" && flag == 'O'
				valueFlags, plainFlags := "", ""
				if base == "curl" {
					valueFlags, plainFlags = "oDHdFXATUuxebm", "fsSLIkivqgN"
				} else {
					valueFlags, plainFlags = "OoUPTtw", "qnvSc"
				}
				if strings.ContainsRune(valueFlags, rune(flag)) {
					value := arg[j+1:]
					if value == "" {
						if i+1 == len(args) {
							return nil
						}
						i++
						value = args[i]
					}
					if output {
						outputs = append(outputs, value)
					}
					break
				}
				if !strings.ContainsRune(plainFlags, rune(flag)) {
					return nil
				}
			}
			continue
		}
		urls = append(urls, arg)
	}
	var result []downloadedFile
	for i, url := range urls {
		if base == "curl" && !globoff && strings.ContainsAny(url, "{}[]") {
			continue // curl's URL/output templates need expansion, not equality
		}
		output, fromStdout := stdout, true
		if base == "wget" {
			// Wget concatenates responses to its last -O destination. Without
			// -O, redirecting stdout does not redirect the downloaded file.
			if len(outputs) == 0 {
				continue
			}
			output = outputs[len(outputs)-1]
			fromStdout = false
		} else if i < len(outputs) {
			// Curl pairs output options and URLs in their respective order.
			output = outputs[i]
			fromStdout = false
		}
		if output == "-" {
			output = stdout
			fromStdout = true
		}
		if output == "" || output == "-" {
			continue
		}
		if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
			continue
		}
		result = append(result, downloadedFile{downloader: base, url: url, path: output, stdout: fromStdout})
	}
	return result
}

func downloadLongOptionValue(base, option string) bool {
	if base == "curl" {
		switch option {
		case "--header", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--form", "--form-string", "--request", "--user", "--user-agent", "--dump-header", "--referer", "--cookie", "--cookie-jar", "--connect-timeout", "--max-time", "--retry", "--cacert", "--cert", "--proxy":
			return true
		}
	} else {
		switch option {
		case "--output-file", "--append-output", "--header", "--post-data", "--post-file", "--user", "--password", "--user-agent", "--timeout", "--tries", "--wait":
			return true
		}
	}
	return false
}

func downloadLongOptionFlag(base, option string) bool {
	if base == "curl" {
		switch option {
		case "--fail", "--fail-with-body", "--silent", "--show-error", "--location", "--head", "--include", "--insecure", "--verbose", "--globoff", "--no-buffer", "--disable":
			return true
		}
	} else {
		switch option {
		case "--quiet", "--no-verbose", "--verbose", "--server-response", "--continue", "--no-check-certificate":
			return true
		}
	}
	return false
}

func executedFileOperand(args []string, stdin string) string {
	if len(args) == 0 {
		return ""
	}
	base := shellWrapperBasename(args[0])
	if base == "." || base == "source" {
		if len(args) > 1 && args[1] != "--" {
			return args[1]
		}
		if len(args) > 2 {
			return args[2]
		}
		return ""
	}
	if isShellBinary(args[0]) {
		for i := 1; i < len(args); i++ {
			arg := args[i]
			if arg == "--" {
				if i+1 < len(args) {
					return args[i+1]
				}
				return stdin
			}
			if arg == "-o" || arg == "+o" {
				i++
				continue
			}
			if arg == "-" {
				return stdin
			}
			if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "+") {
				if hasCFlag(arg) {
					return ""
				}
				if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsRune(arg, 'n') {
					return ""
				}
				if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsRune(arg, 's') {
					return stdin
				}
				if arg == "--noprofile" || arg == "--norc" || arg == "--posix" || literalShellFlags(arg) {
					continue
				}
				return ""
			}
			return arg
		}
		return stdin
	}
	if base == "python" || base == "python3" || base == "node" || base == "ruby" || base == "perl" {
		for i := 1; i < len(args); i++ {
			arg := args[i]
			if arg == "--" && i+1 < len(args) {
				return args[i+1]
			}
			if arg == "-" {
				return stdin
			}
			// Deliberately support only flags that cannot consume or execute
			// another operand. Inline programs and module invocations are not
			// script-file execution, even when later arguments name a file.
			if arg == "-u" && (base == "python" || base == "python3") {
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return ""
			}
			return arg
		}
		return stdin
	}
	if strings.Contains(args[0], "/") {
		return args[0]
	}
	return ""
}

func literalShellPayload(args []string) (string, bool) {
	if len(args) == 0 || !isShellBinary(args[0]) {
		return "", false
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "-o" || arg == "+o" {
			if i+1 < len(args) && arg == "-o" && args[i+1] == "noexec" {
				return "", true
			}
			i++
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "--" {
			return "", false
		}
		if !strings.HasPrefix(arg, "--") && strings.ContainsRune(arg, 'n') {
			return "", true // syntax check; no commands execute
		}
		if hasCFlag(arg) {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", true
		}
	}
	return "", false
}

func literalShellFlags(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' && arg[0] != '+' {
		return false
	}
	for _, flag := range arg[1:] {
		if !strings.ContainsRune("aefhiklmnprsuvxBCDEHPT", flag) {
			return false
		}
	}
	return true
}
