package engine

import (
	"regexp"
	"strings"
)

// Windows recursive deletes are rewritten to the portable "rm -rf <path>"
// form so the POSIX destructive rules cover PowerShell, cmd.exe and Git Bash
// spellings too. These aliases are restrictive-only: they never grant.

// mayBeWindowsDelete is a cheap prefilter for windowsDeleteOperands.
func mayBeWindowsDelete(command string) bool {
	lower := strings.ToLower(command) + " "
	for _, word := range []string{"remove-item", "ri ", "del ", "erase ", "rd ", "rmdir ", "::delete("} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// windowsDeleteOperands returns the targets of a recursive Remove-Item, ri,
// del, erase, rd, rmdir, or PowerShell rm with a backslash path. PowerShell
// does not need -Force to delete a tree, and rd /s without /q only prompts,
// so recursion alone is enough. Without recursion only a trailing wildcard
// counts.
func windowsDeleteOperands(segment string) []string {
	tokens := tokenizeForOS(segment, "powershell")
	if len(tokens) == 0 {
		return nil
	}
	base := strings.TrimSuffix(shellWrapperBasename(tokens[0]), ".exe")
	switch base {
	case "remove-item", "ri", "del", "erase", "rd", "rmdir", "rm":
	default:
		return nil
	}
	recursive := false
	operands := make([]string, 0, len(tokens))
	for index := 1; index < len(tokens); index++ {
		token := strings.ToLower(tokens[index])
		switch {
		case token == "/s" || strings.HasPrefix(token, "-r"):
			recursive = true
		case token == "-filter" || token == "-include" || token == "-exclude":
			index++ // skip the option's value
		case strings.HasPrefix(token, "-") || isCmdSwitch(token):
			// Other switches.
		case base == "rm" && !strings.Contains(token, `\`):
			// POSIX rm is handled by restrictiveRMOperands; only PowerShell's
			// rm alias with a Windows path needs this backslash-safe parse.
		default:
			operands = append(operands, tokens[index])
		}
	}
	if recursive {
		return operands
	}
	// Without recursion a wildcard still empties a folder: Remove-Item C:\*.
	var wildcards []string
	for _, operand := range operands {
		if trimmed := strings.Trim(operand, `"'`); strings.HasSuffix(trimmed, `\*`) || strings.HasSuffix(trimmed, "/*") {
			wildcards = append(wildcards, operand)
		}
	}
	return wildcards
}

// windowsPathAsPOSIX maps a Windows or Git Bash path onto the POSIX layout the
// destructive rules describe: a drive root becomes "/", the Users folder
// becomes "/home", a home variable such as $env:USERPROFILE becomes "~", and
// everything else keeps its path below "/". It returns "" when the value is
// neither.
func windowsPathAsPOSIX(value string) string {
	value = strings.Trim(value, `"'`)
	var rest string
	if home, ok := cutHomeVariable(value); ok {
		home = strings.Trim(strings.ReplaceAll(home, `\`, "/"), "/")
		if home == "" || home == "*" {
			return "~"
		}
		return "~/" + home
	}
	switch {
	case len(value) >= 2 && isASCIILetter(value[0]) && value[1] == ':':
		rest = value[2:]
	case len(value) >= 2 && value[0] == '/' && isASCIILetter(value[1]) && (len(value) == 2 || value[2] == '/'):
		rest = value[2:] // Git Bash /c/...
	default:
		return ""
	}
	rest = strings.Trim(strings.ReplaceAll(rest, `\`, "/"), "/")
	if rest == "" || rest == "*" {
		return "/"
	}
	if head, tail, _ := strings.Cut(rest, "/"); strings.EqualFold(head, "users") {
		rest = strings.TrimSuffix("home/"+tail, "/")
	}
	return "/" + rest
}

// cutHomeVariable strips a leading $env:USERPROFILE, $env:HOME, $HOME or
// %USERPROFILE% and returns the rest of the path.
func cutHomeVariable(value string) (string, bool) {
	lower := strings.ToLower(value)
	for _, prefix := range []string{"$env:userprofile", "${env:userprofile}", "$env:home", "${env:home}", "$home", "%userprofile%", "%homepath%"} {
		if strings.HasPrefix(lower, prefix) {
			rest := value[len(prefix):]
			if rest == "" || rest[0] == '\\' || rest[0] == '/' {
				return rest, true
			}
		}
	}
	return "", false
}

// isCmdSwitch reports cmd.exe switches such as /q or /a:h, as opposed to a
// POSIX absolute path such as / or /c/Users.
func isCmdSwitch(token string) bool {
	return len(token) >= 2 && token[0] == '/' && isASCIILetter(token[1]) && (len(token) == 2 || token[2] == ':')
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// pipedDeleteTargets returns the folders that "Get-ChildItem C:\ -Recurse |
// Remove-Item" deletes: whatever a listing passes to a remover that names no
// path of its own.
func pipedDeleteTargets(segments []string) []string {
	var listed, targets []string
	for _, segment := range segments {
		tokens := tokenizeForOS(segment, "powershell")
		if len(tokens) == 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSuffix(shellWrapperBasename(tokens[0]), ".exe")) {
		case "get-childitem", "gci", "ls", "dir", "get-item", "gi":
			listed = powerShellPathOperands(tokens[1:])
			if len(listed) == 0 {
				listed = []string{"."}
			}
		case "remove-item", "ri", "del", "erase", "rd", "rmdir", "rm":
			if len(powerShellPathOperands(tokens[1:])) == 0 {
				targets = append(targets, listed...)
			}
		}
	}
	return targets
}

// powerShellPathOperands returns the positional and -Path/-LiteralPath
// arguments of a PowerShell file cmdlet.
func powerShellPathOperands(args []string) []string {
	var paths []string
	for index := 0; index < len(args); index++ {
		token := strings.ToLower(args[index])
		switch {
		case token == "-path" || token == "-literalpath" || token == "-lp":
			if index+1 < len(args) {
				index++
				paths = append(paths, args[index])
			}
		case token == "-filter" || token == "-include" || token == "-exclude" || token == "-depth":
			index++ // skip the option's value
		case strings.HasPrefix(token, "-") || isCmdSwitch(token):
		default:
			paths = append(paths, args[index])
		}
	}
	return paths
}

// dotNetDeleteTargets returns the folders a [IO.Directory]::Delete call
// removes.
func dotNetDeleteTargets(segment string) []string {
	var targets []string
	for _, match := range dotNetDirectoryDelete.FindAllStringSubmatch(segment, -1) {
		targets = append(targets, match[1])
	}
	return targets
}

var dotNetDirectoryDelete = regexp.MustCompile(`(?i)\[(?:system\.)?io\.directory\]::delete\(\s*['"]([^'"]+)['"]`)

// indirectDeleteTargets returns the path-like words of a command whose
// recursive delete takes its target from somewhere other than a literal
// operand: the pipeline (gci C:\ -r | Remove-Item), a loop variable
// (for d in ~/*; do rm -rf "$d"; done) or ForEach-Object ($_.FullName).
// The delete then reaches whatever the command lists, so every path the
// command names is treated as a target, whatever the spelling. Words are
// split on PowerShell and shell separators without regard to quoting, which
// can only add candidates.
func indirectDeleteTargets(command string) []string {
	pieces := powerShellStatements(command)
	indirect, recursive := false, false
	var paths []string
	for _, piece := range pieces {
		words := strings.Fields(piece)
		for i := range words {
			words[i] = strings.Trim(words[i], "\"'`,")
			lower := strings.ToLower(words[i])
			if lower == "/s" || strings.HasPrefix(lower, "-r") ||
				(len(lower) > 1 && lower[0] == '-' && lower[1] != '-' && strings.Contains(lower, "r") && strings.Trim(lower[1:], "rf") == "") {
				recursive = true
			}
			if isPathWord(words[i]) {
				paths = append(paths, words[i])
			}
		}
		if !indirect && deleteTakesIndirectTarget(words) {
			indirect = true
		}
	}
	if !indirect || !recursive {
		return nil
	}
	return paths
}

// powerShellStatements splits a command on PowerShell and shell statement,
// pipeline and block separators, ignoring quotes and backslashes.
func powerShellStatements(command string) []string {
	return strings.FieldsFunc(command, func(r rune) bool {
		return r == ';' || r == '|' || r == '&' || r == '\n' || r == '{' || r == '}' || r == '(' || r == ')'
	})
}

// deleteTakesIndirectTarget reports a delete command, after loop and launcher
// keywords, that names no literal target: no operand at all (pipeline input)
// or one that is a variable.
func deleteTakesIndirectTarget(words []string) bool {
	start := 0
	for start < len(words) && (isLoopOrLauncherWord(strings.ToLower(words[start])) ||
		(start > 0 && strings.HasPrefix(words[start], "-"))) {
		start++ // keywords, and launcher flags such as xargs -0
	}
	if start == len(words) {
		return false
	}
	switch strings.TrimSuffix(strings.ToLower(shellWrapperBasename(words[start])), ".exe") {
	case "rm", "remove-item", "ri", "del", "erase", "rd", "rmdir":
	default:
		return false
	}
	literal := false
	for index := start + 1; index < len(words); index++ {
		lower := strings.ToLower(words[index])
		switch {
		case lower == "--":
		case lower == "-filter" || lower == "-include" || lower == "-exclude":
			index++
		case strings.HasPrefix(lower, "$") || strings.HasPrefix(lower, "%") || strings.HasPrefix(lower, "@"):
			return true
		case strings.HasPrefix(lower, "-") || isCmdSwitch(lower):
		default:
			literal = true
		}
	}
	return !literal
}

func isLoopOrLauncherWord(word string) bool {
	switch word {
	case "do", "then", "else", "try", "xargs", "sudo", "command", "exec", "%", "foreach-object", "foreach":
		return true
	}
	return false
}

// isPathWord reports a word that names a filesystem location: absolute,
// home-relative, a home variable, a drive path, or any word with a slash.
func isPathWord(word string) bool {
	if word == "" || strings.HasPrefix(word, "-") || strings.HasPrefix(word, "$_") {
		return false
	}
	if _, ok := cutHomeVariable(word); ok {
		return true
	}
	return word[0] == '/' || word[0] == '~' || windowsPathAsPOSIX(word) != "" || strings.ContainsAny(word, `/\`)
}
