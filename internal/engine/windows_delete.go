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
// so recursion alone is enough.
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
	if !recursive {
		return nil
	}
	return operands
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
