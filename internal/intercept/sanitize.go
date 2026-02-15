package intercept

import (
	"regexp"
	"strings"
)

// heredocRe matches heredoc operators and captures the delimiter.
// Handles: << EOF, << 'EOF', << "EOF", <<-EOF, <<-'EOF', <<-"EOF"
var heredocRe = regexp.MustCompile(`<<-?\s*['"]?(\w+)['"]?`)

// StripHeredocBodies removes heredoc body content from a command string,
// leaving only the command structure. This prevents false positives when
// heredoc content contains dangerous-looking patterns.
//
// Example:
//
//	Input:  "cat << 'EOF'\nrm -rf /\nEOF"
//	Output: "cat << 'EOF'\nEOF"
func StripHeredocBodies(cmd string) string {
	lines := strings.Split(cmd, "\n")
	if len(lines) <= 1 {
		return cmd
	}

	var result []string
	var heredocDelim string
	inHeredoc := false

	for _, line := range lines {
		if inHeredoc {
			trimmed := strings.TrimSpace(line)
			if trimmed == heredocDelim {
				inHeredoc = false
				result = append(result, line)
			}
			// Skip heredoc body lines
			continue
		}

		result = append(result, line)

		// Check if this line starts a heredoc
		matches := heredocRe.FindStringSubmatch(line)
		if len(matches) > 1 {
			heredocDelim = matches[1]
			inHeredoc = true
		}
	}

	return strings.Join(result, "\n")
}

// safeBinaries are commands whose quoted arguments are safe to strip
// for policy matching purposes. These commands do not execute their
// string arguments as code.
var safeBinaries = map[string]bool{
	"echo": true, "printf": true, "cat": true,
	"sed": true, "grep": true,
	"head": true, "tail": true, "tee": true,
	"logger": true,
}

// dangerousWrappers are commands that execute their string arguments.
// Quoted content must be preserved for these so policy matching still works.
var dangerousWrappers = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"python": true, "python3": true, "perl": true,
	"ruby": true, "node": true,
	"exec": true, "eval": true,
	"ssh": true, "curl": true, "wget": true,
	"nc": true, "ncat": true,
}

var (
	doubleQuoteRe = regexp.MustCompile(`"[^"]*"`)
	singleQuoteRe = regexp.MustCompile(`'[^']*'`)
)

// StripQuotedArgs replaces the content of quoted arguments with placeholders
// for safe binaries only. For dangerous wrappers (bash, sh, python, etc.),
// quoted content is preserved so policy matching can still detect attacks.
//
// Example:
//
//	echo "rm -rf /"     → echo "…"
//	bash -c "rm -rf /"  → bash -c "rm -rf /"  (preserved)
func StripQuotedArgs(cmd string) string {
	// Work on the first line only for binary detection;
	// but apply to the whole command.
	firstLine := cmd
	if idx := strings.IndexByte(cmd, '\n'); idx >= 0 {
		firstLine = cmd[:idx]
	}

	fields := strings.Fields(firstLine)
	if len(fields) == 0 {
		return cmd
	}

	bin := fields[0]
	// If it's a dangerous wrapper, never strip.
	if dangerousWrappers[bin] {
		return cmd
	}
	// Only strip for known safe binaries.
	if !safeBinaries[bin] {
		return cmd
	}

	result := doubleQuoteRe.ReplaceAllString(cmd, `"…"`)
	result = singleQuoteRe.ReplaceAllString(result, `'…'`)
	return result
}
