package engine

import "strings"

// Shell expansion lets one word name a protected file without spelling it:
// "cat .en?" reads .env, and "grep -r key ." reads every file under ".".
// globOperandVariants rewrites such a command into the literal reads a rule's
// patterns can recognize. It is used only by deny/ask matching, so a variant
// that the shell would not produce can only make a restriction stricter.

const (
	maxGlobVariantPieces = 256
	maxGlobOperands      = 32
)

func matchGlobOperandFirst(patterns []string, command string, action Action) string {
	if !strings.ContainsAny(command, "*?[{|") && !strings.Contains(command, "grep") && !strings.Contains(command, "rg ") {
		return ""
	}
	variants, complete := globOperandVariants(patterns, command)
	if !complete && len(patterns) > 0 {
		return patterns[0] // An incomplete analysis must not weaken a restriction.
	}
	for _, variant := range variants {
		if matched := matchCommandFirstForAction(patterns, variant, action); matched != "" {
			return matched
		}
	}
	return ""
}

// Each variant is the command name and one expanded operand, as a reader
// reads each operand on its own.
func globOperandVariants(patterns []string, command string) ([]string, bool) {
	tokens := unwrapRestrictiveExecutor(stripLeadingEnvAssignments(tokenizeForOS(command, "posix")))
	if len(tokens) == 0 {
		return nil, true
	}
	pieces := patternNamePieces(patterns)
	seen := map[string]bool{}
	var variants []string
	add := func(operand string) {
		variant := tokens[0] + " " + operand
		if !seen[variant] {
			seen[variant] = true
			variants = append(variants, variant)
		}
	}
	// Windows wildcards match names that start with a dot, so "findstr /s
	// key *" and "Select-String -Path *" read .env files.
	dotfiles := windowsGlobReader(tokens[0])
	visited := map[string]bool{}
	for _, token := range tokens[1:] {
		if visited[token] || !strings.ContainsAny(token, "*?[{") {
			continue
		}
		if visited[token] = true; len(visited) > maxGlobOperands {
			return nil, false
		}
		cut := strings.LastIndexAny(token, "/=<") + 1
		prefix := token[:cut]
		for _, base := range expandBraces(token[cut:]) {
			if !strings.ContainsAny(base, "*?[") {
				if base != token[cut:] {
					add(prefix + base)
				}
				continue
			}
			for _, piece := range pieces {
				if dotfiles && strings.ContainsAny(piece, "*?[") {
					continue // "*.go" must not witness ".env.go"
				}
				if name, ok := globWitness(base, piece, dotfiles); ok {
					add(prefix + name)
				}
			}
		}
	}
	if includes, ok := recursiveSearch(tokens); ok {
		for _, piece := range pieces {
			name, ok := globWitness("*", piece, true)
			if ok && (len(includes) == 0 || matchAny(includes, name)) {
				add("./" + name)
			}
		}
	}
	if reader, includes, ok := pipedRecursiveRead(command); ok {
		for _, piece := range pieces {
			name, ok := globWitness("*", piece, true)
			variant := reader + " ./" + name
			if ok && (len(includes) == 0 || matchAny(includes, name)) && !seen[variant] {
				seen[variant] = true
				variants = append(variants, variant)
			}
		}
	}
	return variants, true
}

// pipedRecursiveRead reports a PowerShell pipeline such as "gci -r | sls key",
// whose reader gets every file under a folder, hidden ones included. It
// returns the reader and any -Include or -Filter globs of the listing.
func pipedRecursiveRead(command string) (string, []string, bool) {
	if !strings.Contains(command, "|") {
		return "", nil, false
	}
	recursive := false
	var includes []string
	for _, segment := range SplitCompoundCommand(command) {
		tokens := tokenizeForOS(segment, "powershell")
		if len(tokens) == 0 {
			continue
		}
		switch head := strings.ToLower(strings.TrimSuffix(shellWrapperBasename(tokens[0]), ".exe")); head {
		case "get-childitem", "gci", "ls", "dir":
			recursive, includes = false, nil
			for index := 1; index < len(tokens); index++ {
				switch token := strings.ToLower(tokens[index]); {
				case token == "-filter" || token == "-include":
					if index+1 < len(tokens) {
						index++
						includes = append(includes, strings.Split(tokens[index], ",")...)
					}
				case strings.HasPrefix(token, "-r") || token == "/s":
					recursive = true
				}
			}
		case "select-string", "sls", "get-content", "gc", "type", "cat":
			if recursive {
				return head, includes, true
			}
		}
	}
	return "", nil, false
}

// patternNamePieces returns the file-name parts of command patterns: each
// piece between spaces, slashes, "=" and "<" that starts with a literal.
func patternNamePieces(patterns []string) []string {
	seen := map[string]bool{}
	var pieces []string
	for _, pattern := range patterns {
		for _, piece := range strings.FieldsFunc(pattern, func(r rune) bool {
			return r == ' ' || r == '/' || r == '=' || r == '<'
		}) {
			if seen[piece] || strings.IndexAny(piece, "*?[") == 0 || len(pieces) >= maxGlobVariantPieces {
				continue
			}
			seen[piece] = true
			pieces = append(pieces, piece)
		}
	}
	return pieces
}

// expandBraces expands one level of "{a,b}" alternation.
func expandBraces(word string) []string {
	open := strings.IndexByte(word, '{')
	end := strings.IndexByte(word, '}')
	if open < 0 || end < open || !strings.Contains(word[open:end], ",") {
		return []string{word}
	}
	var out []string
	for _, alt := range strings.Split(word[open+1:end], ",") {
		out = append(out, word[:open]+alt+word[end+1:])
	}
	return out
}

// recursiveSearch reports whether tokens are a grep that reads a whole tree,
// or an rg told to read hidden files, and returns any --include globs.
func recursiveSearch(tokens []string) ([]string, bool) {
	head := shellWrapperBasename(tokens[0])
	if head != "grep" && head != "egrep" && head != "fgrep" && head != "rgrep" && head != "rg" {
		return nil, false
	}
	recursive := head == "rgrep"
	var includes []string
	for _, token := range tokens[1:] {
		switch {
		case token == "--":
			return includes, recursive
		case strings.HasPrefix(token, "--include="):
			includes = append(includes, strings.TrimPrefix(token, "--include="))
		case head == "rg":
			recursive = recursive || token == "--hidden" || strings.HasPrefix(token, "-uu") || token == "-."
		case token == "--recursive" || token == "--dereference-recursive" || token == "--directories=recurse":
			recursive = true
		case strings.HasPrefix(token, "-") && !strings.HasPrefix(token, "--"):
			recursive = recursive || strings.ContainsAny(token, "rR")
		}
	}
	return includes, recursive
}

// globWitness returns a file name that both segment globs match. A shell glob
// only matches a leading dot that it spells, so a hidden name needs one unless
// dotfiles is set.
func globWitness(glob, piece string, dotfiles bool) (string, bool) {
	a, okA := tokenizeDoubleStarGlob(glob)
	b, okB := tokenizeDoubleStarGlob(piece)
	if !okA || !okB || len(a)+len(b) > 128 {
		return "", false
	}
	type state struct{ i, j int }
	from := map[state]state{}
	char := map[state]rune{}
	queue := []state{{0, 0}}
	from[state{0, 0}] = state{-1, -1}
	visit := func(next, prev state, r rune) {
		if _, seen := from[next]; !seen {
			from[next], char[next] = prev, r
			queue = append(queue, next)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if s.i == len(a) && s.j == len(b) {
			var name []rune
			for ; s.i >= 0; s = from[s] {
				if r := char[s]; r != 0 {
					name = append([]rune{r}, name...)
				}
			}
			hidden := len(name) > 0 && name[0] == '.'
			if hidden && !dotfiles && (len(a) == 0 || a[0].kind != globLiteral || a[0].literal != '.') {
				return "", false
			}
			return string(name), true
		}
		starA := s.i < len(a) && isGlobStar(a[s.i])
		starB := s.j < len(b) && isGlobStar(b[s.j])
		if starA {
			visit(state{s.i + 1, s.j}, s, 0)
		}
		if starB {
			visit(state{s.i, s.j + 1}, s, 0)
		}
		if s.i == len(a) || s.j == len(b) || (starA && starB) {
			continue
		}
		r, ok := commonGlobRune(a[s.i], b[s.j])
		if !ok {
			continue
		}
		next := state{s.i + 1, s.j + 1}
		if starA {
			next.i = s.i
		}
		if starB {
			next.j = s.j
		}
		visit(next, s, r)
	}
	return "", false
}

func isGlobStar(t globToken) bool {
	return t.kind == globSingleStar || t.kind == globDoubleStar
}

func commonGlobRune(a, b globToken) (rune, bool) {
	candidates := []rune{'x', '0', '.', '-', '_'}
	for _, t := range []globToken{a, b} {
		if t.kind == globLiteral {
			candidates = append([]rune{t.literal}, candidates...)
		}
		for _, item := range t.ranges {
			candidates = append(candidates, item.lo, item.hi)
		}
	}
	for _, r := range candidates {
		if globRuneMatches(a, r) && globRuneMatches(b, r) {
			return r, true
		}
	}
	return 0, false
}

func globRuneMatches(t globToken, r rune) bool {
	switch t.kind {
	case globLiteral:
		return r == t.literal
	case globClass:
		return r != '/' && t.matchesClass(r)
	default:
		return r != '/'
	}
}

func windowsGlobReader(head string) bool {
	switch strings.TrimSuffix(shellWrapperBasename(head), ".exe") {
	case "findstr", "select-string", "sls", "get-content", "gc", "type", "more":
		return true
	}
	return false
}
