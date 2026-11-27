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

package policies

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/require"
)

// verdictsFile records the shipped profiles' protective verdicts (watch, ask
// or deny) for a corpus of commands. TestShippedProfileVerdicts fails when any
// recorded verdict changes, and scripts/check-verdict-loosening.sh fails a pull
// request whose recorded verdicts get weaker or disappear unless
// testdata/verdicts-loosened.tsv lists the change. Allowed commands are not
// recorded: they cannot get weaker. Every row must hold on every platform, so
// commands whose verdict depends on the host's case folding are tested per OS
// in internal/engine instead.
const verdictsFile = "testdata/verdicts.tsv"

var updateVerdicts = flag.Bool("update-verdicts", false, "rewrite "+verdictsFile+" from current policy")

type verdictSet struct {
	name     string
	profiles []string // embedded profile names, or a path under policies/
	openclaw bool
}

// verdictSets are the installed combinations a release must not weaken.
var verdictSets = []verdictSet{
	{name: "standard", profiles: []string{"standard"}},
	{name: "standard+guard", profiles: []string{"standard", "guard"}},
	{name: "openclaw+guard", profiles: []string{"openclaw", "guard"}, openclaw: true},
	{name: "standard+headless", profiles: []string{"standard", "examples/headless.yaml"}},
}

type verdictRow struct {
	set     string
	action  string
	command string
}

func TestShippedProfileVerdicts(t *testing.T) {
	rows, err := readVerdicts(verdictsFile)
	require.NoError(t, err)
	require.NotEmpty(t, rows)

	engines := make(map[string]*engine.Engine, len(verdictSets))
	for _, set := range verdictSets {
		engines[set.name] = verdictEngine(t, set)
	}
	evaluate := func(set verdictSet, command string) string {
		params := map[string]any{"command": command}
		agent := "claude-code"
		if set.openclaw {
			agent = "openclaw:main"
			params["rampart_integration"] = "openclaw"
		}
		call := engine.ToolCall{Agent: agent, Session: "verdicts", Tool: "exec", Params: params, Input: params}
		return engines[set.name].Evaluate(call).Action.String()
	}

	if *updateVerdicts {
		var commands []string
		seen := map[string]bool{}
		for _, row := range rows {
			if !seen[row.command] {
				seen[row.command] = true
				commands = append(commands, row.command)
			}
		}
		var updated []verdictRow
		for _, command := range commands {
			for _, set := range verdictSets {
				if action := evaluate(set, command); verdictRank(action) > 0 {
					updated = append(updated, verdictRow{set: set.name, action: action, command: command})
				}
			}
		}
		require.NoError(t, writeVerdicts(verdictsFile, updated))
		return
	}

	known := map[string]bool{}
	for _, set := range verdictSets {
		known[set.name] = true
	}
	var changed []string
	for _, row := range rows {
		require.Truef(t, known[row.set], "unknown profile set %q in %s", row.set, verdictsFile)
		set := verdictSetNamed(row.set)
		if got := evaluate(set, row.command); got != row.action {
			changed = append(changed, fmt.Sprintf("%s: %q was %s, now %s", row.set, row.command, row.action, got))
		}
	}
	if len(changed) > 0 {
		t.Fatalf("%d recorded verdicts changed. If every change is intended, run\n"+
			"  go test ./policies -run TestShippedProfileVerdicts -update-verdicts\n"+
			"and review the diff of %s.\n%s", len(changed), verdictsFile, strings.Join(changed, "\n"))
	}
}

func verdictEngine(t *testing.T, set verdictSet) *engine.Engine {
	t.Helper()
	dir := t.TempDir()
	for i, profile := range set.profiles {
		var content []byte
		var err error
		if strings.HasSuffix(profile, ".yaml") {
			content, err = os.ReadFile(filepath.FromSlash(profile))
		} else {
			content, err = Profile(profile)
		}
		require.NoError(t, err)
		// Files load in name order; keep the listed layering.
		name := fmt.Sprintf("%02d-%s", i, strings.TrimSuffix(filepath.Base(profile), ".yaml")) + ".yaml"
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), content, 0o600))
	}
	eng, err := engine.New(engine.NewMultiStore("", dir, nil), nil)
	require.NoError(t, err)
	return eng
}

func verdictSetNamed(name string) verdictSet {
	for _, set := range verdictSets {
		if set.name == name {
			return set
		}
	}
	return verdictSet{}
}

// verdictRank orders actions by how much they restrict. It matches
// scripts/check-verdict-loosening.sh.
func verdictRank(action string) int {
	switch action {
	case "deny":
		return 3
	case "ask", "require_approval", "webhook":
		return 2
	case "watch":
		return 1
	default:
		return 0
	}
}

func readVerdicts(path string) ([]verdictRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []verdictRow
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.SplitN(text, "\t", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d: want set<TAB>action<TAB>quoted command", path, line)
		}
		command, err := strconv.Unquote(fields[2])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: command: %w", path, line, err)
		}
		rows = append(rows, verdictRow{set: fields[0], action: fields[1], command: command})
	}
	return rows, scanner.Err()
}

func writeVerdicts(path string, rows []verdictRow) error {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].command != rows[j].command {
			return rows[i].command < rows[j].command
		}
		return setIndex(rows[i].set) < setIndex(rows[j].set)
	})
	var b strings.Builder
	b.WriteString("# Protective verdicts of the shipped profiles. Generated; see policies/verdicts_test.go.\n")
	b.WriteString("# To add a command, append a row with any set and action, then run\n")
	b.WriteString("#   go test ./policies -run TestShippedProfileVerdicts -update-verdicts\n")
	b.WriteString("# set\taction\tcommand\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "%s\t%s\t%s\n", row.set, row.action, strconv.Quote(row.command))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func setIndex(name string) int {
	for i, set := range verdictSets {
		if set.name == name {
			return i
		}
	}
	return len(verdictSets)
}
