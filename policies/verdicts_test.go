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

// verdictsFile records commands that every installed combination asks about
// or denies. TestShippedProfileVerdicts fails when a recorded verdict changes,
// and scripts/check-verdict-loosening.sh fails a pull request that weakens or
// removes a row unless testdata/verdicts-loosened.tsv lists the change. A
// command allowed by any combination is not recorded, so the public file never
// shows which forms get through. Rows must hold on every platform; verdicts
// that depend on case folding are tested per OS in internal/engine.
const verdictsFile = "testdata/verdicts.tsv"

var updateVerdicts = flag.Bool("update-verdicts", false, "rewrite "+verdictsFile+" from current policy")

// verdictSets mirror `rampart serve` after setup: the embedded standard
// profile as primary plus the overlays installed in the policy directory.
var verdictSets = []struct {
	name     string
	overlays []string // embedded profile names, or a path under policies/
	openclaw bool
}{
	{name: "standard"},
	{name: "standard+guard", overlays: []string{"guard"}},
	{name: "openclaw+guard", overlays: []string{"openclaw", "guard"}, openclaw: true},
	{name: "standard+headless", overlays: []string{"examples/headless.yaml"}},
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

	setIndex := make(map[string]int, len(verdictSets))
	engines := make([]*engine.Engine, len(verdictSets))
	for i, set := range verdictSets {
		setIndex[set.name] = i
		engines[i] = verdictEngine(t, set.overlays)
	}
	evaluate := func(i int, command string) string {
		params := map[string]any{"command": command}
		agent := "claude-code"
		if verdictSets[i].openclaw {
			agent = "openclaw:main"
			params["rampart_integration"] = "openclaw"
		}
		call := engine.ToolCall{Agent: agent, Session: "verdicts", Tool: "exec", Params: params, Input: params}
		return engines[i].Evaluate(call).Action.String()
	}

	if *updateVerdicts {
		var updated []verdictRow
		seen := map[string]bool{}
		for _, row := range rows {
			if seen[row.command] {
				continue
			}
			seen[row.command] = true
			actions := make([]string, len(verdictSets))
			protected := true
			for i := range verdictSets {
				actions[i] = evaluate(i, row.command)
				protected = protected && blocks(actions[i])
			}
			for i, set := range verdictSets {
				if protected {
					updated = append(updated, verdictRow{set: set.name, action: actions[i], command: row.command})
				}
			}
		}
		sort.SliceStable(updated, func(i, j int) bool { return updated[i].command < updated[j].command })
		require.NoError(t, writeVerdicts(verdictsFile, updated))
		return
	}

	var changed []string
	for _, row := range rows {
		i, ok := setIndex[row.set]
		require.Truef(t, ok, "unknown profile set %q in %s", row.set, verdictsFile)
		if got := evaluate(i, row.command); got != row.action {
			changed = append(changed, fmt.Sprintf("%s: %q was %s, now %s", row.set, row.command, row.action, got))
		}
	}
	if len(changed) > 0 {
		t.Fatalf("%d recorded verdicts changed. If every change is intended, run\n"+
			"  go test ./policies -run TestShippedProfileVerdicts -update-verdicts\n"+
			"and review the diff of %s.\n%s", len(changed), verdictsFile, strings.Join(changed, "\n"))
	}
}

func verdictEngine(t *testing.T, overlays []string) *engine.Engine {
	t.Helper()
	standard, err := Profile("standard")
	require.NoError(t, err)
	dir := t.TempDir()
	for _, overlay := range overlays {
		var content []byte
		if strings.HasSuffix(overlay, ".yaml") {
			content, err = os.ReadFile(filepath.FromSlash(overlay))
		} else {
			content, err = Profile(overlay)
		}
		require.NoError(t, err)
		name := strings.TrimSuffix(filepath.Base(overlay), ".yaml") + ".yaml"
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), content, 0o600))
	}
	store := engine.NewMixedStore(engine.NewMemoryStore(standard, "embedded:standard"), dir, nil)
	eng, err := engine.New(store, nil)
	require.NoError(t, err)
	return eng
}

// blocks reports whether an action stops the call for a decision.
func blocks(action string) bool {
	return action == "deny" || action == "ask" || action == "require_approval"
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
	var b strings.Builder
	b.WriteString("# Commands every shipped combination asks about or denies. Generated; see policies/verdicts_test.go.\n")
	b.WriteString("# To add a command, append a row with any set and action, then run\n")
	b.WriteString("#   go test ./policies -run TestShippedProfileVerdicts -update-verdicts\n")
	b.WriteString("# set\taction\tcommand\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "%s\t%s\t%s\n", row.set, row.action, strconv.Quote(row.command))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
