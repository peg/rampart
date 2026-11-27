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
// or denies. TestShippedProfileVerdicts fails unless the file is exactly what
// current policy generates, and scripts/check-verdict-loosening.sh fails a pull
// request that weakens or removes a row unless testdata/verdicts-loosened.tsv
// lists the change. A command allowed by any combination is not recorded, so
// the public file never shows which forms get through. Rows must hold on every
// platform; verdicts that depend on case folding are tested per OS in
// internal/engine.
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
	{name: "openclaw", overlays: []string{"openclaw"}, openclaw: true},
	{name: "openclaw+guard", overlays: []string{"openclaw", "guard"}, openclaw: true},
	{name: "standard+headless", overlays: []string{"examples/headless.yaml"}},
}

func TestShippedProfileVerdicts(t *testing.T) {
	commands, err := readVerdictCommands(verdictsFile)
	require.NoError(t, err)
	require.NotEmpty(t, commands)

	engines := make([]*engine.Engine, len(verdictSets))
	for i, set := range verdictSets {
		engines[i] = verdictEngine(t, set.overlays)
	}
	evaluate := func(i int, command string) string {
		params := map[string]any{"command": command}
		agent := "claude-code"
		if verdictSets[i].openclaw {
			agent = "main"
			params["rampart_integration"] = "openclaw"
		}
		call := engine.ToolCall{Agent: agent, Session: "verdicts", Tool: "exec", Params: params, Input: params}
		return engines[i].Evaluate(call).Action.String()
	}

	var b strings.Builder
	b.WriteString(verdictsHeader)
	for _, command := range commands {
		actions := make([]string, len(verdictSets))
		protected := true
		for i := range verdictSets {
			actions[i] = evaluate(i, command)
			protected = protected && blocks(actions[i])
		}
		if !protected {
			continue
		}
		for i, set := range verdictSets {
			fmt.Fprintf(&b, "%s\t%s\t%s\n", set.name, actions[i], strconv.Quote(command))
		}
	}
	want := b.String()
	if *updateVerdicts {
		require.NoError(t, os.WriteFile(verdictsFile, []byte(want), 0o644))
		return
	}
	got, err := os.ReadFile(verdictsFile)
	require.NoError(t, err)
	if string(got) != want {
		t.Fatalf("%s differs from current policy (- recorded, + current). If every change is intended, run\n"+
			"  go test ./policies -run TestShippedProfileVerdicts -update-verdicts\n"+
			"and review the diff.\n%s", verdictsFile, lineDiff(string(got), want))
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

// readVerdictCommands returns the sorted, distinct commands of a verdicts file.
func readVerdictCommands(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	var commands []string
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
		if !seen[command] {
			seen[command] = true
			commands = append(commands, command)
		}
	}
	sort.Strings(commands)
	return commands, scanner.Err()
}

const verdictsHeader = "# Commands every shipped combination asks about or denies. Generated; see policies/verdicts_test.go.\n" +
	"# To add a command, append a row with any set and action, then run\n" +
	"#   go test ./policies -run TestShippedProfileVerdicts -update-verdicts\n" +
	"# set\taction\tcommand\n"

func lineDiff(got, want string) string {
	in := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, line := range strings.Split(s, "\n") {
			m[line] = true
		}
		return m
	}
	gotLines, wantLines := in(got), in(want)
	var out []string
	for _, line := range strings.Split(got, "\n") {
		if !wantLines[line] {
			out = append(out, "- "+line)
		}
	}
	for _, line := range strings.Split(want, "\n") {
		if !gotLines[line] {
			out = append(out, "+ "+line)
		}
	}
	if len(out) == 0 {
		return "rows are duplicated or out of order"
	}
	return strings.Join(out, "\n")
}
