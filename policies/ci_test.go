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
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCIPolicySelfModificationGlobalFlags(t *testing.T) {
	eng, err := engine.New(engine.NewFileStore("ci.yaml"), nil)
	require.NoError(t, err)

	for _, command := range []string{
		"rampart --config /tmp/x.yaml token show",
		"rampart --config=/tmp/x.yaml approve abc",
		"/usr/local/bin/rampart --config /a/b deny x",
		"rampart --verbose uninstall",
		"rampart --config /tmp/a/b.yaml allow ls",
	} {
		call := engine.ToolCall{Agent: "ci", Tool: "exec", Params: map[string]any{"command": command}}
		assert.Equal(t, engine.ActionDeny, eng.Evaluate(call).Action, command)
	}
}
