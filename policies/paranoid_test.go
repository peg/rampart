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
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The dev-tools allowlist must not let an allowed reader open credentials.
func TestParanoidCredentialCommands(t *testing.T) {
	eng, err := engine.New(engine.NewFileStore("paranoid.yaml"), nil)
	require.NoError(t, err)
	for command, want := range map[string]engine.Action{
		"cat .env":                       engine.ActionDeny,
		"grep KEY app/.env":              engine.ActionDeny,
		"cat ~/.ssh/id_rsa":              engine.ActionDeny,
		`cat C:\Users\alice\.ssh\id_rsa`: engine.ActionDeny,
		"tail ~/.aws/credentials":        engine.ActionDeny,
		"cat README.md":                  engine.ActionAllow,
		"git status":                     engine.ActionAllow,
	} {
		decision := eng.Evaluate(engine.ToolCall{
			ID: "test-paranoid", Tool: "exec", Timestamp: time.Now(),
			Params: map[string]any{"command": command},
		})
		assert.Equal(t, want, decision.Action, "%s: %s", command, decision.Message)
	}
}
