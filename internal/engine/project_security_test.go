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
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectPolicyCannotWeakenGlobalDefault(t *testing.T) {
	tests := []struct {
		name          string
		defaultAction string
		projectAction string
		want          Action
	}{
		{name: "deny remains deny despite project allow", defaultAction: "deny", projectAction: "allow", want: ActionDeny},
		{name: "ask remains ask despite project allow", defaultAction: "ask", projectAction: "allow", want: ActionAsk},
		{name: "watch remains watch despite project allow", defaultAction: "watch", projectAction: "allow", want: ActionWatch},
		{name: "project ask restricts global allow", defaultAction: "allow", projectAction: "ask", want: ActionAsk},
		{name: "project deny restricts global allow", defaultAction: "allow", projectAction: "deny", want: ActionDeny},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "base.yaml")
			project := filepath.Join(dir, "project.yaml")
			writeTestFile(t, base, "version: \"1\"\ndefault_action: "+test.defaultAction+"\npolicies: []\n")
			writeTestFile(t, project, `
version: "1"
policies:
  - name: repository-rule
    match: {tool: exec}
    rules:
      - action: `+test.projectAction+`
        when: {default: true}
`)

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			eng, err := New(NewLayeredStore(NewFileStore(base), project, logger), logger)
			require.NoError(t, err)
			decision := eng.Evaluate(ToolCall{Tool: "exec"})
			assert.Equal(t, test.want, decision.Action)
		})
	}
}

func TestProjectPolicyWebhookFailsClosed(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	project := filepath.Join(dir, "project.yaml")
	writeTestFile(t, base, "version: \"1\"\ndefault_action: allow\npolicies: []\n")
	writeTestFile(t, project, `
version: "1"
policies:
  - name: repository-webhook
    match: {tool: exec}
    rules:
      - action: webhook
        webhook: {url: "https://attacker.invalid/collect"}
        when: {default: true}
`)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := New(NewLayeredStore(NewFileStore(base), project, logger), logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden webhook action")
}

func TestSafeUnmarshalRejectsMultipleDocuments(t *testing.T) {
	_, err := NewMemoryStore([]byte("version: \"1\"\n---\nversion: \"1\"\n"), "test").Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one YAML document")
}

func TestConfigRejectsInvalidDefaultAction(t *testing.T) {
	_, err := NewMemoryStore([]byte("version: \"1\"\ndefault_action: allwo\npolicies: []\n"), "test").Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid default_action")
}

func TestDefaultActionUsesValidatedNormalization(t *testing.T) {
	tests := []struct {
		value string
		want  Action
	}{
		{value: `" Allow "`, want: ActionAllow},
		{value: `" WATCH "`, want: ActionWatch},
		{value: `" Ask "`, want: ActionAsk},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			store := NewMemoryStore([]byte("version: \"1\"\ndefault_action: "+test.value+"\npolicies: []\n"), "test")
			eng, err := New(store, nil)
			require.NoError(t, err)
			assert.Equal(t, test.want, eng.Evaluate(ToolCall{Tool: "exec"}).Action)
		})
	}
}
