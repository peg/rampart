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

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// runPresetCLI runs `rampart policy generate preset <extraArgs...>` and returns
// the combined stdout output and any error. It never touches the real
// filesystem for policy files (use --print or --dest <tmp>).
func runPresetCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	root := NewRootCmd(context.Background(), &buf, &buf)
	root.SetArgs(append([]string{"policy", "generate", "preset"}, args...))
	err := root.Execute()
	return buf.String(), err
}

// ---------------------------------------------------------------------------
// Tests: CLI flags (no TTY required)
// ---------------------------------------------------------------------------

func TestPolicyGeneratePreset_PrintCodingAgent(t *testing.T) {
	out, err := runPresetCLI(t, "--preset", "coding-agent", "--print")
	require.NoError(t, err)
	assert.Contains(t, out, "version:")
	assert.Contains(t, out, "coding-agent")
	assert.Contains(t, out, "coding-block-credentials")
	assert.Contains(t, out, "Preset: coding-agent")
}

func TestPolicyGeneratePreset_PrintResearchAgent(t *testing.T) {
	out, err := runPresetCLI(t, "--preset", "research-agent", "--print")
	require.NoError(t, err)
	assert.Contains(t, out, "research-allow-fetch")
	assert.Contains(t, out, "research-block-writes")
}

func TestPolicyGeneratePreset_PrintCIAgent(t *testing.T) {
	out, err := runPresetCLI(t, "--preset", "ci-agent", "--print")
	require.NoError(t, err)
	assert.Contains(t, out, "ci-block-secrets")
	assert.Contains(t, out, "ci-allow-build-test")
	assert.Contains(t, out, "ci-block-network")
}

func TestPolicyGeneratePreset_PrintDevopsAgent(t *testing.T) {
	out, err := runPresetCLI(t, "--preset", "devops-agent", "--print")
	require.NoError(t, err)
	assert.Contains(t, out, "devops-approve-kubectl-write")
	assert.Contains(t, out, "devops-approve-ssh")
	assert.Contains(t, out, "ask")
}

func TestPolicyGeneratePreset_UnknownPreset(t *testing.T) {
	_, err := runPresetCLI(t, "--preset", "no-such-preset", "--print")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown preset")
}

func TestPolicyGeneratePreset_WriteFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "policy.yaml")

	_, err := runPresetCLI(t, "--preset", "coding-agent", "--dest", dest)
	require.NoError(t, err)

	data, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Contains(t, string(data), "coding-block-credentials")
	// Verify it's parseable by the engine.
	var cfg engine.Config
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	assert.Equal(t, "1", cfg.Version)
	assert.NotEmpty(t, cfg.Policies)
}

func TestPolicyGeneratePreset_WriteFileExists_NoForce(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(dest, []byte("existing"), 0o600))

	_, err := runPresetCLI(t, "--preset", "coding-agent", "--dest", dest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestPolicyGeneratePreset_WriteFileExists_Force(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(dest, []byte("existing"), 0o600))

	_, err := runPresetCLI(t, "--preset", "coding-agent", "--dest", dest, "--force")
	require.NoError(t, err)

	data, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Contains(t, string(data), "coding-block-credentials")
}

func TestPolicyGeneratePreset_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "subdir", "nested", "policy.yaml")

	_, err := runPresetCLI(t, "--preset", "ci-agent", "--dest", dest)
	require.NoError(t, err)

	data, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Contains(t, string(data), "ci-block-secrets")
}
