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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/generate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Compile-time check: ensure generate package is used (avoids import error in
// packages that only import for the side-effect of registration).
var _ = generate.Presets

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// runPresetCLI runs `rampart policy generate preset <extraArgs...>` and returns
// the combined stdout output and any error. It never touches the real
// filesystem for policy files (use --print or --dest <tmp>).
func runPresetCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	root := NewRootCmd(nil, &buf, &buf)
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

// ---------------------------------------------------------------------------
// Tests: generate.Preset (unit-level, no CLI)
// ---------------------------------------------------------------------------

func TestFindPreset_ValidIDs(t *testing.T) {
	ids := []string{"coding-agent", "research-agent", "ci-agent", "devops-agent"}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			p, err := generate.FindPreset(id)
			require.NoError(t, err)
			assert.Equal(t, id, p.ID)
			assert.NotEmpty(t, p.Description)
		})
	}
}

func TestFindPreset_InvalidID(t *testing.T) {
	_, err := generate.FindPreset("bogus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown preset")
	assert.Contains(t, err.Error(), "coding-agent")
}

func TestFindPreset_EmptyID(t *testing.T) {
	_, err := generate.FindPreset("")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests: RenderYAML produces engine-loadable YAML for every preset
// ---------------------------------------------------------------------------

func TestPreset_RenderYAML_AllPresets(t *testing.T) {
	for _, p := range generate.Presets {
		t.Run(p.ID, func(t *testing.T) {
			data, err := p.RenderYAML()
			require.NoError(t, err, "RenderYAML should not error")

			// Must be valid YAML the engine can parse.
			var cfg engine.Config
			err = yaml.Unmarshal(data, &cfg)
			require.NoError(t, err, "RenderYAML output must be valid engine Config YAML")

			assert.Equal(t, "1", cfg.Version, "version must be '1'")
			assert.NotEmpty(t, cfg.Policies, "must have at least one policy")

			// Header comment must include preset ID and description.
			assert.Contains(t, string(data), p.ID)
			assert.Contains(t, string(data), "rampart policy generate preset")
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: policy correctness — spot-check key rules
// ---------------------------------------------------------------------------

func TestCodingAgent_BlocksCredentials(t *testing.T) {
	p, _ := generate.FindPreset("coding-agent")
	data, _ := p.RenderYAML()
	assert.Contains(t, string(data), ".aws/credentials")
	assert.Contains(t, string(data), ".ssh/id_*")
	assert.Contains(t, string(data), "deny")
}

func TestResearchAgent_DeniesWrites(t *testing.T) {
	p, _ := generate.FindPreset("research-agent")
	data, _ := p.RenderYAML()
	assert.Contains(t, string(data), "research-block-writes")
	assert.Contains(t, string(data), "read-only")
}

func TestCIAgent_BlocksNetwork(t *testing.T) {
	p, _ := generate.FindPreset("ci-agent")
	data, _ := p.RenderYAML()
	assert.Contains(t, string(data), "ci-block-network")
	// Must block curl and wget.
	assert.Contains(t, string(data), "curl *")
	assert.Contains(t, string(data), "wget *")
}

func TestDevopsAgent_RequiresApprovalForKubectl(t *testing.T) {
	p, _ := generate.FindPreset("devops-agent")
	data, _ := p.RenderYAML()
	assert.Contains(t, string(data), "ask")
	assert.Contains(t, string(data), "kubectl apply *")
	assert.Contains(t, string(data), "ssh *")
}

// ---------------------------------------------------------------------------
// Tests: WriteToFile
// ---------------------------------------------------------------------------

func TestPreset_WriteToFile_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.yaml")

	p, err := generate.FindPreset("coding-agent")
	require.NoError(t, err)

	err = p.WriteToFile(dest, false)
	require.NoError(t, err)

	data, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(data), "coding-agent"))
}

func TestPreset_WriteToFile_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.yaml")
	require.NoError(t, os.WriteFile(dest, []byte("existing"), 0o600))

	p, _ := generate.FindPreset("coding-agent")
	err := p.WriteToFile(dest, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestPreset_WriteToFile_Force(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.yaml")
	require.NoError(t, os.WriteFile(dest, []byte("existing"), 0o600))

	p, _ := generate.FindPreset("ci-agent")
	err := p.WriteToFile(dest, true)
	require.NoError(t, err)

	data, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Contains(t, string(data), "ci-block-secrets")
}

func TestPreset_WriteToFile_MkdirAll(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "a", "b", "c", "policy.yaml")

	p, _ := generate.FindPreset("devops-agent")
	err := p.WriteToFile(dest, false)
	require.NoError(t, err)
	assert.FileExists(t, dest)
}
