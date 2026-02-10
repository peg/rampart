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

package openclaw

import (
	"strings"
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncFromConfigStandard(t *testing.T) {
	cfg := &engine.Config{
		Version:       "1",
		DefaultAction: "allow",
		Policies: []engine.Policy{
			{
				Name:  "block-destructive",
				Match: engine.Match{Tool: engine.StringOrSlice{"exec"}},
				Rules: []engine.Rule{
					{
						Action:  "deny",
						When:    engine.Condition{CommandMatches: []string{"rm -rf /", "rm -rf ~"}},
						Message: "Destructive command blocked",
					},
				},
			},
			{
				Name:  "block-credentials",
				Match: engine.Match{Tool: engine.StringOrSlice{"read"}},
				Rules: []engine.Rule{
					{
						Action:  "deny",
						When:    engine.Condition{PathMatches: []string{"**/.ssh/id_*", "**/.env"}},
						Message: "Credential access blocked",
					},
				},
			},
		},
	}

	result := SyncFromConfig(cfg, "standard.yaml")

	assert.Equal(t, "standard", result.Profile)
	assert.Equal(t, "standard.yaml", result.SourceFile)
	require.Len(t, result.ExecDenyPatterns, 2)
	assert.Contains(t, result.ExecDenyPatterns, "rm -rf /")
	assert.Contains(t, result.ExecDenyPatterns, "rm -rf ~")
	require.Len(t, result.ReadDenyPaths, 2)
	assert.Contains(t, result.ReadDenyPaths, "**/.ssh/id_*")
}

func TestSyncFromConfigParanoid(t *testing.T) {
	cfg := &engine.Config{
		Version:       "1",
		DefaultAction: "deny",
		Policies: []engine.Policy{
			{
				Name:  "dev-tools-allowlist",
				Match: engine.Match{Tool: engine.StringOrSlice{"exec"}},
				Rules: []engine.Rule{
					{
						Action:  "allow",
						When:    engine.Condition{CommandMatches: []string{"git *", "go *", "npm *"}},
						Message: "Allowed dev tool",
					},
				},
			},
		},
	}

	result := SyncFromConfig(cfg, "paranoid.yaml")

	assert.Equal(t, "paranoid", result.Profile)
	require.Len(t, result.ExecAllowPatterns, 3)
	assert.Contains(t, result.ExecAllowPatterns, "git *")
}

func TestSyncSkipsDisabledPolicies(t *testing.T) {
	disabled := false
	cfg := &engine.Config{
		Version:       "1",
		DefaultAction: "allow",
		Policies: []engine.Policy{
			{
				Name:    "disabled-policy",
				Enabled: &disabled,
				Match:   engine.Match{Tool: engine.StringOrSlice{"exec"}},
				Rules: []engine.Rule{
					{
						Action: "deny",
						When:   engine.Condition{CommandMatches: []string{"rm -rf /"}},
					},
				},
			},
		},
	}

	result := SyncFromConfig(cfg, "test.yaml")
	assert.Empty(t, result.ExecDenyPatterns)
}

func TestFormatOpenClawConfigOutput(t *testing.T) {
	result := &SyncResult{
		Profile:          "standard",
		SourceFile:       "rampart.yaml",
		ExecDenyPatterns: []string{"rm -rf /"},
		ReadDenyPaths:    []string{"**/.env"},
	}

	output := FormatOpenClawConfig(result)
	assert.Contains(t, output, "rampart openclaw sync")
	assert.Contains(t, output, "standard profile")
	assert.Contains(t, output, "tools:")
}

func TestFormatIncludesExecApprovals(t *testing.T) {
	result := &SyncResult{
		Profile:           "paranoid",
		SourceFile:        "paranoid.yaml",
		ExecDenyPatterns:  []string{"rm -rf /"},
		ExecAllowPatterns: []string{"git *", "npm *"},
	}

	output := FormatOpenClawConfig(result)
	assert.True(t, strings.Contains(output, "exec-approvals.json"))
	assert.True(t, strings.Contains(output, "allowlist"))
	assert.True(t, strings.Contains(output, "git *"))
}
