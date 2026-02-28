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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPolicySyncCopiesPolicyAndSavesState(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	origLookPath := policySyncLookPath
	origRunGit := policySyncRunGit
	origNow := policySyncNow
	t.Cleanup(func() {
		policySyncLookPath = origLookPath
		policySyncRunGit = origRunGit
		policySyncNow = origNow
	})

	now := time.Date(2026, 2, 28, 15, 0, 0, 0, time.UTC)
	policySyncNow = func() time.Time { return now }
	policySyncLookPath = func(string) (string, error) { return "git", nil }

	policySyncRunGit = func(_ context.Context, args ...string) (string, error) {
		switch {
		case len(args) >= 5 && args[0] == "clone":
			repoPath := args[4]
			if err := os.MkdirAll(repoPath, 0o755); err != nil {
				return "", err
			}
			if err := os.MkdirAll(filepath.Join(repoPath, ".git"), 0o755); err != nil {
				return "", err
			}
			return "", os.WriteFile(filepath.Join(repoPath, "rampart.yaml"), []byte("version: \"1\"\npolicies: []\n"), 0o644)
		case len(args) >= 4 && args[0] == "-C" && args[2] == "rev-parse" && args[3] == "HEAD":
			return "abc123", nil
		case len(args) >= 5 && args[0] == "-C" && args[2] == "remote" && args[3] == "get-url":
			return "https://example.com/org/policy.git", nil
		case len(args) >= 4 && args[0] == "-C" && args[2] == "pull":
			return "Already up to date.", nil
		default:
			return "", fmt.Errorf("unexpected git args: %v", args)
		}
	}

	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"policy", "sync", "https://example.com/org/policy.git"})
	require.NoError(t, root.Execute())

	syncedPolicyPath := filepath.Join(home, ".rampart", "policies", policySyncPolicyName)
	data, err := os.ReadFile(syncedPolicyPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "version: \"1\"")

	statePath := filepath.Join(home, ".rampart", policySyncStateFileName)
	stateData, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.Contains(t, string(stateData), "https://example.com/org/policy.git")
	require.Contains(t, string(stateData), "abc123")
	require.Contains(t, string(stateData), now.Format(time.RFC3339))
	require.Contains(t, out.String(), "commit=abc123")
}

func TestPolicySyncWatchPrintsChecks(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	origLookPath := policySyncLookPath
	origRunGit := policySyncRunGit
	origNow := policySyncNow
	t.Cleanup(func() {
		policySyncLookPath = origLookPath
		policySyncRunGit = origRunGit
		policySyncNow = origNow
	})

	policySyncLookPath = func(string) (string, error) { return "git", nil }

	baseTime := time.Date(2026, 2, 28, 16, 0, 0, 0, time.UTC)
	calls := 0
	policySyncNow = func() time.Time {
		calls++
		return baseTime.Add(time.Duration(calls) * time.Minute)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cloneCount := 0
	policySyncRunGit = func(_ context.Context, args ...string) (string, error) {
		switch {
		case len(args) >= 5 && args[0] == "clone":
			cloneCount++
			repoPath := args[4]
			if err := os.MkdirAll(repoPath, 0o755); err != nil {
				return "", err
			}
			if err := os.MkdirAll(filepath.Join(repoPath, ".git"), 0o755); err != nil {
				return "", err
			}
			return "", os.WriteFile(filepath.Join(repoPath, "rampart.yaml"), []byte("version: \"1\"\npolicies: []\n"), 0o644)
		case len(args) >= 5 && args[0] == "-C" && args[2] == "remote" && args[3] == "get-url":
			return "https://example.com/org/policy.git", nil
		case len(args) >= 4 && args[0] == "-C" && args[2] == "pull":
			return "Already up to date.", nil
		case len(args) >= 4 && args[0] == "-C" && args[2] == "rev-parse" && args[3] == "HEAD":
			if calls >= 2 {
				cancel()
			}
			return "def456", nil
		default:
			return "", fmt.Errorf("unexpected git args: %v", args)
		}
	}

	var out bytes.Buffer
	root := NewRootCmd(ctx, &out, &bytes.Buffer{})
	root.SetArgs([]string{"policy", "sync", "https://example.com/org/policy.git", "--watch", "--interval", "1ms"})
	require.NoError(t, root.Execute())

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.GreaterOrEqual(t, len(lines), 2)
	require.Contains(t, lines[0], "commit=def456")
	require.Contains(t, lines[1], "commit=def456")
	require.Equal(t, 1, cloneCount)
}

func TestPolicySyncStatusAndStop(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	state := syncState{
		GitURL:        "https://example.com/org/policy.git",
		LastCommitSHA: "cafebabe",
		LastSyncTime:  time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}
	require.NoError(t, savePolicySyncState(state))

	var statusOut bytes.Buffer
	root := NewRootCmd(context.Background(), &statusOut, &bytes.Buffer{})
	root.SetArgs([]string{"policy", "sync", "status"})
	require.NoError(t, root.Execute())
	require.Contains(t, statusOut.String(), "https://example.com/org/policy.git")
	require.Contains(t, statusOut.String(), "cafebabe")

	var stopOut bytes.Buffer
	root = NewRootCmd(context.Background(), &stopOut, &bytes.Buffer{})
	root.SetArgs([]string{"policy", "sync", "stop"})
	require.NoError(t, root.Execute())
	require.Contains(t, stopOut.String(), "Policy sync URL removed")

	updated, err := loadPolicySyncState()
	require.NoError(t, err)
	require.Empty(t, updated.GitURL)
	require.Equal(t, "cafebabe", updated.LastCommitSHA)
}

func TestPolicySyncRejectsNonHTTPSURL(t *testing.T) {
	_, err := resolvePolicySyncURL([]string{"http://example.com/org/policy.git"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "only HTTPS")
}

func TestPolicySyncErrorsWhenGitMissing(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	origLookPath := policySyncLookPath
	t.Cleanup(func() {
		policySyncLookPath = origLookPath
	})

	policySyncLookPath = func(string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	_, err := performPolicySync(context.Background(), "https://example.com/org/policy.git")
	require.Error(t, err)
	require.Contains(t, err.Error(), "git is required")
}

func TestFindPolicySyncSourceOrder(t *testing.T) {
	repo := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".rampart"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "policy.yaml"), []byte("secondary"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, ".rampart", "policy.yaml"), []byte("tertiary"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "rampart.yaml"), []byte("primary"), 0o644))

	got, err := findPolicySyncSource(repo)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(repo, "rampart.yaml"), got)
}
