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
	"sync"
	"sync/atomic"
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

func TestPolicySyncSerializesSharedRepositoryAndActivation(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	origLookPath := policySyncLookPath
	origRunGit := policySyncRunGit
	t.Cleanup(func() {
		policySyncLookPath = origLookPath
		policySyncRunGit = origRunGit
	})
	policySyncLookPath = func(string) (string, error) { return "git", nil }

	var activeCalls atomic.Int32
	var cloneStarted sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	overlapped := make(chan struct{}, 1)
	policySyncRunGit = func(_ context.Context, args ...string) (string, error) {
		if activeCalls.Add(1) > 1 {
			select {
			case overlapped <- struct{}{}:
			default:
			}
		}
		defer activeCalls.Add(-1)

		switch {
		case len(args) >= 5 && args[0] == "clone":
			cloneStarted.Do(func() { close(started) })
			<-release
			repoPath := args[4]
			if err := os.MkdirAll(filepath.Join(repoPath, ".git"), 0o700); err != nil {
				return "", err
			}
			return "", os.WriteFile(filepath.Join(repoPath, "rampart.yaml"), []byte("version: \"1\"\npolicies: []\n"), 0o600)
		case len(args) >= 5 && args[0] == "-C" && args[2] == "remote" && args[3] == "get-url":
			return "https://example.com/org/policy.git", nil
		case len(args) >= 4 && args[0] == "-C" && args[2] == "pull":
			return "Already up to date.", nil
		case len(args) >= 4 && args[0] == "-C" && args[2] == "rev-parse" && args[3] == "HEAD":
			return "serialized-sha", nil
		default:
			return "", fmt.Errorf("unexpected git args: %v", args)
		}
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := performPolicySync(context.Background(), "https://example.com/org/policy.git")
		errCh <- err
	}()
	<-started
	go func() {
		_, err := performPolicySync(context.Background(), "https://example.com/org/policy.git")
		errCh <- err
	}()

	select {
	case <-overlapped:
		t.Fatal("concurrent policy sync entered the shared repository transaction")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for range 2 {
		require.NoError(t, <-errCh)
	}
	select {
	case <-overlapped:
		t.Fatal("policy sync git operations overlapped")
	default:
	}
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

	require.Error(t, validatePolicySyncURL("https://"))
	err = validatePolicySyncURL("https://token@example.com/org/policy.git")
	require.Error(t, err)
	require.Contains(t, err.Error(), "credentials")
	require.Error(t, validatePolicySyncURL("https://example.com/org/policy.git#main"))

	err = validatePolicySyncURL("https://example.com/org/policy.git?token=secret")
	require.Error(t, err)
	require.Contains(t, err.Error(), "queries")
	require.Error(t, validatePolicySyncURL("https://example.com/org/policy.git?"))

	err = validatePolicySyncURL("https:example.com/org/policy.git")
	require.Error(t, err)
	require.Contains(t, err.Error(), "opaque")
}

func TestPolicySyncURLForDisplayRedactsLegacyCredentials(t *testing.T) {
	display := policySyncURLForDisplay("https://user:secret@example.com/org/policy.git?token=legacy-secret#main")
	require.Equal(t, "https://example.com/org/policy.git", display)
	require.NotContains(t, display, "secret")
	require.NotContains(t, display, "token")
	require.Equal(t, "(invalid configured URL)", policySyncURLForDisplay("https:user:secret@example.com"))
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

func TestFindPolicySyncSourceRefusesSymlink(t *testing.T) {
	repo := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.yaml")
	require.NoError(t, os.WriteFile(target, []byte("version: \"1\"\npolicies: []\n"), 0o600))
	if err := os.Symlink(target, filepath.Join(repo, "rampart.yaml")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := findPolicySyncSource(repo)
	require.Error(t, err)
}

func TestPolicySyncRejectsInvalidRemotePolicyWithoutReplacingCurrent(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	dest := filepath.Join(home, ".rampart", "policies", policySyncPolicyName)
	require.NoError(t, os.MkdirAll(filepath.Dir(dest), 0o700))
	current := []byte("version: \"1\"\npolicies: []\n")
	require.NoError(t, os.WriteFile(dest, current, 0o600))

	origLookPath := policySyncLookPath
	origRunGit := policySyncRunGit
	t.Cleanup(func() {
		policySyncLookPath = origLookPath
		policySyncRunGit = origRunGit
	})
	policySyncLookPath = func(string) (string, error) { return "git", nil }
	policySyncRunGit = func(_ context.Context, args ...string) (string, error) {
		if len(args) >= 5 && args[0] == "clone" {
			repoPath := args[4]
			require.NoError(t, os.MkdirAll(filepath.Join(repoPath, ".git"), 0o700))
			return "", os.WriteFile(filepath.Join(repoPath, "rampart.yaml"), []byte("not: [valid"), 0o600)
		}
		return "", fmt.Errorf("unexpected git args: %v", args)
	}

	_, err := performPolicySync(context.Background(), "https://example.com/org/policy.git")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed validation")
	after, readErr := os.ReadFile(dest)
	require.NoError(t, readErr)
	require.Equal(t, current, after)
}

func TestPolicySyncHeadFailurePreservesLivePolicyAndState(t *testing.T) {
	dest, statePath, currentPolicy, currentState := preparePolicySyncTransactionTest(t, fmt.Errorf("rev-parse unavailable"))

	_, err := performPolicySync(context.Background(), "https://example.com/org/policy.git")
	require.Error(t, err)
	require.Contains(t, err.Error(), "rev-parse unavailable")
	requireFileContent(t, dest, currentPolicy)
	requireFileContent(t, statePath, currentState)
}

func TestPolicySyncStateWriteFailureAfterReplaceRollsBack(t *testing.T) {
	dest, statePath, currentPolicy, currentState := preparePolicySyncTransactionTest(t, nil)
	originalWrite := policySyncWrite
	failed := false
	policySyncWrite = func(path string, data []byte) error {
		if err := originalWrite(path, data); err != nil {
			return err
		}
		if path == statePath && !failed {
			failed = true
			return fmt.Errorf("injected post-replace state failure")
		}
		return nil
	}

	_, err := performPolicySync(context.Background(), "https://example.com/org/policy.git")
	require.Error(t, err)
	require.Contains(t, err.Error(), "post-replace state failure")
	require.True(t, failed)
	requireFileContent(t, dest, currentPolicy)
	requireFileContent(t, statePath, currentState)
}

func TestPolicySyncPolicyWriteFailureAfterReplaceRollsBackPolicyAndState(t *testing.T) {
	dest, statePath, currentPolicy, currentState := preparePolicySyncTransactionTest(t, nil)
	originalWrite := policySyncWrite
	failed := false
	policySyncWrite = func(path string, data []byte) error {
		if err := originalWrite(path, data); err != nil {
			return err
		}
		if path == dest && !failed {
			failed = true
			return fmt.Errorf("injected post-replace policy failure")
		}
		return nil
	}

	_, err := performPolicySync(context.Background(), "https://example.com/org/policy.git")
	require.Error(t, err)
	require.Contains(t, err.Error(), "post-replace policy failure")
	require.True(t, failed)
	requireFileContent(t, dest, currentPolicy)
	requireFileContent(t, statePath, currentState)
}

func TestRestorePolicySyncFileAllowsMissingParentForAbsentSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "nested", "state.json")
	require.NoError(t, restorePolicySyncFile(path, policySyncFileSnapshot{}))
}

func preparePolicySyncTransactionTest(t *testing.T, headErr error) (string, string, []byte, []byte) {
	t.Helper()
	home := t.TempDir()
	testSetHome(t, home)

	origLookPath := policySyncLookPath
	origRunGit := policySyncRunGit
	origNow := policySyncNow
	origWrite := policySyncWrite
	t.Cleanup(func() {
		policySyncLookPath = origLookPath
		policySyncRunGit = origRunGit
		policySyncNow = origNow
		policySyncWrite = origWrite
	})

	currentPolicy := []byte("version: \"1\"\ndefault_action: deny\npolicies: []\n")
	dest := filepath.Join(home, ".rampart", "policies", policySyncPolicyName)
	require.NoError(t, os.MkdirAll(filepath.Dir(dest), 0o700))
	require.NoError(t, os.WriteFile(dest, currentPolicy, 0o600))
	require.NoError(t, savePolicySyncState(syncState{
		GitURL:        "https://example.com/previous/policy.git",
		LastCommitSHA: "old-sha",
		LastSyncTime:  time.Date(2026, 2, 27, 10, 0, 0, 0, time.UTC),
	}))
	statePath := filepath.Join(home, ".rampart", policySyncStateFileName)
	currentState, err := os.ReadFile(statePath)
	require.NoError(t, err)

	policySyncLookPath = func(string) (string, error) { return "git", nil }
	policySyncNow = func() time.Time { return time.Date(2026, 2, 28, 10, 0, 0, 0, time.UTC) }
	policySyncRunGit = func(_ context.Context, args ...string) (string, error) {
		switch {
		case len(args) >= 5 && args[0] == "clone":
			repoPath := args[4]
			if err := os.MkdirAll(filepath.Join(repoPath, ".git"), 0o700); err != nil {
				return "", err
			}
			remote := []byte("version: \"1\"\ndefault_action: allow\npolicies: []\n")
			return "", os.WriteFile(filepath.Join(repoPath, "rampart.yaml"), remote, 0o600)
		case len(args) >= 4 && args[0] == "-C" && args[2] == "rev-parse" && args[3] == "HEAD":
			if headErr != nil {
				return "", headErr
			}
			return "new-sha", nil
		default:
			return "", fmt.Errorf("unexpected git args: %v", args)
		}
	}

	return dest, statePath, currentPolicy, currentState
}

func requireFileContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
