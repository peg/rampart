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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/filetxn"
	"github.com/spf13/cobra"
)

const (
	policySyncStateFileName = "sync-state.json"
	policySyncPolicyName    = "org-sync.yaml"
)

var (
	policySyncLookPath = exec.LookPath
	policySyncRunGit   = runPolicySyncGit
	policySyncNow      = func() time.Time { return time.Now().UTC() }
	policySyncWrite    = atomicWritePrivateFile
)

type syncState struct {
	GitURL        string    `json:"git_url,omitempty"`
	LastCommitSHA string    `json:"last_commit_sha,omitempty"`
	LastSyncTime  time.Time `json:"last_sync_time,omitempty"`
}

type syncResult struct {
	CommitSHA     string
	PolicyChanged bool
	SyncedAt      time.Time
}

func newPolicySyncCmd(_ *rootOptions) *cobra.Command {
	var (
		watch    bool
		interval time.Duration
	)

	cmd := &cobra.Command{
		Use:   "sync <git-url>",
		Short: "Sync policies from a git repository",
		Long: `Sync a Rampart policy file from a git repository.

Requirements:
  - git must be installed and in PATH
  - URL must use HTTPS (git://, ssh://, and file:// are not supported)
  - Repository must be publicly accessible (no authentication)

Rampart checks for policy files in this order:
  1. rampart.yaml
  2. policy.yaml
  3. .rampart/policy.yaml

Synced policy is written to ~/.rampart/policies/org-sync.yaml and state is
stored at ~/.rampart/sync-state.json.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			url, err := resolvePolicySyncURL(args)
			if err != nil {
				return err
			}

			result, err := performPolicySync(cmd.Context(), url)
			if err != nil {
				return err
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s commit=%s policy_changed=%t\n", result.SyncedAt.Format(time.RFC3339), result.CommitSHA, result.PolicyChanged); err != nil {
				return fmt.Errorf("policy: write sync output: %w", err)
			}

			if !watch {
				return nil
			}

			if interval <= 0 {
				return fmt.Errorf("policy: --interval must be greater than 0")
			}

			for {
				select {
				case <-cmd.Context().Done():
					return nil
				case <-time.After(interval):
				}

				result, err := performPolicySync(cmd.Context(), url)
				if err != nil {
					return err
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s commit=%s policy_changed=%t\n", result.SyncedAt.Format(time.RFC3339), result.CommitSHA, result.PolicyChanged); err != nil {
					return fmt.Errorf("policy: write sync output: %w", err)
				}
			}
		},
	}

	cmd.Flags().BoolVar(&watch, "watch", false, "Poll for policy updates in the foreground")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "How often to poll for changes when using --watch (default: 5m)")

	cmd.AddCommand(newPolicySyncStatusCmd())
	cmd.AddCommand(newPolicySyncStopCmd())

	return cmd
}

func newPolicySyncStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show policy sync status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := loadPolicySyncState()
			if err != nil {
				return err
			}

			displayURL := policySyncURLForDisplay(state.GitURL)
			if strings.TrimSpace(displayURL) == "" {
				displayURL = "(not configured)"
			}

			lastSync := "(never)"
			if !state.LastSyncTime.IsZero() {
				lastSync = state.LastSyncTime.UTC().Format(time.RFC3339)
			}

			sha := state.LastCommitSHA
			if strings.TrimSpace(sha) == "" {
				sha = "(unknown)"
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Git URL: %s\nLast sync: %s\nLast commit: %s\n", displayURL, lastSync, sha); err != nil {
				return fmt.Errorf("policy: write sync status output: %w", err)
			}
			return nil
		},
	}
}

func newPolicySyncStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop policy sync by removing configured URL",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := loadPolicySyncState()
			if err != nil {
				return err
			}
			state.GitURL = ""
			if err := savePolicySyncState(state); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Policy sync URL removed."); err != nil {
				return fmt.Errorf("policy: write sync stop output: %w", err)
			}
			return nil
		},
	}
}

func resolvePolicySyncURL(args []string) (string, error) {
	if len(args) > 0 {
		url := strings.TrimSpace(args[0])
		if err := validatePolicySyncURL(url); err != nil {
			return "", err
		}
		return url, nil
	}

	state, err := loadPolicySyncState()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(state.GitURL) == "" {
		return "", fmt.Errorf("policy: git URL is required (use: rampart policy sync <https-url>)")
	}
	if err := validatePolicySyncURL(state.GitURL); err != nil {
		return "", err
	}
	return state.GitURL, nil
}

func validatePolicySyncURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("policy: git URL cannot be empty")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("policy: only HTTPS git URLs are supported")
	}
	if parsed.Opaque != "" {
		return fmt.Errorf("policy: opaque policy sync URLs are not supported")
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("policy: only HTTPS git URLs are supported")
	}
	if parsed.User != nil {
		return fmt.Errorf("policy: credentials are not allowed in policy sync URLs; use a public HTTPS repository")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return fmt.Errorf("policy: URL queries are not supported; use a public HTTPS repository without credentials")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("policy: URL fragments are not supported")
	}
	return nil
}

func policySyncURLForDisplay(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.Opaque != "" {
		return "(invalid configured URL)"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

func performPolicySync(ctx context.Context, url string) (syncResult, error) {
	if _, err := policySyncLookPath("git"); err != nil {
		return syncResult{}, fmt.Errorf("policy: git is required but was not found in PATH")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return syncResult{}, fmt.Errorf("policy: resolve home directory: %w", err)
	}

	repoPath := filepath.Join(home, ".rampart", "sync-repo")
	statePath, err := policySyncStatePath()
	if err != nil {
		return syncResult{}, fmt.Errorf("policy: resolve sync state path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return syncResult{}, fmt.Errorf("policy: create sync state directory: %w", err)
	}
	destPolicyPath := filepath.Join(home, ".rampart", "policies", policySyncPolicyName)

	var result syncResult
	if err := filetxn.WithLock(statePath, func() error {
		// The checkout is shared by manual and --watch syncs. Keep repository
		// mutation, policy reading, HEAD resolution, and activation in one
		// transaction so contents can never be attributed to another sync's SHA.
		if err := syncRepo(ctx, url, repoPath); err != nil {
			return err
		}

		srcPolicyPath, err := findPolicySyncSource(repoPath)
		if err != nil {
			return err
		}
		srcPolicyData, err := os.ReadFile(srcPolicyPath)
		if err != nil {
			return fmt.Errorf("policy: read policy from repository: %w", err)
		}
		if _, err := engine.NewMemoryStore(srcPolicyData, "policy-sync:"+srcPolicyPath).Load(); err != nil {
			return fmt.Errorf("policy: remote policy failed validation: %w", err)
		}

		sha, err := policySyncRunGit(ctx, "-C", repoPath, "rev-parse", "HEAD")
		if err != nil {
			return err
		}

		activated, activateErr := activatePolicySync(
			url,
			strings.TrimSpace(sha),
			policySyncNow(),
			srcPolicyData,
			destPolicyPath,
			statePath,
		)
		result = activated
		return activateErr
	}); err != nil {
		return syncResult{}, err
	}
	return result, nil
}

type policySyncFileSnapshot struct {
	exists bool
	data   []byte
}

type policySyncRollbackTarget struct {
	path     string
	snapshot policySyncFileSnapshot
}

// activatePolicySync commits state first and the policy last. The policy file
// is the live activation point: if either durable write reports an error, both
// files are restored to their prior contents before the failure is returned.
func activatePolicySync(
	gitURL string,
	commitSHA string,
	syncedAt time.Time,
	policyData []byte,
	policyPath string,
	statePath string,
) (syncResult, error) {
	policySnapshot, err := snapshotPolicySyncFile(policyPath)
	if err != nil {
		return syncResult{}, fmt.Errorf("policy: snapshot existing synced policy: %w", err)
	}
	stateSnapshot, err := snapshotPolicySyncFile(statePath)
	if err != nil {
		return syncResult{}, fmt.Errorf("policy: snapshot sync state: %w", err)
	}

	state, err := decodePolicySyncState(stateSnapshot)
	if err != nil {
		return syncResult{}, err
	}
	state.GitURL = gitURL
	state.LastCommitSHA = commitSHA
	state.LastSyncTime = syncedAt
	stateData, err := encodePolicySyncState(state)
	if err != nil {
		return syncResult{}, err
	}

	changed := !policySnapshot.exists || !bytes.Equal(policySnapshot.data, policyData)
	if err := policySyncWrite(statePath, stateData); err != nil {
		writeErr := fmt.Errorf("policy: write sync state: %w", err)
		return syncResult{}, joinPolicySyncRollback(writeErr, policySyncRollbackTarget{statePath, stateSnapshot})
	}
	if changed {
		if err := policySyncWrite(policyPath, policyData); err != nil {
			writeErr := fmt.Errorf("policy: write synced policy: %w", err)
			return syncResult{}, joinPolicySyncRollback(
				writeErr,
				policySyncRollbackTarget{policyPath, policySnapshot},
				policySyncRollbackTarget{statePath, stateSnapshot},
			)
		}
	}

	return syncResult{CommitSHA: commitSHA, PolicyChanged: changed, SyncedAt: syncedAt}, nil
}

func snapshotPolicySyncFile(path string) (policySyncFileSnapshot, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return policySyncFileSnapshot{}, nil
	}
	if err != nil {
		return policySyncFileSnapshot{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return policySyncFileSnapshot{}, fmt.Errorf("refusing non-regular or symlinked file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return policySyncFileSnapshot{}, err
	}
	return policySyncFileSnapshot{exists: true, data: data}, nil
}

func restorePolicySyncFile(path string, snapshot policySyncFileSnapshot) error {
	if snapshot.exists {
		return policySyncWrite(path, snapshot.data)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return filetxn.SyncDir(dir)
}

func joinPolicySyncRollback(cause error, targets ...policySyncRollbackTarget) error {
	var rollbackErrs []error
	for _, target := range targets {
		if err := restorePolicySyncFile(target.path, target.snapshot); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("restore %s: %w", target.path, err))
		}
	}
	if rollbackErr := errors.Join(rollbackErrs...); rollbackErr != nil {
		return errors.Join(cause, fmt.Errorf("policy: rollback sync activation: %w", rollbackErr))
	}
	return cause
}

func syncRepo(ctx context.Context, url, repoPath string) error {
	gitDir := filepath.Join(repoPath, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		remoteURL, err := policySyncRunGit(ctx, "-C", repoPath, "remote", "get-url", "origin")
		if err != nil {
			return err
		}
		if strings.TrimSpace(remoteURL) != url {
			if err := os.RemoveAll(repoPath); err != nil {
				return fmt.Errorf("policy: clear previous sync repository: %w", err)
			}
			return clonePolicyRepo(ctx, url, repoPath)
		}
		if _, err := policySyncRunGit(ctx, "-C", repoPath, "pull", "--ff-only"); err != nil {
			return err
		}
		return nil
	}
	if err := os.RemoveAll(repoPath); err != nil {
		return fmt.Errorf("policy: remove invalid sync repository: %w", err)
	}
	return clonePolicyRepo(ctx, url, repoPath)
}

func clonePolicyRepo(ctx context.Context, url, repoPath string) error {
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		return fmt.Errorf("policy: create sync repository directory: %w", err)
	}
	if _, err := policySyncRunGit(ctx, "clone", "--depth", "1", url, repoPath); err != nil {
		return err
	}
	return nil
}

func findPolicySyncSource(repoPath string) (string, error) {
	candidates := []string{
		filepath.Join(repoPath, "rampart.yaml"),
		filepath.Join(repoPath, "policy.yaml"),
		filepath.Join(repoPath, ".rampart", "policy.yaml"),
	}
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("policy: no policy file found in repository (expected rampart.yaml, policy.yaml, or .rampart/policy.yaml)")
}

func runPolicySyncGit(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return "", fmt.Errorf("policy: git command failed: git %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("policy: git command failed: git %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(string(out)), nil
}

func loadPolicySyncState() (syncState, error) {
	path, err := policySyncStatePath()
	if err != nil {
		return syncState{}, fmt.Errorf("policy: resolve sync state path: %w", err)
	}
	snapshot, err := snapshotPolicySyncFile(path)
	if err != nil {
		return syncState{}, fmt.Errorf("policy: read sync state: %w", err)
	}
	return decodePolicySyncState(snapshot)
}

func decodePolicySyncState(snapshot policySyncFileSnapshot) (syncState, error) {
	if !snapshot.exists {
		return syncState{}, nil
	}
	var state syncState
	if err := json.Unmarshal(snapshot.data, &state); err != nil {
		return syncState{}, fmt.Errorf("policy: parse sync state: %w", err)
	}
	return state, nil
}

func encodePolicySyncState(state syncState) ([]byte, error) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("policy: encode sync state: %w", err)
	}
	return append(data, '\n'), nil
}

func savePolicySyncState(state syncState) error {
	path, err := policySyncStatePath()
	if err != nil {
		return fmt.Errorf("policy: resolve sync state path: %w", err)
	}
	data, err := encodePolicySyncState(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("policy: create sync state directory: %w", err)
	}
	return filetxn.WithLock(path, func() error {
		if err := policySyncWrite(path, data); err != nil {
			return fmt.Errorf("policy: write sync state: %w", err)
		}
		return nil
	})
}

func policySyncStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".rampart", policySyncStateFileName), nil
}
