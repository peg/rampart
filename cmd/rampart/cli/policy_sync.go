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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
		Long: `Sync a Rampart policy file from a public HTTPS git repository.

Rampart checks for policy files in this order:
  1. rampart.yaml
  2. policy.yaml
  3. .rampart/policy.yaml

Synced policy is written to ~/.rampart/policies/org-sync.yaml and a state file
is stored at ~/.rampart/sync-state.json.`,
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
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "Polling interval for --watch")

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

			url := state.GitURL
			if strings.TrimSpace(url) == "" {
				url = "(not configured)"
			}

			lastSync := "(never)"
			if !state.LastSyncTime.IsZero() {
				lastSync = state.LastSyncTime.UTC().Format(time.RFC3339)
			}

			sha := state.LastCommitSHA
			if strings.TrimSpace(sha) == "" {
				sha = "(unknown)"
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Git URL: %s\nLast sync: %s\nLast commit: %s\n", url, lastSync, sha); err != nil {
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

func validatePolicySyncURL(url string) error {
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("policy: git URL cannot be empty")
	}
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return fmt.Errorf("policy: only HTTPS git URLs are supported")
	}
	return nil
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
	if err := syncRepo(ctx, url, repoPath); err != nil {
		return syncResult{}, err
	}

	srcPolicyPath, err := findPolicySyncSource(repoPath)
	if err != nil {
		return syncResult{}, err
	}
	srcPolicyData, err := os.ReadFile(srcPolicyPath)
	if err != nil {
		return syncResult{}, fmt.Errorf("policy: read policy from repository: %w", err)
	}

	destPolicyPath := filepath.Join(home, ".rampart", "policies", policySyncPolicyName)
	changed := true
	if existing, err := os.ReadFile(destPolicyPath); err == nil {
		changed = string(existing) != string(srcPolicyData)
	} else if !os.IsNotExist(err) {
		return syncResult{}, fmt.Errorf("policy: read existing synced policy: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(destPolicyPath), 0o755); err != nil {
		return syncResult{}, fmt.Errorf("policy: create policy directory: %w", err)
	}
	if err := os.WriteFile(destPolicyPath, srcPolicyData, 0o600); err != nil {
		return syncResult{}, fmt.Errorf("policy: write synced policy: %w", err)
	}

	sha, err := policySyncRunGit(ctx, "-C", repoPath, "rev-parse", "HEAD")
	if err != nil {
		return syncResult{}, err
	}

	now := policySyncNow()
	state, err := loadPolicySyncState()
	if err != nil {
		return syncResult{}, err
	}
	state.GitURL = url
	state.LastCommitSHA = strings.TrimSpace(sha)
	state.LastSyncTime = now
	if err := savePolicySyncState(state); err != nil {
		return syncResult{}, err
	}

	return syncResult{CommitSHA: state.LastCommitSHA, PolicyChanged: changed, SyncedAt: now}, nil
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
		if _, err := os.Stat(candidate); err == nil {
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
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return syncState{}, nil
		}
		return syncState{}, fmt.Errorf("policy: read sync state: %w", err)
	}
	var state syncState
	if err := json.Unmarshal(data, &state); err != nil {
		return syncState{}, fmt.Errorf("policy: parse sync state: %w", err)
	}
	return state, nil
}

func savePolicySyncState(state syncState) error {
	path, err := policySyncStatePath()
	if err != nil {
		return fmt.Errorf("policy: resolve sync state path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("policy: create sync state directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("policy: encode sync state: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("policy: write sync state: %w", err)
	}
	return nil
}

func policySyncStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".rampart", policySyncStateFileName), nil
}
