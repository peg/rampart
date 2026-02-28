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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

const policyRegistryCacheFileName = "registry-cache.json"

var (
	defaultPolicyRegistryManifestURL = "https://raw.githubusercontent.com/peg/rampart-policies/main/registry.json"
	defaultPolicyRegistryHTTPClient  = &http.Client{Timeout: 10 * time.Second}
)

type policyRegistryManifest struct {
	Version   string                `json:"version"`
	UpdatedAt string                `json:"updated_at"`
	Policies  []policyRegistryEntry `json:"policies"`
}

type policyRegistryEntry struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	URL         string   `json:"url"`
	SHA256      string   `json:"sha256"`
	Version     string   `json:"version"`
	Author      string   `json:"author"`
}

type policyRegistryClient struct {
	httpClient  *http.Client
	manifestURL string
	cacheTTL    time.Duration
	now         func() time.Time
}

func newPolicyRegistryClient() *policyRegistryClient {
	return &policyRegistryClient{
		httpClient:  defaultPolicyRegistryHTTPClient,
		manifestURL: defaultPolicyRegistryManifestURL,
		cacheTTL:    time.Hour,
		now:         time.Now,
	}
}

func newPolicyListCmd(_ *rootOptions) *cobra.Command {
	var refresh bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List community policy profiles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client := newPolicyRegistryClient()
			manifest, err := client.loadManifest(cmd.Context(), refresh)
			if err != nil {
				return err
			}

			entries := make([]policyRegistryEntry, len(manifest.Policies))
			copy(entries, manifest.Policies)
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name < entries[j].Name
			})

			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "NAME\tDESCRIPTION\tTAGS"); err != nil {
				return fmt.Errorf("policy: write list header: %w", err)
			}
			for _, entry := range entries {
				tags := strings.Join(entry.Tags, ",")
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", entry.Name, entry.Description, tags); err != nil {
					return fmt.Errorf("policy: write list row: %w", err)
				}
			}
			if err := tw.Flush(); err != nil {
				return fmt.Errorf("policy: flush list output: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&refresh, "refresh", false, "Force refresh of registry cache")
	return cmd
}

func newPolicyFetchCmd(_ *rootOptions) *cobra.Command {
	var force bool
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "fetch <name>",
		Short: "Download and install a community policy profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			client := newPolicyRegistryClient()
			manifest, err := client.loadManifest(cmd.Context(), false)
			if err != nil {
				return err
			}

			entry, found := findPolicyByName(manifest, name)
			if !found {
				return fmt.Errorf("policy: policy %q not found in registry. Run 'rampart policy list' to see available policies", name)
			}

			content, err := client.downloadPolicy(cmd.Context(), entry)
			if err != nil {
				return err
			}

			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("policy: resolve home directory: %w", err)
			}
			dest := filepath.Join(home, ".rampart", "policies", entry.Name+".yaml")

			if dryRun {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Would install %q to %s\n", entry.Name, dest); err != nil {
					return fmt.Errorf("policy: write dry-run output: %w", err)
				}
				return nil
			}

			if _, err := os.Stat(dest); err == nil && !force {
				return fmt.Errorf("policy: %s already exists (use --force to overwrite)", dest)
			} else if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("policy: check destination %s: %w", dest, err)
			}

			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return fmt.Errorf("policy: create policies directory: %w", err)
			}
			if err := os.WriteFile(dest, content, 0o644); err != nil {
				return fmt.Errorf("policy: write %s: %w", dest, err)
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed %q to %s\n", entry.Name, dest); err != nil {
				return fmt.Errorf("policy: write fetch output: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing policy file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview download and install path without writing files")
	return cmd
}

func newPolicyRemoveCmd(_ *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an installed community policy profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if isBuiltInPolicyProfile(name) {
				return fmt.Errorf("policy: %q is a built-in profile and cannot be removed", name)
			}

			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("policy: resolve home directory: %w", err)
			}
			path := filepath.Join(home, ".rampart", "policies", name+".yaml")

			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("policy: %q is not installed at %s", name, path)
				}
				return fmt.Errorf("policy: remove %s: %w", path, err)
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", path); err != nil {
				return fmt.Errorf("policy: write remove output: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func isBuiltInPolicyProfile(name string) bool {
	for _, profile := range policies.ProfileNames {
		if profile == name {
			return true
		}
	}
	return false
}

func findPolicyByName(manifest *policyRegistryManifest, name string) (policyRegistryEntry, bool) {
	for _, entry := range manifest.Policies {
		if entry.Name == name {
			return entry, true
		}
	}
	return policyRegistryEntry{}, false
}

func (c *policyRegistryClient) loadManifest(ctx context.Context, refresh bool) (*policyRegistryManifest, error) {
	cachePath, err := policyRegistryCachePath()
	if err != nil {
		return nil, err
	}

	if !refresh {
		cached, ok, err := c.readFreshCachedManifest(cachePath)
		if err != nil {
			return nil, err
		}
		if ok {
			return cached, nil
		}
	}

	manifest, err := c.fetchManifest(ctx)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return nil, fmt.Errorf("policy: create cache directory: %w", err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("policy: encode registry manifest: %w", err)
	}
	if err := os.WriteFile(cachePath, data, 0o644); err != nil {
		return nil, fmt.Errorf("policy: write cache file: %w", err)
	}
	return manifest, nil
}

func (c *policyRegistryClient) readFreshCachedManifest(cachePath string) (*policyRegistryManifest, bool, error) {
	info, err := os.Stat(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("policy: stat cache file: %w", err)
	}

	if c.now().Sub(info.ModTime()) > c.cacheTTL {
		return nil, false, nil
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false, fmt.Errorf("policy: read cache file: %w", err)
	}
	manifest := &policyRegistryManifest{}
	if err := json.Unmarshal(data, manifest); err != nil {
		return nil, false, fmt.Errorf("policy: parse cache file: %w", err)
	}
	if err := validatePolicyRegistryManifest(manifest); err != nil {
		return nil, false, err
	}
	return manifest, true, nil
}

func (c *policyRegistryClient) fetchManifest(ctx context.Context) (*policyRegistryManifest, error) {
	body, err := fetchURL(ctx, c.httpClient, c.manifestURL)
	if err != nil {
		return nil, wrapNetworkFetchError("policy registry", c.manifestURL, err)
	}

	manifest := &policyRegistryManifest{}
	if err := json.Unmarshal(body, manifest); err != nil {
		return nil, fmt.Errorf("policy: parse registry manifest: %w", err)
	}
	if err := validatePolicyRegistryManifest(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func validatePolicyRegistryManifest(manifest *policyRegistryManifest) error {
	if manifest.Version != "1" {
		return fmt.Errorf("policy: unsupported registry manifest version %q", manifest.Version)
	}
	if len(manifest.Policies) == 0 {
		return nil
	}
	for _, entry := range manifest.Policies {
		if strings.TrimSpace(entry.Name) == "" {
			return fmt.Errorf("policy: registry manifest contains policy with empty name")
		}
		if strings.TrimSpace(entry.URL) == "" {
			return fmt.Errorf("policy: registry manifest policy %q has empty url", entry.Name)
		}
		if strings.TrimSpace(entry.SHA256) == "" {
			return fmt.Errorf("policy: registry manifest policy %q has empty sha256", entry.Name)
		}
	}
	return nil
}

func (c *policyRegistryClient) downloadPolicy(ctx context.Context, entry policyRegistryEntry) ([]byte, error) {
	content, err := fetchURL(ctx, c.httpClient, entry.URL)
	if err != nil {
		return nil, wrapNetworkFetchError("policy", entry.URL, err)
	}

	if err := verifyPolicySHA256(content, entry.SHA256, entry.Name); err != nil {
		return nil, err
	}
	return content, nil
}

func verifyPolicySHA256(content []byte, expectedSHA, name string) error {
	sum := sha256.Sum256(content)
	actualSHA := hex.EncodeToString(sum[:])
	if !strings.EqualFold(strings.TrimSpace(expectedSHA), actualSHA) {
		return fmt.Errorf("policy: sha256 mismatch for %q: expected %s, got %s", name, expectedSHA, actualSHA)
	}
	return nil
}

func fetchURL(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return body, nil
}

func wrapNetworkFetchError(subject, target string, err error) error {
	if isLikelyNetworkError(err) {
		return fmt.Errorf("policy: unable to reach %s at %s: %w", subject, target, err)
	}
	return fmt.Errorf("policy: fetch %s from %s: %w", subject, target, err)
}

func isLikelyNetworkError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

func policyRegistryCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("policy: resolve home directory: %w", err)
	}
	return filepath.Join(home, ".rampart", policyRegistryCacheFileName), nil
}
