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
	"github.com/peg/rampart/policies/community"
	"github.com/peg/rampart/registry"
	"github.com/spf13/cobra"
)

// builtInProfileDescriptions provides human-readable descriptions for each
// built-in policy profile, replacing the generic "Built-in profile" label
// in the policy list output.
var builtInProfileDescriptions = map[string]string{
	"standard":               "Balanced default policy for everyday use",
	"paranoid":               "Maximum restriction — blocks all unrecognized commands",
	"yolo":                   "Permissive — allows everything, logs only",
	"block-prompt-injection": "Blocks prompt injection attempts",
	"research-agent":         "Tuned for research and browsing workflows",
	"mcp-server":             "Policy for MCP server tool access",
}

const policyRegistryCacheFileName = "registry-cache.json"

var (
	defaultPolicyRegistryManifestURL = "https://raw.githubusercontent.com/peg/rampart/main/registry/registry.json"
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
	MinRampart  string   `json:"min_rampart,omitempty"`
	BenchScore  int      `json:"bench_score,omitempty"`
}

type policyRegistryClient struct {
	httpClient  *http.Client
	manifestURL string
	cacheTTL    time.Duration
	now         func() time.Time
	warnWriter  io.Writer // destination for warnings (defaults to os.Stderr)
}

func newPolicyRegistryClient() *policyRegistryClient {
	warnWriter := io.Writer(os.Stderr)
	registryURL := defaultPolicyRegistryManifestURL

	if os.Getenv("RAMPART_DEV") == "1" {
		if override := os.Getenv("RAMPART_REGISTRY_URL"); override != "" {
			if !strings.HasPrefix(strings.ToLower(override), "https://") {
				fmt.Fprintf(warnWriter, "WARNING: RAMPART_REGISTRY_URL=%q uses non-HTTPS scheme; ignoring override\n", override)
			} else {
				fmt.Fprintf(warnWriter, "WARNING: using custom registry URL from RAMPART_REGISTRY_URL=%q (development mode)\n", override)
				registryURL = override
			}
		}
	} else if override := os.Getenv("RAMPART_REGISTRY_URL"); override != "" {
		fmt.Fprintf(warnWriter, "WARNING: RAMPART_REGISTRY_URL is set but ignored (set RAMPART_DEV=1 to enable custom registries)\n")
	}

	return &policyRegistryClient{
		httpClient:  defaultPolicyRegistryHTTPClient,
		manifestURL: registryURL,
		cacheTTL:    time.Hour,
		now:         time.Now,
		warnWriter:  warnWriter,
	}
}

// policyListEntry is an internal type for the unified list command output.
type policyListEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Tags        string `json:"tags"`
	Source      string `json:"source,omitempty"` // "built-in" or "community" (shown in --extended mode)
	Installed   bool   `json:"installed,omitempty"` // shown in --extended mode
}

func newPolicyListCmd(_ *rootOptions) *cobra.Command {
	var refresh bool
	var jsonOut bool
	var extended bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List built-in profiles and community policies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("policy: resolve home directory: %w", err)
			}
			policyDir := filepath.Join(home, ".rampart", "policies")

			// Collect built-in profiles.
			seen := make(map[string]bool)
			var entries []policyListEntry
			for _, name := range policies.ProfileNames {
				installed := false
				if _, err := os.Stat(filepath.Join(policyDir, name+".yaml")); err == nil {
					installed = true
				}
				desc := builtInProfileDescriptions[name]
				if desc == "" {
					desc = "Built-in profile"
				}
				entries = append(entries, policyListEntry{
					Name:        name,
					Description: desc,
					Source:      "built-in",
					Installed:   installed,
				})
				seen[name] = true
			}

			// Collect community policies from registry.
			client := newPolicyRegistryClient()
			manifest, fetchErr := client.loadManifest(cmd.Context(), refresh)
			if fetchErr == nil {
				for _, entry := range manifest.Policies {
					if seen[entry.Name] {
						continue
					}
					installed := false
					if _, err := os.Stat(filepath.Join(policyDir, entry.Name+".yaml")); err == nil {
						installed = true
					}
					entries = append(entries, policyListEntry{
						Name:        entry.Name,
						Description: entry.Description,
						Tags:        strings.Join(entry.Tags, ","),
						Source:      "community",
						Installed:   installed,
					})
					seen[entry.Name] = true
				}
			}

			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name < entries[j].Name
			})

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(entries)
			}

			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			if extended {
				// Extended format: NAME | DESCRIPTION | SOURCE | INSTALLED
				if _, err := fmt.Fprintln(tw, "NAME\tDESCRIPTION\tSOURCE\tINSTALLED"); err != nil {
					return fmt.Errorf("policy: write list header: %w", err)
				}
				for _, e := range entries {
					inst := ""
					if e.Installed {
						inst = "✓"
					}
					if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Name, e.Description, e.Source, inst); err != nil {
						return fmt.Errorf("policy: write list row: %w", err)
					}
				}
			} else {
				// Default format: NAME | DESCRIPTION | TAGS (backward-compatible)
				if _, err := fmt.Fprintln(tw, "NAME\tDESCRIPTION\tTAGS"); err != nil {
					return fmt.Errorf("policy: write list header: %w", err)
				}
				for _, e := range entries {
					if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.Description, e.Tags); err != nil {
						return fmt.Errorf("policy: write list row: %w", err)
					}
				}
			}
			if err := tw.Flush(); err != nil {
				return fmt.Errorf("policy: flush list output: %w", err)
			}
			if fetchErr != nil {
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "\nNote: could not fetch community registry: %v\n", fetchErr); err != nil {
					return fmt.Errorf("policy: write list note: %w", err)
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&refresh, "refresh", false, "Force refresh of registry cache")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&extended, "extended", false, "Show extended columns (SOURCE, INSTALLED)")
	return cmd
}

func newPolicySearchCmd(_ *rootOptions) *cobra.Command {
	var tagFilter string
	var minScore int
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search community policies by name, description, or tags",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if minScore < 0 || minScore > 100 {
				return fmt.Errorf("policy: --min-score must be between 0 and 100, got %d", minScore)
			}

			query := strings.ToLower(strings.TrimSpace(args[0]))
			client := newPolicyRegistryClient()
			manifest, err := client.loadManifest(cmd.Context(), false)
			if err != nil {
				return err
			}

			var matches []policyRegistryEntry
			for _, entry := range manifest.Policies {
				if minScore > 0 && entry.BenchScore < minScore {
					continue
				}
				if tagFilter != "" {
					if !entryHasTag(entry, tagFilter) {
						continue
					}
				}
				if entryMatchesQuery(entry, query) {
					matches = append(matches, entry)
				}
			}

			sort.Slice(matches, func(i, j int) bool {
				return matches[i].BenchScore > matches[j].BenchScore
			})

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(matches)
			}

			if len(matches) == 0 {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "No policies found."); err != nil {
					return fmt.Errorf("policy: write search output: %w", err)
				}
				return nil
			}

			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "NAME\tDESCRIPTION\tTAGS\tSCORE"); err != nil {
				return fmt.Errorf("policy: write search header: %w", err)
			}
			for _, entry := range matches {
				tags := strings.Join(entry.Tags, ",")
				score := ""
				if entry.BenchScore > 0 {
					score = fmt.Sprintf("%d%%", entry.BenchScore)
				}
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", entry.Name, entry.Description, tags, score); err != nil {
					return fmt.Errorf("policy: write search row: %w", err)
				}
			}
			if err := tw.Flush(); err != nil {
				return fmt.Errorf("policy: flush search output: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&tagFilter, "tag", "", "Filter by exact tag")
	cmd.Flags().IntVar(&minScore, "min-score", 0, "Minimum bench score (0-100)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	return cmd
}

func newPolicyShowCmd(_ *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Print full YAML of a community policy (no side effects)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])

			// Check built-in profiles first.
			if isSupportedProfile(name) {
				content, err := policies.Profile(name)
				if err != nil {
					return fmt.Errorf("policy: read built-in profile %q: %w", name, err)
				}
				_, err = cmd.OutOrStdout().Write(content)
				return err
			}

			client := newPolicyRegistryClient()
			manifest, err := client.loadManifest(cmd.Context(), false)
			if err != nil {
				return err
			}

			entry, found := findPolicyByName(manifest, name)
			if !found {
				return fmt.Errorf("policy: %q not found in registry or built-in profiles. Run 'rampart policy search %s' to check", name, name)
			}

			content, err := client.downloadPolicy(cmd.Context(), entry)
			if err != nil {
				return err
			}

			_, err = cmd.OutOrStdout().Write(content)
			return err
		},
	}

	return cmd
}

// newPolicyInstallCmd is an alias for newPolicyFetchCmd. The issue spec uses
// "install" but the codebase predates that with "fetch". Both are supported.
func newPolicyInstallCmd(opts *rootOptions) *cobra.Command {
	cmd := newPolicyFetchCmd(opts)
	cmd.Use = "install <name>"
	cmd.Aliases = []string{}
	return cmd
}

// entryMatchesQuery returns true if query is a case-insensitive substring
// of the entry's name, description, or any tag.
func entryMatchesQuery(entry policyRegistryEntry, query string) bool {
	query = strings.ToLower(query)
	if strings.Contains(strings.ToLower(entry.Name), query) {
		return true
	}
	if strings.Contains(strings.ToLower(entry.Description), query) {
		return true
	}
	for _, tag := range entry.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	return false
}

// entryHasTag returns true if the entry has a tag matching the filter
// (case-insensitive exact match).
func entryHasTag(entry policyRegistryEntry, tag string) bool {
	tag = strings.ToLower(strings.TrimSpace(tag))
	for _, t := range entry.Tags {
		if strings.ToLower(strings.TrimSpace(t)) == tag {
			return true
		}
	}
	return false
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

			// Sanitize the name from the manifest (not just the user arg) to guard
			// against a compromised registry serving path-traversal names.
			if err := sanitizePolicyName(entry.Name); err != nil {
				return err
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
			if err := os.WriteFile(dest, content, 0o600); err != nil {
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
			if err := sanitizePolicyName(name); err != nil {
				return err
			}
			if isSupportedProfile(name) {
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

// sanitizePolicyName rejects names containing path separators or traversal
// sequences that could escape the ~/.rampart/policies/ directory.
func sanitizePolicyName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("policy: invalid policy name %q", name)
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return fmt.Errorf("policy: invalid policy name %q: must not contain path separators or '..'", name)
	}
	// Ensure filepath.Base agrees — catches any edge cases filepath.Join might resolve
	if filepath.Base(name) != name {
		return fmt.Errorf("policy: invalid policy name %q", name)
	}
	return nil
}

// isBuiltInPolicyProfile is removed — use isSupportedProfile from init.go instead.

func findPolicyByName(manifest *policyRegistryManifest, name string) (policyRegistryEntry, bool) {
	for _, entry := range manifest.Policies {
		if entry.Name == name {
			return entry, true
		}
	}
	return policyRegistryEntry{}, false
}

func (c *policyRegistryClient) loadManifest(ctx context.Context, refresh bool) (*policyRegistryManifest, error) {
	// Always start from the embedded registry compiled into the binary.
	// This guarantees community policies shipped with this build are never
	// lost due to stale caches or unreachable servers.
	embedded, err := loadEmbeddedManifest()
	if err != nil {
		return nil, err
	}

	cachePath, cacheErr := policyRegistryCachePath()

	// Try cache first (unless refresh is requested).
	if cacheErr == nil && !refresh {
		cached, ok, err := c.readFreshCachedManifest(cachePath)
		if err == nil && ok {
			return mergeManifests(embedded, cached), nil
		}
	}

	// Try network fetch.
	manifest, fetchErr := c.fetchManifest(ctx)
	if fetchErr == nil {
		merged := mergeManifests(embedded, manifest)
		// Cache the merged result.
		if cacheErr == nil {
			if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err == nil {
				if data, err := json.MarshalIndent(merged, "", "  "); err == nil {
					_ = os.WriteFile(cachePath, data, 0o644)
				}
			}
		}
		return merged, nil
	}

	// Both cache and network unavailable — return the embedded baseline.
	fmt.Fprintf(c.warnWriter, "Warning: using embedded registry data (network unavailable: %v)\n", fetchErr)
	return embedded, nil
}

// loadEmbeddedManifest parses the registry manifest that was compiled into
// the binary via go:embed. This is the compile-time baseline that ships with
// every build.
func loadEmbeddedManifest() (*policyRegistryManifest, error) {
	manifest := &policyRegistryManifest{}
	if err := json.Unmarshal(registry.RegistryJSON, manifest); err != nil {
		return nil, fmt.Errorf("policy: parse embedded registry manifest: %w", err)
	}
	if err := validatePolicyRegistryManifest(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

// mergeManifests returns a manifest containing all policies from both base
// and overlay. Overlay entries win when names collide. This ensures embedded
// policies are always present while network/cache data can override them.
func mergeManifests(base, overlay *policyRegistryManifest) *policyRegistryManifest {
	byName := make(map[string]policyRegistryEntry, len(base.Policies)+len(overlay.Policies))
	order := make([]string, 0, len(base.Policies)+len(overlay.Policies))

	for _, e := range base.Policies {
		byName[e.Name] = e
		order = append(order, e.Name)
	}
	for _, e := range overlay.Policies {
		if _, exists := byName[e.Name]; !exists {
			order = append(order, e.Name)
		}
		byName[e.Name] = e // overlay wins
	}

	merged := make([]policyRegistryEntry, 0, len(byName))
	for _, name := range order {
		merged = append(merged, byName[name])
	}

	result := &policyRegistryManifest{
		Version:   overlay.Version,
		UpdatedAt: overlay.UpdatedAt,
		Policies:  merged,
	}
	return result
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
		if err := sanitizePolicyName(strings.TrimSpace(entry.Name)); err != nil {
			return fmt.Errorf("policy: registry manifest contains unsafe policy name: %w", err)
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
	// Validate policy name to prevent path traversal.
	if entry.Name == "" || strings.Contains(entry.Name, "/") || strings.Contains(entry.Name, "\\") || strings.Contains(entry.Name, "..") {
		return nil, fmt.Errorf("policy: invalid policy name %q", entry.Name)
	}

	// Prefer remote download to receive upstream security fixes immediately.
	// Fall back to embedded content on network failure.
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(entry.URL)), "https://") {
		content, fetchErr := fetchURL(ctx, c.httpClient, entry.URL)
		if fetchErr == nil {
			if err := verifyPolicySHA256(content, entry.SHA256, entry.Name); err == nil {
				return content, nil
			}
			// SHA256 mismatch from remote — fall through to embedded.
			fmt.Fprintf(c.warnWriter, "Warning: remote policy %q failed SHA256 check, using embedded version\n", entry.Name)
		}
		// Network error — fall through to embedded.
	}

	// Fall back to embedded community policies.
	if content, err := community.FS.ReadFile(entry.Name + ".yaml"); err == nil {
		return content, nil
	}

	// No embedded copy and no HTTPS URL — cannot proceed.
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(entry.URL)), "https://") {
		return nil, fmt.Errorf("policy: refusing to download %q from non-HTTPS URL: %s", entry.Name, entry.URL)
	}

	return nil, fmt.Errorf("policy: unable to download or find embedded copy of %q", entry.Name)
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
