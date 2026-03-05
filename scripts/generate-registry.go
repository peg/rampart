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

// generate-registry reads policies/community/*.yaml, parses metadata headers,
// computes SHA256 hashes, and writes registry/registry.json.
//
// Usage:
//
//	go run scripts/generate-registry.go
//
// This script is intended to be run by CI on PRs that touch policies/community/.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type registryEntry struct {
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

type registryManifest struct {
	Version   string          `json:"version"`
	UpdatedAt string          `json:"updated_at"`
	Policies  []registryEntry `json:"policies"`
}

var metadataPattern = regexp.MustCompile(`^#\s*@(\w[\w-]*):\s*(.+)$`)

// requiredFields are the metadata fields every community policy must have.
var requiredFields = []string{"name", "description", "author", "tags", "min-rampart"}

// semverPattern validates min-rampart field format.
var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(-[\w.]+)?$`)

func main() {
	repoRoot := "."
	if len(os.Args) > 1 {
		repoRoot = os.Args[1]
	}

	communityDir := filepath.Join(repoRoot, "policies", "community")
	registryPoliciesDir := filepath.Join(repoRoot, "registry", "policies")
	outputPath := filepath.Join(repoRoot, "registry", "registry.json")

	var entries []registryEntry

	// 1. Parse first-party registry policies (registry/policies/*.yaml).
	firstPartyFiles, _ := filepath.Glob(filepath.Join(registryPoliciesDir, "*.yaml"))
	for _, path := range firstPartyFiles {
		entry, err := parseFirstPartyPolicy(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: skipping first-party policy %s: %v\n", path, err)
			continue
		}
		entries = append(entries, entry)
	}

	// 2. Parse community policies (policies/community/*.yaml).
	communityFiles, _ := filepath.Glob(filepath.Join(communityDir, "*.yaml"))
	errors := 0
	for _, path := range communityFiles {
		entry, err := parseCommunityPolicy(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", path, err)
			errors++
			continue
		}
		entries = append(entries, entry)
	}

	if errors > 0 {
		fmt.Fprintf(os.Stderr, "\n%d policy file(s) had errors\n", errors)
		os.Exit(1)
	}

	manifest := registryManifest{
		Version:   "1",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Policies:  entries,
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: marshal registry.json: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: write %s: %v\n", outputPath, err)
		os.Exit(1)
	}

	fmt.Printf("✓ Generated %s with %d policies\n", outputPath, len(entries))
}

func parseCommunityPolicy(path string) (registryEntry, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return registryEntry{}, fmt.Errorf("read file: %w", err)
	}

	metadata := parseMetadata(string(content))

	// Validate required fields.
	for _, field := range requiredFields {
		if _, ok := metadata[field]; !ok {
			return registryEntry{}, fmt.Errorf("missing required metadata field @%s", field)
		}
	}

	// Validate min-rampart format.
	if mr, ok := metadata["min-rampart"]; ok {
		if !semverPattern.MatchString(mr) {
			return registryEntry{}, fmt.Errorf("@min-rampart %q is not valid semver (expected X.Y.Z)", mr)
		}
	}

	name := metadata["name"]
	normalizedContent := strings.ReplaceAll(string(content), "\r\n", "\n")
	sum := sha256.Sum256([]byte(normalizedContent))
	sha := hex.EncodeToString(sum[:])

	tags := parseTags(metadata["tags"])

	baseName := strings.TrimSuffix(filepath.Base(path), ".yaml")
	url := fmt.Sprintf("https://raw.githubusercontent.com/peg/rampart/main/policies/community/%s.yaml", baseName)

	return registryEntry{
		Name:        name,
		Description: metadata["description"],
		Tags:        tags,
		URL:         url,
		SHA256:      sha,
		Version:     "1.0.0",
		Author:      metadata["author"],
		MinRampart:  metadata["min-rampart"],
	}, nil
}

func parseFirstPartyPolicy(path string) (registryEntry, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return registryEntry{}, fmt.Errorf("read file: %w", err)
	}

	metadata := parseMetadata(string(content))
	name := metadata["name"]
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), ".yaml")
	}

	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])

	baseName := strings.TrimSuffix(filepath.Base(path), ".yaml")
	url := fmt.Sprintf("https://raw.githubusercontent.com/peg/rampart/main/registry/policies/%s.yaml", baseName)

	desc := metadata["description"]
	if desc == "" {
		desc = "First-party policy profile"
	}

	return registryEntry{
		Name:        name,
		Description: desc,
		Tags:        parseTags(metadata["tags"]),
		URL:         url,
		SHA256:      sha,
		Version:     "1.0.0",
		Author:      metadata["author"],
	}, nil
}

func parseMetadata(content string) map[string]string {
	metadata := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") {
			// Stop at the first non-comment, non-empty line.
			if line != "" {
				break
			}
			continue
		}
		matches := metadataPattern.FindStringSubmatch(line)
		if len(matches) == 3 {
			key := strings.ToLower(strings.TrimSpace(matches[1]))
			value := strings.TrimSpace(matches[2])
			metadata[key] = value
		}
	}
	return metadata
}

func parseTags(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	tags := make([]string, 0, len(parts))
	for _, t := range parts {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}
