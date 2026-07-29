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

package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestChecksumsMatchPublishedPolicySources(t *testing.T) {
	var manifest struct {
		Policies []struct {
			Name   string `json:"name"`
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(RegistryJSON, &manifest); err != nil {
		t.Fatalf("parse embedded registry: %v", err)
	}
	if len(manifest.Policies) == 0 {
		t.Fatal("embedded registry has no policies")
	}

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	const sourcePrefix = "/peg/rampart/main/"
	seenSources := make(map[string]bool, len(manifest.Policies))
	for _, entry := range manifest.Policies {
		t.Run(entry.Name, func(t *testing.T) {
			parsed, err := url.Parse(entry.URL)
			if err != nil {
				t.Fatalf("parse source URL: %v", err)
			}
			if parsed.Scheme != "https" || parsed.Host != "raw.githubusercontent.com" || !strings.HasPrefix(parsed.Path, sourcePrefix) {
				t.Fatalf("unexpected policy source URL %q", entry.URL)
			}
			relative := strings.TrimPrefix(parsed.Path, sourcePrefix)
			if seenSources[relative] {
				t.Fatalf("duplicate registry source %q", relative)
			}
			seenSources[relative] = true
			sourcePath := filepath.Join(repoRoot, filepath.FromSlash(relative))
			if rel, err := filepath.Rel(repoRoot, sourcePath); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("policy source escapes repository: %q", relative)
			}
			content, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatalf("read source %s: %v", relative, err)
			}
			normalized := strings.ReplaceAll(string(content), "\r\n", "\n")
			sum := sha256.Sum256([]byte(normalized))
			if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
				t.Fatalf("registry checksum = %s, source checksum = %s; run `go run scripts/generate-registry.go`", entry.SHA256, got)
			}
		})
	}

	for _, pattern := range []string{"registry/policies/*.yaml", "policies/community/*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatalf("glob registry sources: %v", err)
		}
		for _, sourcePath := range matches {
			relative, err := filepath.Rel(repoRoot, sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			relative = filepath.ToSlash(relative)
			if !seenSources[relative] {
				t.Errorf("policy source %s is missing from registry.json", relative)
			}
		}
	}
}
