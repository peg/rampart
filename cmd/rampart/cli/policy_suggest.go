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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/peg/rampart/internal/detect"
)

// policySuggestion represents a detected tool → community policy mapping.
type policySuggestion struct {
	Binary     string              // detected binary name, e.g. "kubectl"
	PolicyName string              // registry policy name, e.g. "kubernetes"
	Entry      policyRegistryEntry // full registry entry for display
}

// binaryToPolicyMapping maps detected binary names to community policy names.
// One binary maps to exactly one policy. Future enhancement: support one-to-many.
var binaryToPolicyMapping = []struct {
	binary     string
	policyName string
}{
	{"kubectl", "kubernetes"},
	{"terraform", "terraform"},
	{"docker", "docker"},
	{"node", "node-python"},
	{"npm", "node-python"},
	{"python", "node-python"},
	{"python3", "node-python"},
	{"pip", "node-python"},
	{"aws", "aws-cli"},
}

// suggestPolicies returns community policies that match detected tools and are
// not already installed. It silently skips policies that cannot be found in the
// manifest or are already present on disk.
func suggestPolicies(result *detect.DetectResult, manifest *policyRegistryManifest) []policySuggestion {
	if result == nil || manifest == nil {
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	policyDir := filepath.Join(home, ".rampart", "policies")

	// Build a fast lookup for the manifest.
	byName := make(map[string]policyRegistryEntry, len(manifest.Policies))
	for _, entry := range manifest.Policies {
		byName[entry.Name] = entry
	}

	// Map detect results to booleans for quick lookup.
	detected := map[string]bool{
		"kubectl":   result.HasKubectl,
		"terraform": result.HasTerraform,
		"docker":    result.HasDocker,
		"node":      result.HasNode,
		"npm":       result.HasNode,
		"python":    result.HasPython,
		"python3":   result.HasPython,
		"pip":       result.HasPython,
		"aws":       result.HasAWSCLI,
	}

	// Deduplicate by policy name (multiple binaries may map to the same policy).
	seenPolicy := make(map[string]bool)
	var suggestions []policySuggestion

	for _, mapping := range binaryToPolicyMapping {
		if !detected[mapping.binary] {
			continue
		}
		if seenPolicy[mapping.policyName] {
			continue
		}
		seenPolicy[mapping.policyName] = true

		// Skip if already installed.
		installed := filepath.Join(policyDir, mapping.policyName+".yaml")
		if _, err := os.Stat(installed); err == nil {
			continue
		}

		entry, found := byName[mapping.policyName]
		if !found {
			continue
		}

		suggestions = append(suggestions, policySuggestion{
			Binary:     mapping.binary,
			PolicyName: mapping.policyName,
			Entry:      entry,
		})
	}

	return suggestions
}

// printPolicySuggestions prints proactive policy suggestions to the writer.
func printPolicySuggestions(w io.Writer, suggestions []policySuggestion) {
	if len(suggestions) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  We found tools in your environment with community policies:")
	for _, s := range suggestions {
		score := ""
		if s.Entry.BenchScore > 0 {
			score = fmt.Sprintf(" (%d%%)", s.Entry.BenchScore)
		}
		fmt.Fprintf(w, "  %s → rampart policy fetch %s%s\n",
			s.Binary,
			s.PolicyName,
			score,
		)
	}
	fmt.Fprintln(w)
}

// describeSuggestions returns a one-line summary for doctor output.
func describeSuggestions(suggestions []policySuggestion) string {
	if len(suggestions) == 0 {
		return ""
	}
	names := make([]string, len(suggestions))
	for i, s := range suggestions {
		names[i] = s.PolicyName
	}
	return fmt.Sprintf("community policies available for detected tools: %s", strings.Join(names, ", "))
}
