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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check Rampart installation health",
		Long:  "Run diagnostic checks on your Rampart installation and report any issues.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.OutOrStdout())
		},
	}
}

func runDoctor(w io.Writer) error {
	fmt.Fprintln(w, "🩺 Rampart Doctor")
	fmt.Fprintln(w)

	issues := 0

	// 1. Binary version
	fmt.Fprintf(w, "✓ Version: %s (%s)\n", build.Version, runtime.Version())

	// 2. Policy files
	issues += doctorPolicies(w)

	// 3. Server running
	issues += doctorServer(w)

	// 4. Hooks installed
	issues += doctorHooks(w)

	// 5. Audit directory
	issues += doctorAudit(w)

	// 6. System info
	fmt.Fprintf(w, "✓ System: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	fmt.Fprintln(w)
	if issues == 0 {
		fmt.Fprintln(w, "No issues found.")
	} else {
		noun := "issue"
		if issues > 1 {
			noun = "issues"
		}
		fmt.Fprintf(w, "%d %s found. Run 'rampart setup' to fix hook installation.\n", issues, noun)
	}
	return nil
}

func doctorPolicies(w io.Writer) int {
	issues := 0
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}
	policyDir := filepath.Join(home, ".rampart", "policies")

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		fmt.Fprintf(w, "✗ Policy: %s (not found)\n", policyDir)
		return 1
	}

	found := false
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		found = true
		path := filepath.Join(policyDir, e.Name())
		store := engine.NewFileStore(path)
		cfg, err := store.Load()
		if err != nil {
			fmt.Fprintf(w, "✗ Policy: ~/%s (%s)\n", relHome(path, home), err)
			issues++
		} else {
			count := len(cfg.Policies)
			fmt.Fprintf(w, "✓ Policy: ~/%s (%d policies, valid)\n", relHome(path, home), count)
		}
	}
	if !found {
		fmt.Fprintf(w, "✗ Policy: no .yaml files in %s\n", policyDir)
		issues++
	}
	return issues
}

func doctorServer(w io.Writer) int {
	issues := 0
	client := &http.Client{Timeout: 2 * time.Second}

	for _, port := range []int{19090, 9090} {
		label := "serve"
		if port == 19090 {
			label = "shim"
		}
		url := fmt.Sprintf("http://localhost:%d/health", port)
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			fmt.Fprintf(w, "✓ Server: rampart %s running on :%d\n", label, port)
		} else {
			fmt.Fprintf(w, "✗ Server: not running on :%d\n", port)
			issues++
		}
	}
	return issues
}

func doctorHooks(w io.Writer) int {
	issues := 0

	// Claude Code hooks
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}
	claudeSettings := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(claudeSettings)
	if err == nil {
		// Count hook matchers
		var settings map[string]any
		if json.Unmarshal(data, &settings) == nil {
			count := countClaudeHookMatchers(settings)
			if count > 0 {
				fmt.Fprintf(w, "✓ Hooks: Claude Code (%d matchers in settings.json)\n", count)
			} else {
				fmt.Fprintln(w, "✗ Hooks: Claude Code (no Rampart hooks in settings.json)")
				issues++
			}
		} else {
			fmt.Fprintln(w, "✗ Hooks: Claude Code (invalid settings.json)")
			issues++
		}
	} else {
		fmt.Fprintln(w, "✗ Hooks: Claude Code (not installed)")
		issues++
	}

	// Cline hooks
	clineDir := filepath.Join(home, "Documents", "Cline", "Hooks")
	if entries, err := os.ReadDir(clineDir); err == nil {
		hookCount := 0
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "rampart-") {
				hookCount++
			}
		}
		if hookCount > 0 {
			fmt.Fprintf(w, "✓ Hooks: Cline (%d hook scripts)\n", hookCount)
		} else {
			fmt.Fprintln(w, "✗ Hooks: Cline (no Rampart hooks found)")
			issues++
		}
	} else {
		fmt.Fprintln(w, "✗ Hooks: Cline (not installed)")
		issues++
	}

	return issues
}

// countClaudeHookMatchers counts Rampart-related hook matchers in Claude settings.
func countClaudeHookMatchers(settings map[string]any) int {
	count := 0
	hooks, ok := settings["hooks"]
	if !ok {
		return 0
	}
	hooksMap, ok := hooks.(map[string]any)
	if !ok {
		return 0
	}
	for _, v := range hooksMap {
		arr, ok := v.([]any)
		if !ok {
			continue
		}
		for _, item := range arr {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			// Check nested hooks[].command for "rampart" (matches --remove detection)
			if innerHooks, ok := m["hooks"].([]any); ok {
				for _, h := range innerHooks {
					if hm, ok := h.(map[string]any); ok {
						if cmd, ok := hm["command"].(string); ok && strings.Contains(cmd, "rampart") {
							count++
							break
						}
					}
				}
			}
		}
	}
	return count
}

func doctorAudit(w io.Writer) int {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}
	auditDir := filepath.Join(home, ".rampart", "audit")

	entries, err := os.ReadDir(auditDir)
	if err != nil {
		fmt.Fprintf(w, "✗ Audit: %s (not found)\n", auditDir)
		return 1
	}

	// Check writable
	testFile := filepath.Join(auditDir, ".doctor-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		fmt.Fprintf(w, "✗ Audit: %s (not writable)\n", auditDir)
		return 1
	}
	os.Remove(testFile)

	// Count files and find latest
	var files []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			files = append(files, e)
		}
	}

	if len(files) == 0 {
		fmt.Fprintf(w, "✓ Audit: ~/%s (0 files)\n", relHome(auditDir, home))
		return 0
	}

	// Find latest modification time
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() > files[j].Name()
	})
	latest := ""
	if info, err := files[0].Info(); err == nil {
		latest = info.ModTime().Format("2006-01-02")
	}

	fmt.Fprintf(w, "✓ Audit: ~/%s (%d files, latest: %s)\n", relHome(auditDir, home), len(files), latest)
	return 0
}

func relHome(path, home string) string {
	if rel, err := filepath.Rel(home, path); err == nil {
		return rel
	}
	return path
}
