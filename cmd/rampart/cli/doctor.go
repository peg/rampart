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
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

const doctorServePort = 18275

// checkResult holds the outcome of a single doctor check for --json output.
type checkResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "ok", "warn", "fail", "info"
	Message string `json:"message"`
}

func newDoctorCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check Rampart installation health",
		Long:  "Run diagnostic checks on your Rampart installation and report any issues.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.OutOrStdout(), jsonOut)
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results as JSON")
	return cmd
}

func runDoctor(w io.Writer, jsonOut bool) error {
	var results []checkResult
	collect := jsonOut // only accumulate when --json is set
	useColor := !jsonOut && !noColor() && isTerminal(os.Stdout)

	emit := func(name, status, msg string) {
		if collect {
			results = append(results, checkResult{Name: name, Status: status, Message: msg})
			return
		}
		var icon string
		switch status {
		case "fail":
			if useColor {
				icon = colorRed + "✗" + colorReset
			} else {
				icon = "✗"
			}
		case "warn":
			if useColor {
				icon = colorYellow + "⚠" + colorReset
			} else {
				icon = "⚠"
			}
		default:
			if useColor {
				icon = colorGreen + "✓" + colorReset
			} else {
				icon = "✓"
			}
		}
		fmt.Fprintf(w, "%s %s: %s\n", icon, name, msg)
	}

	if !collect {
		fmt.Fprintln(w, "🩺 Rampart Doctor")
		fmt.Fprintln(w)
	}

	issues := 0
	warnings := 0

	// 1. Binary version
	versionMsg := fmt.Sprintf("%s (%s)", build.Version, runtime.Version())
	emit("Version", "ok", versionMsg)
	if n := doctorVersionCheck(w, collect, emit); n > 0 {
		issues += n
	}

	// 2. PATH check
	if _, err := exec.LookPath("rampart"); err != nil {
		emit("PATH", "fail", "rampart not found in PATH")
		issues++
	} else {
		emit("PATH", "ok", "rampart found in PATH")
	}

	// 3. Token check
	tokenIssues, token := doctorToken(emit)
	issues += tokenIssues

	// 4. Policy files
	issues += doctorPolicies(emit)

	// 5. Hook binary path
	issues += doctorHookBinary(emit)

	// 6. Hooks installed (claude settings + cline)
	issues += doctorHooks(emit)

	// 7. Audit directory
	issues += doctorAudit(emit)

	// 8. Server running on port 18275
	serverIssues, serveURL := doctorServer(emit)
	issues += serverIssues

	// 9. Token auth check (requires server running)
	if serveURL != "" && token != "" {
		if n := doctorTokenAuth(emit, serveURL, token); n > 0 {
			issues += n
		}
	}

	// 10. Policies via API
	if serveURL != "" && token != "" {
		if n := doctorPoliciesAPI(emit, serveURL, token); n > 0 {
			issues += n
		}
	}

	// 11. Pending approvals
	if serveURL != "" && token != "" {
		if n := doctorPending(emit, serveURL, token); n > 0 {
			warnings += n
		}
	}

	// 12. System info
	emit("System", "ok", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))

	// 13. Project policy (informational only — not a failure)
	doctorProjectPolicy(w, emit, collect)

	if collect {
		// JSON output
		issueCount := 0
		warnCount := 0
		for _, r := range results {
			switch r.Status {
			case "fail":
				issueCount++
			case "warn":
				warnCount++
			}
		}
		out := map[string]any{
			"checks":   results,
			"issues":   issueCount,
			"warnings": warnCount,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		if issueCount > 0 {
			return exitCodeError{code: 1}
		}
		return nil
	}

	fmt.Fprintln(w)
	if issues == 0 && warnings == 0 {
		fmt.Fprintln(w, "No issues found.")
	} else {
		if issues > 0 {
			noun := "issue"
			if issues > 1 {
				noun = "issues"
			}
			fmt.Fprintf(w, "%d %s found. Run 'rampart setup' to fix hook installation.\n", issues, noun)
		}
		if warnings > 0 {
			fmt.Fprintf(w, "%d warning(s) — not blocking but worth reviewing.\n", warnings)
		}
	}

	if issues > 0 {
		return exitCodeError{code: 1}
	}
	return nil
}

type emitFn func(name, status, msg string)

func doctorToken(emit emitFn) (issues int, token string) {
	// Env var takes highest priority.
	if tok := os.Getenv("RAMPART_TOKEN"); tok != "" {
		emit("Token", "ok", "token found in RAMPART_TOKEN env var")
		return 0, tok
	}
	// Fall back to persisted token file.
	if tok, err := readPersistedToken(); err == nil && tok != "" {
		emit("Token", "ok", "token found in ~/.rampart/token")
		return 0, tok
	}
	emit("Token", "fail", "no token found (run 'rampart serve install' to create one)")
	return 1, ""
}

func doctorHookBinary(emit emitFn) int {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}
	claudeSettingsPath := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(claudeSettingsPath)
	if err != nil {
		return 0 // settings.json absent — hook check covers this
	}

	var settings map[string]any
	if json.Unmarshal(data, &settings) != nil {
		return 0
	}

	// Find all hook commands and check absolute paths.
	issues := 0
	hooks, _ := settings["hooks"].(map[string]any)
	for _, v := range hooks {
		arr, _ := v.([]any)
		for _, item := range arr {
			m, _ := item.(map[string]any)
			innerHooks, _ := m["hooks"].([]any)
			for _, h := range innerHooks {
				hm, _ := h.(map[string]any)
				cmd, _ := hm["command"].(string)
				if cmd == "" {
					continue
				}
				// Extract the binary (first field, before any spaces).
				fields := strings.Fields(cmd)
				if len(fields) == 0 {
					continue
				}
				bin := fields[0]
				if !filepath.IsAbs(bin) {
					continue // not absolute — skip (PATH lookup, not our concern)
				}
				if _, statErr := os.Stat(bin); statErr != nil {
					emit("Hook binary", "fail", fmt.Sprintf("%s not found", bin))
					issues++
				} else {
					emit("Hook binary", "ok", fmt.Sprintf("%s exists", bin))
				}
			}
		}
	}
	return issues
}

func doctorPolicies(emit emitFn) int {
	issues := 0
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}
	policyDir := filepath.Join(home, ".rampart", "policies")

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		emit("Policy", "fail", fmt.Sprintf("%s (not found)", policyDir))
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
			emit("Policy", "fail", fmt.Sprintf("~/%s (%s)", relHome(path, home), err))
			issues++
		} else {
			count := len(cfg.Policies)
			emit("Policy", "ok", fmt.Sprintf("~/%s (%d policies, valid)", relHome(path, home), count))
		}
	}
	if !found {
		emit("Policy", "fail", fmt.Sprintf("no .yaml files in %s", policyDir))
		issues++
	}
	return issues
}

// doctorServer checks if rampart serve is running on port 18275.
// Returns (issue count, serve URL for subsequent API checks).
func doctorServer(emit emitFn) (int, string) {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://localhost:%d/healthz", doctorServePort)
	resp, err := client.Get(url)
	if err != nil {
		emit("Server", "fail", fmt.Sprintf("not running on :%d (run 'rampart serve')", doctorServePort))
		return 1, ""
	}
	defer resp.Body.Close()

	// Parse version from health response if available.
	var health map[string]any
	versionStr := ""
	if decErr := json.NewDecoder(resp.Body).Decode(&health); decErr == nil {
		if v, ok := health["version"].(string); ok {
			versionStr = " v" + v
		}
	}

	serveURL := fmt.Sprintf("http://localhost:%d", doctorServePort)
	emit("Server", "ok", fmt.Sprintf("rampart serve%s running on :%d", versionStr, doctorServePort))
	return 0, serveURL
}

func doctorTokenAuth(emit emitFn, serveURL, token string) int {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, serveURL+"/v1/policy", nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return 0 // server issue, already reported
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		emit("Token auth", "fail", fmt.Sprintf("token rejected by server (HTTP %d)", resp.StatusCode))
		return 1
	}
	emit("Token auth", "ok", "token accepted by server")
	return 0
}

func doctorPoliciesAPI(emit emitFn, serveURL, token string) int {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, serveURL+"/v1/policy", nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0
	}

	count := 0
	if v, ok := body["policy_count"].(float64); ok {
		count = int(v)
	}
	if count == 0 {
		emit("Policies API", "fail", "server reports 0 policies loaded")
		return 1
	}
	emit("Policies API", "ok", fmt.Sprintf("%d policies loaded via API", count))
	return 0
}

func doctorPending(emit emitFn, serveURL, token string) int {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, serveURL+"/v1/approvals", nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0
	}

	count := 0
	if pending, ok := body["approvals"].([]any); ok {
		count = len(pending)
	}
	if count > 0 {
		emit("Pending", "warn", fmt.Sprintf("%d approval(s) pending — check 'rampart approve list'", count))
		return 1 // warning, not a hard failure
	}
	emit("Pending", "ok", "no pending approvals")
	return 0
}

func doctorHooks(emit emitFn) int {
	issues := 0

	// Claude Code hooks — only check if ~/.claude/ exists
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}
	claudeDir := filepath.Join(home, ".claude")
	if _, err := os.Stat(claudeDir); err == nil {
		claudeSettingsPath := filepath.Join(claudeDir, "settings.json")
		data, err := os.ReadFile(claudeSettingsPath)
		if err == nil {
			var settings map[string]any
			if json.Unmarshal(data, &settings) == nil {
				count := countClaudeHookMatchers(settings)
				if count > 0 {
					emit("Hooks", "ok", fmt.Sprintf("Claude Code (%d matchers in settings.json)", count))
				} else {
					emit("Hooks", "fail", "Claude Code (no Rampart hooks in settings.json)")
					issues++
				}
			} else {
				emit("Hooks", "fail", "Claude Code (invalid settings.json)")
				issues++
			}
		} else {
			emit("Hooks", "fail", "Claude Code (no settings.json found)")
			issues++
		}
	}

	// Cline hooks — only check if ~/Documents/Cline/ exists
	clineBaseDir := filepath.Join(home, "Documents", "Cline")
	if _, err := os.Stat(clineBaseDir); err == nil {
		clineDir := filepath.Join(clineBaseDir, "Hooks")
		if entries, err := os.ReadDir(clineDir); err == nil {
			hookCount := 0
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "rampart-") {
					hookCount++
				}
			}
			if hookCount > 0 {
				emit("Hooks", "ok", fmt.Sprintf("Cline (%d hook scripts)", hookCount))
			} else {
				emit("Hooks", "fail", "Cline (no Rampart hooks found)")
				issues++
			}
		} else {
			emit("Hooks", "fail", "Cline (no Hooks directory found)")
			issues++
		}
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

func doctorAudit(emit emitFn) int {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}
	auditDir := filepath.Join(home, ".rampart", "audit")

	entries, err := os.ReadDir(auditDir)
	if err != nil {
		emit("Audit", "fail", fmt.Sprintf("%s (not found)", auditDir))
		return 1
	}

	// Check writable
	testFile := filepath.Join(auditDir, ".doctor-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		emit("Audit", "fail", fmt.Sprintf("%s (not writable)", auditDir))
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
		emit("Audit", "ok", fmt.Sprintf("~/%s (0 files)", relHome(auditDir, home)))
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

	emit("Audit", "ok", fmt.Sprintf("~/%s (%d files, latest: %s)", relHome(auditDir, home), len(files), latest))
	return 0
}

func doctorVersionCheck(w io.Writer, silent bool, emit emitFn) int {
	current := build.Version
	if current == "dev" || current == "" {
		return 0 // dev build, skip check
	}

	// Pseudoversion or pre-release build (e.g. v0.2.37-0.20260218194853-6c13a58b371e).
	// Comparing these to a stable release tag is meaningless and confusing — skip the check.
	if strings.Contains(current, "-0.") {
		if emit != nil {
			emit("Update check", "info", "Dev build — update checks skipped")
		} else if !silent {
			fmt.Fprintf(w, "  ℹ Update check skipped (dev build: %s)\n", current)
		}
		return 0
	}

	// GitHub API: get latest release
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/peg/rampart/releases/latest")
	if err != nil {
		return 0 // network error, don't count as issue
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return 0
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	currentClean := strings.TrimPrefix(current, "v")

	if latest == currentClean {
		return 0
	}

	if !silent {
		// Detect install method for upgrade hint
		exe, _ := os.Executable()
		var hint string
		switch {
		case strings.Contains(exe, "homebrew") || strings.Contains(exe, "Cellar") || strings.Contains(exe, "linuxbrew"):
			hint = "  brew upgrade rampart"
		case strings.Contains(exe, filepath.Join("go", "bin")):
			hint = fmt.Sprintf("  go install github.com/peg/rampart/cmd/rampart@%s", release.TagName)
		default:
			hint = fmt.Sprintf("  go install github.com/peg/rampart/cmd/rampart@%s\n  — or download from https://github.com/peg/rampart/releases", release.TagName)
		}
		fmt.Fprintf(w, "  ⚠ Update available: %s → %s\n%s\n", current, release.TagName, hint)
	}
	return 0 // informational, not an issue
}

// doctorProjectPolicy checks if the current git repo has a .rampart/policy.yaml project policy.
// This check is purely informational — it never counts as a failure.
func doctorProjectPolicy(w io.Writer, emit emitFn, collect bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	out, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		// Not in a git repo (or git not installed) — skip silently.
		return
	}

	gitRoot := strings.TrimSpace(string(out))
	policyPath := filepath.Join(gitRoot, ".rampart", "policy.yaml")

	if _, err := os.Stat(policyPath); err == nil {
		emit("Project policy", "ok", ".rampart/policy.yaml")
	} else {
		// Informational — not a failure. For JSON, use status "info".
		if collect {
			emit("Project policy", "info", "No project policy (.rampart/policy.yaml not found in this repo)")
		} else {
			fmt.Fprintf(w, "  No project policy (.rampart/policy.yaml not found in this repo)\n")
		}
	}
}

func relHome(path, home string) string {
	if rel, err := filepath.Rel(home, path); err == nil {
		return rel
	}
	return path
}
