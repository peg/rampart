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
	"bufio"
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
	"github.com/peg/rampart/internal/detect"
	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

// defaultServePort is the default port for rampart serve.
// Referenced by doctor, hook, quickstart, and serve install.
// Must match the --port flag default in newServeCmd.
const defaultServePort = 9090

// checkResult holds the outcome of a single doctor check for --json output.
type checkResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "ok", "warn", "fail", "info"
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"` // actionable suggestion on failure/warn
}

// hintSep is the separator embedded in doctor messages to carry a hint.
// Format: "<msg>\n" + hintSep + "<hint>"
const hintSep = "\n  💡 "

func newDoctorCmd() *cobra.Command {
	var jsonOut bool
	var fix bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check Rampart installation health",
		Long:  "Run diagnostic checks on your Rampart installation and report any issues.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if fix {
				return runDoctorFix(cmd)
			}
			return runDoctor(cmd.OutOrStdout(), jsonOut)
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results as JSON")
	cmd.Flags().BoolVar(&fix, "fix", false, "Automatically apply fixes for detected issues (re-runs patch-tools if needed)")
	return cmd
}

// runDoctorFix checks for missing patches and applies them automatically.
func runDoctorFix(cmd *cobra.Command) error {
	needsPatch := !openclawWebFetchPatched() || !openclawBrowserPatched() ||
		!openclawMessagePatched() || !openclawExecPatched() || !openclawDistPatched()

	if !needsPatch {
		fmt.Fprintln(cmd.OutOrStdout(), "✓ All patches already applied — nothing to fix.")
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Applying missing patches...")
	_, err := patchOpenClawDistTools(cmd, fmt.Sprintf("http://127.0.0.1:%d", defaultServePort), "")
	if err != nil {
		// May need sudo — tell the user
		fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Auto-fix failed (may need sudo): %v\n", err)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Run manually: sudo rampart setup openclaw --patch-tools --force\n")
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ Patches applied. Restart OpenClaw for changes to take effect.")
	return nil
}

func runDoctor(w io.Writer, jsonOut bool) error {
	var results []checkResult
	collect := jsonOut // only accumulate when --json is set
	useColor := !jsonOut && !noColor() && isTerminal(os.Stdout)

	emit := func(name, status, msg string) {
		// Split hint from message (hint is appended with hintSep).
		mainMsg, hint, _ := strings.Cut(msg, hintSep)

		if collect {
			r := checkResult{Name: name, Status: status, Message: mainMsg}
			if hint != "" {
				r.Hint = hint
			}
			results = append(results, r)
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
		fmt.Fprintf(w, "%s %s: %s\n", icon, name, mainMsg)

		// Print hint on its own indented line.
		if hint != "" {
			if useColor {
				fmt.Fprintf(w, "    %s💡 Try this:%s %s\n", colorDim, colorReset, hint)
			} else {
				fmt.Fprintf(w, "    💡 Try this: %s\n", hint)
			}
		}
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
		emit("PATH", "fail", "rampart not found in PATH"+hintSep+
			`export PATH="$PATH:$(go env GOPATH)/bin"`)
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
	auditIssues, auditWarnings := doctorAudit(emit)
	issues += auditIssues
	warnings += auditWarnings

	// 8. Server running on default port
	protected := detectProtectedAgents()
	serverIssues, serveURL := doctorServer(emit, protected)
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

	// 12. Preload health (Linux only)
	if runtime.GOOS == "linux" {
		if n := doctorPreload(emit); n > 0 {
			warnings += n
		}
	}

	// 13. File tool patches (OpenClaw only)
	if n := doctorFileToolPatches(emit); n > 0 {
		warnings += n
	}

	// 14. System info
	emit("System", "ok", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))

	// 15. Project policy (informational only — not a failure)
	doctorProjectPolicy(w, emit, collect)

	// 16. OpenClaw ask mode check
	if n := doctorOpenClawAskMode(emit); n > 0 {
		warnings += n
	}

	// 17. OpenClaw plugin health
	if n := doctorOpenClawPlugin(emit); n > 0 {
		warnings += n
	}

	// 18. Proactive policy suggestions (informational only)
	if detectResult, detectErr := detect.Environment(); detectErr == nil {
		client := newPolicyRegistryClient()
		if manifest, fetchErr := client.loadManifest(context.Background(), false); fetchErr == nil {
			suggestions := suggestPolicies(detectResult, manifest)
			if len(suggestions) > 0 {
				desc := describeSuggestions(suggestions)
				emit("Policy suggestions", "info", desc)
			}
		}
	}

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
	} else if issues == 0 && warnings > 0 {
		fmt.Fprintf(w, "%d warning(s) — not blocking but worth reviewing.\n", warnings)
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
	// On Windows, token is optional since serve is optional for basic protection
	if runtime.GOOS == "windows" {
		emit("Token", "warn", "no token found (optional — only needed for dashboard/approvals)")
		return 0, ""
	}
	emit("Token", "fail", "no token found"+hintSep+"rampart serve install")
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

	// Find all hook commands and check absolute paths (dedupe).
	issues := 0
	checked := make(map[string]bool)
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
				if checked[bin] {
					continue // already checked this path
				}
				checked[bin] = true
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
		emit("Policy", "fail", fmt.Sprintf("%s (not found)", policyDir)+hintSep+
			"rampart init --profile standard")
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
			continue
		}

		// Run lint to catch silent issues (e.g. condition field typos that yaml
		// unmarshaling ignores, making rules silently match everything).
		lintResult := engine.LintPolicyFile(path)
		count := len(cfg.Policies)
		rel := relHome(path, home)
		isManagedEmptyCustom := strings.EqualFold(filepath.Base(path), "custom.yaml") && count == 0
		switch {
		case lintResult.HasErrors():
			emit("Policy", "fail",
				fmt.Sprintf("~/%s (%d policies, %d lint error(s))", rel, count, lintResult.Errors)+
					hintSep+fmt.Sprintf("rampart policy lint %s", path))
			issues++
		case isManagedEmptyCustom:
			emit("Policy", "ok", fmt.Sprintf("~/%s (%d policies, valid placeholder)", rel, count))
		case lintResult.Warnings > 0:
			emit("Policy", "ok",
				fmt.Sprintf("~/%s (%d policies, %d lint warning(s) — policy works, run lint for details)", rel, count, lintResult.Warnings))
		default:
			// Check for stale built-in policies.
			if builtInProfiles[filepath.Base(path)] {
				if staleMsg := checkPolicyVersionStamp(path); staleMsg != "" {
					emit("Policy", "warn", fmt.Sprintf("~/%s (%d policies, valid, %s)", rel, count, staleMsg)+
						hintSep+"rampart upgrade --no-binary")
				} else {
					emit("Policy", "ok", fmt.Sprintf("~/%s (%d policies, valid)", rel, count))
				}
			} else {
				emit("Policy", "ok", fmt.Sprintf("~/%s (%d policies, valid)", rel, count))
			}
		}
	}
	if !found {
		emit("Policy", "fail",
			fmt.Sprintf("no .yaml files in %s", policyDir)+hintSep+
				"rampart init --profile standard")
		issues++
	}
	return issues
}

// doctorServer checks if rampart serve is running on defaultServePort.
// Returns (issue count, serve URL for subsequent API checks).
// builtInProfiles lists policy files that are managed by rampart and can be auto-updated.
var builtInProfiles = map[string]bool{
	"standard.yaml":               true,
	"paranoid.yaml":               true,
	"yolo.yaml":                   true,
	"demo.yaml":                   true,
	"block-prompt-injection.yaml": true,
	"research-agent.yaml":         true,
	"mcp-server.yaml":             true,
	"openclaw.yaml":               true,
}

// checkPolicyVersionStamp reads the first line of a policy file looking for
// "# rampart-policy-version: X.Y.Z". Returns a warning message if the stamp
// version is older than the running binary, or "" if current/no stamp.
func checkPolicyVersionStamp(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return ""
	}
	line := scanner.Text()

	const prefix = "# rampart-policy-version: "
	if !strings.HasPrefix(line, prefix) {
		// No stamp — policy predates version stamping (pre-v0.9.0).
		// Don't warn: the user may have never run upgrade, or manually edited the file.
		return ""
	}

	stampVer := strings.TrimSpace(line[len(prefix):])
	if stampVer == build.Version || build.Version == "dev" || stampVer == "dev" {
		return ""
	}

	// Normalize for comparison
	stampNorm := stampVer
	if !strings.HasPrefix(stampNorm, "v") {
		stampNorm = "v" + stampNorm
	}
	binaryNorm := build.Version
	if !strings.HasPrefix(binaryNorm, "v") {
		binaryNorm = "v" + binaryNorm
	}

	if compareSemver(stampNorm, binaryNorm) < 0 {
		return fmt.Sprintf("from %s, binary is %s", stampVer, build.Version)
	}
	return ""
}

func doctorServer(emit emitFn, protected []string) (int, string) {
	client := &http.Client{Timeout: 2 * time.Second}
	serveURL := resolveServeURL("")
	url := serveURL + "/healthz"

	resp, err := client.Get(url)
	if err != nil {
		// Hook-based agents (Claude Code, Cline) evaluate policies locally.
		// Serve is only required for LD_PRELOAD/shim modes and the dashboard.
		hookOnly := isHookBasedOnly(protected)
		if hookOnly || runtime.GOOS == "windows" {
			emit("Server", "info",
				fmt.Sprintf("not reachable at %s (optional — hooks evaluate policies locally)", serveURL)+hintSep+
					"rampart serve  # for dashboard + approvals")
			return 0, ""
		}

		issues := 1

		emit("Server", "fail",
			fmt.Sprintf("not reachable at %s", serveURL)+hintSep+
				"rampart serve --background")

		// Warn about silent policy bypass when fail-open + serve down.
		failOpen := os.Getenv("RAMPART_FAIL_OPEN")
		if failOpen == "" || failOpen == "1" || failOpen == "true" {
			emit("Fail-open", "warn",
				"serve is down and RAMPART_FAIL_OPEN=1 (default) — commands execute without policy checks"+hintSep+
					"Start serve or set RAMPART_FAIL_OPEN=0 to block when serve is unreachable")
			issues++
		}

		return issues, ""
	}
	defer resp.Body.Close()

	// Parse version from health response if available.
	var health map[string]any
	versionStr := ""
	servePort := 0
	if decErr := json.NewDecoder(resp.Body).Decode(&health); decErr == nil {
		if v, ok := health["version"].(string); ok {
			versionStr = " v" + v
		}
	}

	// Extract port from URL for display.
	if strings.Contains(serveURL, ":") {
		parts := strings.Split(serveURL, ":")
		if p := parts[len(parts)-1]; p != "" {
			fmt.Sscanf(p, "%d", &servePort)
		}
	}

	if servePort != 0 && servePort != defaultServePort {
		emit("Server", "ok", fmt.Sprintf("rampart serve%s running on :%d (non-default port)", versionStr, servePort))
	} else {
		emit("Server", "ok", fmt.Sprintf("rampart serve%s running on :%d", versionStr, defaultServePort))
	}
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
					emit("Hooks", "fail",
						fmt.Sprintf("Claude Code hook not installed (expected hook in %s)", claudeSettingsPath)+
							hintSep+"rampart setup claude-code")
					issues++
				}
			} else {
				emit("Hooks", "fail",
					fmt.Sprintf("Claude Code settings invalid at %s", claudeSettingsPath)+
						hintSep+"rampart setup claude-code")
				issues++
			}
		} else {
			emit("Hooks", "fail",
				fmt.Sprintf("Claude Code hook not installed (expected hook in %s)", claudeSettingsPath)+
					hintSep+"rampart setup claude-code")
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
				emit("Hooks", "fail",
					fmt.Sprintf("Cline hook not installed (expected Rampart hook scripts in %s)", clineDir)+
						hintSep+"rampart setup cline")
				issues++
			}
		} else {
			emit("Hooks", "fail",
				fmt.Sprintf("Cline hook not installed (expected Rampart hook scripts in %s)", clineDir)+
					hintSep+"rampart setup cline")
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

// doctorPreload checks if the LD_PRELOAD drop-in is installed and actually
// loaded in the running OpenClaw gateway process. Catches the case where
// setup was run but the gateway wasn't restarted through systemd.
func doctorPreload(emit emitFn) (warnings int) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}

	dropinPath := filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d", "rampart.conf")
	if _, err := os.Stat(dropinPath); err != nil {
		// No drop-in installed — preload not configured, nothing to check
		return 0
	}

	// Drop-in exists. Find the OpenClaw gateway process and check its env.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	foundGateway := false
	preloadActive := false

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue
		}
		if !strings.Contains(string(cmdline), "openclaw") || !strings.Contains(string(cmdline), "gateway") {
			continue
		}
		foundGateway = true

		// Check environment for LD_PRELOAD — read only the var names we need
		environ, err := os.ReadFile(filepath.Join("/proc", pid, "environ"))
		if err != nil {
			// Can't read env (permissions), skip this process
			continue
		}
		// Parse null-delimited env vars, only check for LD_PRELOAD
		for _, envVar := range strings.Split(string(environ), "\x00") {
			if strings.HasPrefix(envVar, "LD_PRELOAD=") && strings.Contains(envVar, "librampart") {
				preloadActive = true
				break
			}
		}
		if preloadActive {
			break
		}
	}

	if !foundGateway {
		emit("Preload", "warn", "drop-in installed but OpenClaw gateway not running")
		return 1
	}
	if preloadActive {
		emit("Preload", "ok", "LD_PRELOAD active in OpenClaw gateway")
		return 0
	}
	emit("Preload", "warn",
		"drop-in installed but LD_PRELOAD not active — gateway needs a full restart"+
			hintSep+"systemctl --user restart openclaw-gateway")
	return 1
}

// doctorFileToolPatches checks if OpenClaw's file tools (read, write, edit, grep)
// are patched with Rampart policy checks. If the tools directory exists but files
// aren't patched, warns the user — this happens after npm upgrades.
func doctorFileToolPatches(emit emitFn) (warnings int) {
	// Check if OpenClaw uses bundled dist files (#204).
	if openclawUsesBundledDist() {
		distPatched := openclawDistPatched()
		webFetchPatched := openclawWebFetchPatched()
		browserPatched := openclawBrowserPatched()
		messagePatched := openclawMessagePatched()
		execPatched := openclawExecPatched()

		if distPatched && webFetchPatched && browserPatched && messagePatched && execPatched {
			emit("Tool patches", "ok", "All OpenClaw tools patched (read/write/edit + web_fetch + browser + message + exec)")
			return 0
		}

		// Report each unpatched tool separately so users know exactly what to fix.
		if !distPatched {
			emit("Tool patches", "warn",
				"OpenClaw dist files not patched — read/write/edit not policy-checked"+
					hintSep+"sudo rampart setup openclaw --patch-tools --force")
			warnings++
		} else {
			emit("Tool patches", "ok", "OpenClaw dist files patched (read + write/edit)")
		}
		if !webFetchPatched {
			emit("web_fetch patch", "warn",
				"OpenClaw web_fetch not patched — URL fetch requests not policy-checked"+
					hintSep+"sudo rampart setup openclaw --patch-tools --force")
			warnings++
		}
		if !browserPatched {
			emit("browser patch", "warn",
				"OpenClaw browser tool not patched — navigate/open not policy-checked"+
					hintSep+"sudo rampart setup openclaw --patch-tools --force")
			warnings++
		}
		if !messagePatched {
			emit("message patch", "warn",
				"OpenClaw message tool not patched — outbound sends not policy-checked"+
					hintSep+"sudo rampart setup openclaw --patch-tools --force")
			warnings++
		}
		if !execPatched {
			emit("exec patch", "warn",
				"OpenClaw exec tool not patched — human-initiated execs bypass pre-check"+
					hintSep+"sudo rampart setup openclaw --patch-tools --force")
			warnings++
		}
		if warnings > 0 {
			return warnings
		}
		return 0
	}

	candidates := openclawToolsCandidates()
	var toolsDir string
	for _, d := range candidates {
		if _, err := os.Stat(filepath.Join(d, "read.js")); err == nil {
			toolsDir = d
			break
		}
	}
	if toolsDir == "" {
		// No OpenClaw tools found — not an OpenClaw installation, skip
		return 0
	}

	readFile := filepath.Join(toolsDir, "read.js")
	data, err := os.ReadFile(readFile)
	if err != nil {
		return 0
	}

	if strings.Contains(string(data), "RAMPART_") {
		emit("File tools", "ok", "OpenClaw file tools patched")
		return 0
	}

	emit("File tools", "warn",
		"OpenClaw file tools not patched — file read/write/edit/grep not policy-checked"+
			hintSep+"sudo rampart setup openclaw --patch-tools --force")
	return 1
}

// openclawUsesBundledDist checks if the OpenClaw installation uses pre-bundled
// dist files (pi-embedded-*.js) rather than loading tools from node_modules.
// When bundled, patching source files in node_modules has no effect.
func openclawUsesBundledDist() bool {
	// Check common OpenClaw install locations for bundled dist files
	candidates := []string{
		"/usr/lib/node_modules/openclaw/dist",
		"/usr/local/lib/node_modules/openclaw/dist",
	}
	home, err := os.UserHomeDir()
	if err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".npm-global", "lib", "node_modules", "openclaw", "dist"),
			filepath.Join(home, "node_modules", "openclaw", "dist"),
		)
	}

	for _, distDir := range candidates {
		// Check for pi-embedded-*.js (older OpenClaw) or auth-profiles-*.js (newer OpenClaw)
		piMatches, _ := filepath.Glob(filepath.Join(distDir, "pi-embedded-*.js"))
		authMatches, _ := filepath.Glob(filepath.Join(distDir, "auth-profiles-*.js"))
		matches := append(piMatches, authMatches...)
		if len(matches) > 0 {
			// Bundled dist exists. Check if the bundle contains tool definitions
			// (confirming tools are compiled in, not loaded from node_modules).
			for _, m := range matches {
				data, err := os.ReadFile(m)
				if err != nil {
					continue
				}
				if strings.Contains(string(data), "createReadTool") || strings.Contains(string(data), "readTool") ||
					strings.Contains(string(data), "processGatewayAllowlist") || strings.Contains(string(data), "runMessageAction") {
					return true
				}
			}
		}
	}
	return false
}

// openclawDistPatched checks if the bundled dist files have been patched with Rampart checks.
// Checks both pi-embedded-*.js (older OpenClaw) and auth-profiles-*.js (newer OpenClaw).
func openclawDistPatched() bool {
	return openclawDistCheckPatched("RAMPART_DIST_CHECK")
}

// openclawWebFetchPatched checks if any dist *.js files have the web_fetch Rampart patch.
func openclawWebFetchPatched() bool {
	return openclawDistCheckPatched("RAMPART_DIST_CHECK_WEBFETCH")
}

// openclawBrowserPatched checks if the browser tool is patched.
func openclawBrowserPatched() bool {
	return openclawDistCheckPatched("RAMPART_DIST_CHECK_BROWSER")
}

// openclawMessagePatched checks if the message tool is patched.
func openclawMessagePatched() bool {
	return openclawDistCheckPatched("RAMPART_DIST_CHECK_MESSAGE")
}

// openclawExecPatched checks if the exec tool is patched.
func openclawExecPatched() bool {
	return openclawDistCheckPatched("RAMPART_DIST_CHECK_EXEC")
}

// openclawDistCheckPatched returns true if any dist *.js file contains the given marker.
func openclawDistCheckPatched(marker string) bool {
	for _, d := range openclawDistCandidates() {
		allJS, _ := filepath.Glob(filepath.Join(d, "*.js"))
		for _, m := range allJS {
			data, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			if strings.Contains(string(data), marker) {
				return true
			}
		}
	}
	return false
}

func openclawToolsPatched() bool {
	for _, d := range openclawToolsCandidates() {
		readFile := filepath.Join(d, "read.js")
		data, err := os.ReadFile(readFile)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "RAMPART") {
			return true
		}
	}
	return false
}

func doctorAudit(emit emitFn) (issues int, warnings int) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, 0
	}
	auditDir := filepath.Join(home, ".rampart", "audit")

	entries, err := os.ReadDir(auditDir)
	if err != nil {
		hint := "rampart serve --background  # creates the audit directory"
		if runtime.GOOS == "windows" {
			hint = "rampart serve  # creates the audit directory"
		}
		emit("Audit", "fail",
			fmt.Sprintf("%s (not found)", auditDir)+hintSep+hint)
		return 1, 0
	}

	// Check writable
	testFile := filepath.Join(auditDir, ".doctor-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		emit("Audit", "fail",
			fmt.Sprintf("%s (not writable)", auditDir)+hintSep+
				fmt.Sprintf("chmod u+w %s", auditDir))
		return 1, 0
	}
	// Defer removal so the temp file is cleaned up on every exit path,
	// including early returns and panics, not just the happy path.
	defer os.Remove(testFile)

	// Count files and find latest
	var files []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			files = append(files, e)
		}
	}

	if len(files) == 0 {
		emit("Audit", "ok", fmt.Sprintf("~/%s (0 files)", relHome(auditDir, home)))
		return 0, 0
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

	worldReadable := make([]string, 0, 4)
	_ = filepath.WalkDir(auditDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Mode().Perm()&0o004 != 0 {
			if len(worldReadable) < 3 {
				worldReadable = append(worldReadable, relHome(path, home))
			}
			warnings++
		}
		return nil
	})
	if warnings > 0 {
		sample := strings.Join(worldReadable, ", ")
		msg := fmt.Sprintf("%d world-readable audit file(s) found", warnings)
		if sample != "" {
			msg += fmt.Sprintf(" (e.g. ~/%s)", sample)
		}
		emit("Audit perms", "warn", msg)
	}
	return 0, warnings
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

// doctorOpenClawPlugin checks whether the Rampart native plugin is installed
// in ~/.openclaw/extensions/rampart/. This is the preferred integration method
// for OpenClaw >= 2026.3.28 (uses the before_tool_call hook instead of dist patches).
//
// Emits:
//   - ok if plugin directory exists
//   - warn (with hint) if OpenClaw is installed but plugin is missing
//   - skipped silently if OpenClaw is not installed at all
func doctorOpenClawPlugin(emit emitFn) (warnings int) {
	// Skip silently if OpenClaw is not installed.
	if !isOpenClawInstalled() {
		return 0
	}

	if isOpenClawPluginInstalled() {
		emit("OpenClaw plugin", "ok", "installed (before_tool_call hook active)")
		return 0
	}

	emit("OpenClaw plugin", "warn",
		"not installed — native hook interception disabled"+hintSep+
			"rampart setup openclaw --plugin")
	return 1
}

// doctorOpenClawAskMode checks if ~/.openclaw/openclaw.json has ask set to
// "on-miss" or "always", which is required for exec approval events to reach
// Rampart's bridge. If the file doesn't exist, the check is skipped silently.
func doctorOpenClawAskMode(emit emitFn) (warnings int) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}

	configPath := filepath.Join(home, ".openclaw", "openclaw.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		// File doesn't exist — not everyone uses OpenClaw, skip silently.
		return 0
	}

	// ask can be set at top-level OR at tools.exec.ask
	var cfg struct {
		Ask   string `json:"ask"`
		Tools struct {
			Exec struct {
				Ask string `json:"ask"`
			} `json:"exec"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		emit("OpenClaw ask mode", "warn", fmt.Sprintf("failed to parse %s: %v", configPath, err))
		return 1
	}

	askVal := cfg.Ask
	if askVal == "" {
		askVal = cfg.Tools.Exec.Ask
	}

	switch askVal {
	case "on-miss", "always":
		emit("OpenClaw ask mode", "ok", fmt.Sprintf("%s (exec approvals will reach Rampart bridge)", askVal))
		return 0
	default:
		emit("OpenClaw ask mode", "warn",
			"not configured for exec interception"+hintSep+
				"Add \"ask\": \"on-miss\" to ~/.openclaw/openclaw.json, then restart OpenClaw\n"+
				"       Without this, exec approval events are never sent to Rampart's bridge")
		return 1
	}
}

func relHome(path, home string) string {
	if rel, err := filepath.Rel(home, path); err == nil {
		return rel
	}
	return path
}
