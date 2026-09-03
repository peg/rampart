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
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	ochardening "github.com/peg/rampart/internal/openclaw/hardening"
	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
	"github.com/peg/rampart/policies"
)

// openclawPluginDir is the well-known directory where the Rampart OpenClaw
// plugin is installed by `openclaw plugins install`.
const openclawPluginDir = "extensions/rampart"

// openclawMinVersion is the minimum OpenClaw version required for the
// before_tool_call hook used by the Rampart plugin.
const openclawMinVersion = "2026.3.28"

// The plugin is bundled inside the binary via //go:embed and extracted to a
// temp directory during setup. No external checkout or npm install required.

// runSetupOpenClawPlugin installs the Rampart native plugin into OpenClaw.
//
// Steps:
//  1. Locate the openclaw binary.
//  2. Verify the OpenClaw version is >= openclawMinVersion (requires before_tool_call hook).
//  3. Run: openclaw plugins install <plugin-path> with the host-supported
//     non-interactive source and capability-consent flags.
//  4. Preserve the host's canonical tools.exec.mode when present; otherwise
//     record ownership and set the legacy tools.exec.ask field to "off".
//     Native OpenClaw approvals remain the visible approval owner while
//     Rampart evaluates policy and persists allow-always behavior.
//  5. Copy the openclaw.yaml policy profile to ~/.rampart/policies/openclaw.yaml.
//  6. Run rampart doctor for a health summary.
//  7. Print success and next steps.
func runSetupOpenClawPlugin(w io.Writer, errW io.Writer) error {
	return runSetupOpenClawPluginForServeURL(w, errW, "")
}

func runSetupOpenClawPluginForServeURL(w io.Writer, errW io.Writer, requestedServeURL string) error {
	// 1. Locate openclaw.
	openclawBin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("openclaw not found — is it installed?\n  Install: npm install -g openclaw\n  Error: %w", err)
	}
	fmt.Fprintf(w, "✓ Found OpenClaw: %s\n", openclawBin)
	stateDir, configPath, err := resolveOpenClawStateDir(openclawBin)
	if err != nil {
		return fmt.Errorf("resolve active OpenClaw state directory: %w", err)
	}
	fmt.Fprintf(w, "✓ Target OpenClaw state: %s (config: %s)\n", stateDir, configPath)

	// 2. Check version.
	version, err := getOpenClawVersion(openclawBin)
	if err != nil {
		return fmt.Errorf("determine OpenClaw version before installing the native security boundary: %w", err)
	}
	ok, cmpErr := openclawVersionAtLeast(version, openclawMinVersion)
	if cmpErr != nil {
		return fmt.Errorf("parse OpenClaw version %q: %w", version, cmpErr)
	}
	if !ok {
		return fmt.Errorf("OpenClaw version %s is too old — need >= %s for before_tool_call hook\n  Upgrade: npm install -g openclaw@latest", version, openclawMinVersion)
	}
	fmt.Fprintf(w, "✓ OpenClaw version: %s (>= %s required)\n", version, openclawMinVersion)
	serveURL, err := resolveServeURLStrict(requestedServeURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return fmt.Errorf("resolve Rampart policy service URL: %w", err)
	}

	// Start the policy service only after proving that the requested host exists
	// and supports the native security hook. A missing, malformed, or outdated
	// OpenClaw install must not mutate Rampart's background-service state.
	if err := ensureServeRunningForURL(w, errW, serveURL); err != nil {
		return fmt.Errorf("start Rampart policy service: %w", err)
	}

	// 3. Extract the bundled plugin to a temp dir and install it.
	pluginDir, err := os.MkdirTemp("", "rampart-openclaw-plugin-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for plugin: %w", err)
	}
	defer os.RemoveAll(pluginDir)

	if err := ocplugin.Extract(pluginDir); err != nil {
		return fmt.Errorf("failed to extract bundled plugin: %w", err)
	}
	fmt.Fprintf(w, "Installing bundled plugin (v%s)...\n", ocplugin.Version())

	install := func() error {
		return runWithOpenClawExecModeMigration(stateDir, configPath, func() error {
			if err := runOpenClawPluginInstall(openclawBin, pluginDir, w, errW); err != nil {
				return err
			}
			return runOpenClawPluginEnable(openclawBin, w, errW)
		}, w)
	}
	validate := func() error { return validateOpenClawPluginRuntime(openclawBin) }
	if err := installOpenClawPluginSafely(stateDir, configPath, install, validate, errW); err != nil {
		return fmt.Errorf("OpenClaw plugin install/enable failed: %w\n  After reviewing the bundled plugin, inspect the installed host's required consent flags: openclaw plugins install --help; openclaw plugins enable --help", err)
	}
	if state := getOpenClawPluginStateAt(stateDir, configPath); !openClawPluginCurrent(state) {
		return fmt.Errorf("OpenClaw plugin install and enable completed, but the managed Rampart plugin is not active in the resolved host configuration")
	}
	fmt.Fprintln(w, "✓ Rampart plugin installed into OpenClaw")
	fmt.Fprintln(w, "  Note: OpenClaw may warn about suspicious code patterns — this is a false positive.")
	fmt.Fprintln(w, "  Rampart reads a local token file and talks to localhost:9090 only. See: https://docs.rampart.sh/integrations/openclaw#security-scanner")

	// 4. Preserve canonical tools.exec.mode or manage the legacy ask field.
	if err := ensureOpenClawExecApprovalConfig(openclawBin, stateDir, configPath); err != nil {
		return fmt.Errorf("configure OpenClaw exec approval ownership: %w", err)
	}
	fmt.Fprintln(w, "✓ OpenClaw exec approval configuration is compatible with the active host schema")

	// 4b. Harden OpenClaw approval semantics and align approval timeouts.
	if err := ensureOpenClawApprovalHardening(w, errW); err != nil {
		return fmt.Errorf("configure OpenClaw approval hardening: %w", err)
	}
	fmt.Fprintf(w, "✓ OpenClaw approval handling checked (plugin approvals aligned at %dms)\n", ochardening.DesiredApprovalTimeoutMs)

	// 5. Copy openclaw.yaml policy profile.
	if err := installOpenClawPolicy(w, errW); err != nil {
		return fmt.Errorf("install OpenClaw policy: %w", err)
	}

	// 6. Run rampart doctor.
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Running 'rampart doctor'...")
	doctorCmd := osexec.Command(os.Args[0], "doctor")
	doctorCmd.Stdout = w
	doctorCmd.Stderr = errW
	_ = doctorCmd.Run() // non-fatal — doctor output is informational

	// 7. Success message.
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "✅ Rampart is protecting your OpenClaw agent")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Protected tools: exec, read, write, edit, web_fetch, browser, message")
	serveStatus := serveURL
	if isSetupServeReachableAt(serveURL) {
		serveStatus += " (running)"
	} else {
		serveStatus += " (not running — start with: rampart serve --background)"
	}
	fmt.Fprintf(w, "  Policy engine:   %s\n", serveStatus)
	fmt.Fprintln(w, "  Audit log:       ~/.rampart/audit/")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  → Restart the gateway if it was not restarted automatically:  openclaw gateway restart")
	fmt.Fprintln(w, "  → Run `rampart watch` to see policy decisions in real time")
	fmt.Fprintln(w, "  → Run `rampart doctor` to verify your setup")

	return nil
}

func ensureOpenClawApprovalHardening(w io.Writer, errW io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	configPath := filepath.Join(home, ".openclaw", "openclaw.json")
	openclawBin, binErr := findOpenClawBinary()
	if binErr == nil {
		if _, resolvedConfigPath, stateErr := resolveOpenClawStateDir(openclawBin); stateErr == nil {
			configPath = resolvedConfigPath
		}
	}

	if isOpenClawPluginInstalled() {
		if binErr != nil {
			return fmt.Errorf("find OpenClaw for plugin approval timeout: %w", binErr)
		}
		// OpenClaw owns config serialization and $include write-through. A
		// direct whole-file edit here could flatten operator-authored config or
		// create an invalid sibling next to plugins.$include.
		cmd := osexec.Command(
			openclawBin,
			"config", "set", "plugins.entries.rampart.config.approvalTimeoutMs",
			strconv.Itoa(ochardening.DesiredApprovalTimeoutMs), "--json",
		)
		cmd.Stdout = w
		cmd.Stderr = errW
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("align plugin approval timeout through OpenClaw: %w", err)
		}
		fmt.Fprintf(w, "  Set plugins.entries.rampart.config.approvalTimeoutMs = %d\n", ochardening.DesiredApprovalTimeoutMs)
		fmt.Fprintln(w, "✓ Native OpenClaw plugin approvals configured; skipped legacy exec approval bundle patching")
		return nil
	}
	if version, modern := modernOpenClawVersion(); modern {
		return fmt.Errorf("OpenClaw %s supports Rampart's native plugin; refusing legacy approval bundle patching because the native plugin was not detected (run `rampart protect openclaw --reinstall`)", version)
	}

	state, err := ochardening.InspectConfig(configPath, openclawDistCandidates())
	if err != nil {
		return fmt.Errorf("inspect current hardening state: %w", err)
	}
	if state.ExecApprovalsPath == "" || state.BashToolsPath == "" {
		return fmt.Errorf("openclaw approval bundles not found under supported dist paths")
	}
	if !state.Supported {
		return fmt.Errorf("unsupported OpenClaw approval bundle shape; refusing blind legacy exec approval patch")
	}
	if state.FallbackSafe && state.CompletionAttributionSafe && state.ApprovalTimeoutAligned && state.PluginApprovalTimeoutAligned {
		fmt.Fprintln(w, "✓ OpenClaw approval semantics already hardened and timeout-aligned")
		return nil
	}
	result, err := ochardening.Apply(home, openclawDistCandidates())
	if err != nil {
		return fmt.Errorf("apply approval hardening: %w", err)
	}
	for _, path := range result.PatchedFiles {
		fmt.Fprintf(w, "  Hardened %s\n", filepath.Base(path))
	}
	if result.ConfigUpdated {
		fmt.Fprintf(w, "  Set plugins.entries.rampart.config.approvalTimeoutMs = %d\n", ochardening.DesiredApprovalTimeoutMs)
	}
	if result.RestartSuggested {
		if err := restartOpenClawGateway(); err != nil {
			fmt.Fprintf(errW, "⚠ Approval hardening applied, but automatic gateway restart failed: %v\n", err)
			fmt.Fprintln(errW, "  Restart manually: openclaw gateway restart")
		} else {
			fmt.Fprintln(w, "  Restarted OpenClaw gateway to activate approval hardening")
		}
	}
	return nil
}

func restartOpenClawGateway() error {
	openclawBin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("find OpenClaw for gateway restart: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := osexec.CommandContext(ctx, openclawBin, "gateway", "restart")
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		if len(out) > 0 {
			return fmt.Errorf("openclaw gateway restart: %w: %s", runErr, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("openclaw gateway restart: %w", runErr)
	}
	return nil
}

func inspectOpenClawInstallPath(path, name string, managed func(string) bool) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect OpenClaw %s path %s: %w", name, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refusing to replace symlinked OpenClaw %s path %s", name, path)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("refusing to replace non-directory OpenClaw %s path %s", name, path)
	}
	if !managed(path) {
		return false, fmt.Errorf("refusing to replace non-Rampart OpenClaw %s path %s", name, path)
	}
	return true, nil
}

func openClawHookManaged(hookDir string) bool {
	checks := map[string]string{
		"HOOK.md":  "Rampart AI agent firewall hook",
		"index.js": `export * from "../../index.js"`,
	}
	for name, marker := range checks {
		path := filepath.Join(hookDir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), marker) {
			return false
		}
	}
	return true
}

func runOpenClawPluginInstall(openclawBin, pluginDir string, w, errW io.Writer) error {
	// OpenClaw owns the config/include, SQLite index, lifecycle lease, and
	// staged filesystem rollback. Current hosts use --force to acknowledge this
	// bundled local source for non-interactive installs and separately require
	// explicit acceptance of the manifest's declared capability surface.
	// Feature-detect both flags because Rampart's supported OpenClaw floor
	// predates them.
	helpCmd := osexec.Command(openclawBin, "plugins", "install", "--help")
	helpOutput, err := helpCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect OpenClaw plugin install options: %w", err)
	}
	args := []string{"plugins", "install", pluginDir}
	if commandHelpHasFlag(helpOutput, "--force") {
		args = append(args, "--force")
	}
	if commandHelpHasFlag(helpOutput, "--accept-capabilities") {
		args = append(args, "--accept-capabilities")
	}
	cmd := osexec.Command(openclawBin, args...)
	cmd.Stdout = w
	cmd.Stderr = errW
	return cmd.Run()
}

func runOpenClawPluginEnable(openclawBin string, w, errW io.Writer) error {
	// Current OpenClaw preserves an explicitly disabled plugin across reinstall.
	// Use the host-owned enable command so capability consent is enforced and
	// recorded by OpenClaw instead of bypassing it with a direct config write.
	// Feature-detect the consent flag because Rampart's supported host floor
	// predates that contract.
	helpCmd := osexec.Command(openclawBin, "plugins", "enable", "--help")
	helpOutput, err := helpCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect OpenClaw plugin enable options: %w", err)
	}
	args := []string{"plugins", "enable", "rampart"}
	if commandHelpHasFlag(helpOutput, "--accept-capabilities") {
		args = append(args, "--accept-capabilities")
	}
	cmd := osexec.Command(openclawBin, args...)
	cmd.Stdout = w
	cmd.Stderr = errW
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("enable Rampart plugin through OpenClaw: %w", err)
	}
	return nil
}

func commandHelpHasFlag(output []byte, flag string) bool {
	for _, field := range strings.Fields(string(output)) {
		if field == flag {
			return true
		}
	}
	return false
}

func runOpenClawPluginUninstall(openclawBin string, w, errW io.Writer) error {
	cmd := osexec.Command(openclawBin, "plugins", "uninstall", "rampart", "--force")
	cmd.Stdout = w
	cmd.Stderr = errW
	return cmd.Run()
}

func jsonTreeContainsString(value any, want string) bool {
	switch typed := value.(type) {
	case string:
		return typed == want
	case []any:
		for _, child := range typed {
			if jsonTreeContainsString(child, want) {
				return true
			}
		}
	case map[string]any:
		for key, child := range typed {
			if key == want || jsonTreeContainsString(child, want) {
				return true
			}
		}
	}
	return false
}

func validateOpenClawPluginRuntime(openclawBin string) error {
	cmd := osexec.Command(openclawBin, "plugins", "inspect", "rampart", "--runtime", "--json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect Rampart plugin runtime: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var report any
	if err := decodeOpenClawJSON(output, &report); err != nil {
		return fmt.Errorf("decode Rampart plugin runtime inspection: %w", err)
	}
	if !jsonTreeContainsString(report, "rampart") || !jsonTreeContainsString(report, "before_tool_call") {
		return fmt.Errorf("OpenClaw runtime inspection did not report Rampart's before_tool_call hook")
	}
	return nil
}

// openClawConfigMayReferenceRampart is a conservative collision check for a
// fresh install. It recognizes the current single-file plugins $include shape
// without flattening or rewriting operator-authored config. Ambiguous include
// forms fail closed and are left for OpenClaw or the operator to resolve.
func openClawConfigMayReferenceRampart(configPath string) bool {
	plugins, err := loadOpenClawPluginsConfig(configPath)
	if err != nil {
		return true
	}
	return jsonTreeContainsString(plugins, "rampart")
}

// loadOpenClawPluginsConfig reads a directly authored plugins object or the
// current single-file plugins.$include shape without flattening it. Ambiguous,
// nested, linked, or escaping includes fail closed.
func loadOpenClawPluginsConfig(configPath string) (map[string]any, error) {
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	pluginsValue, exists := cfg["plugins"]
	if !exists {
		return map[string]any{}, nil
	}
	plugins, ok := pluginsValue.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plugins must be a JSON object")
	}
	includeValue, hasInclude := plugins["$include"]
	if !hasInclude {
		return plugins, nil
	}
	if len(plugins) != 1 {
		return nil, fmt.Errorf("plugins.$include cannot be combined with sibling keys")
	}
	include, ok := includeValue.(string)
	if !ok || include == "" || strings.ContainsRune(include, 0) {
		return nil, fmt.Errorf("plugins.$include must be a non-empty path string")
	}
	includePath := include
	if !filepath.IsAbs(includePath) {
		includePath = filepath.Join(filepath.Dir(configPath), includePath)
	}
	root, rootErr := filepath.Abs(filepath.Dir(configPath))
	target, targetErr := filepath.Abs(includePath)
	if rootErr != nil || targetErr != nil {
		return nil, fmt.Errorf("resolve plugins.$include path")
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("plugins.$include resolves outside the OpenClaw config directory")
	}
	info, err := os.Lstat(target)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("plugins.$include must reference a regular, non-symlink file")
	}
	included, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	var includedPlugins map[string]any
	if err := json.Unmarshal(included, &includedPlugins); err != nil {
		return nil, err
	}
	if _, nestedInclude := includedPlugins["$include"]; nestedInclude {
		return nil, fmt.Errorf("nested plugins.$include is unsupported")
	}
	return includedPlugins, nil
}

// installOpenClawPluginSafely refuses same-name collisions before delegating
// replacement to OpenClaw's own lifecycle transaction. OpenClaw owns its
// config/include writes, SQLite plugin index, lifecycle lease, staged publish,
// and rollback; duplicating those stores here would make recovery incomplete.
func installOpenClawPluginSafely(stateDir, cfgPath string, install, validate func() error, errW io.Writer) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create OpenClaw state directory: %w", err)
	}
	paths := []struct {
		name    string
		target  string
		managed func(string) bool
	}{
		{name: "plugin", target: filepath.Join(stateDir, openclawPluginDir), managed: openClawPluginManaged},
		{name: "hook", target: filepath.Join(stateDir, "hooks", "rampart"), managed: openClawHookManaged},
	}
	ownedPath := false
	for i := range paths {
		existed, err := inspectOpenClawInstallPath(paths[i].target, paths[i].name, paths[i].managed)
		if err != nil {
			return err
		}
		ownedPath = ownedPath || existed
	}
	if !ownedPath && openClawConfigMayReferenceRampart(cfgPath) {
		return fmt.Errorf("refusing to replace config-only OpenClaw plugin ID rampart without a positively owned Rampart plugin path")
	}
	if install == nil {
		return fmt.Errorf("OpenClaw plugin install operation is required")
	}
	if err := install(); err != nil {
		return err
	}
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	installedState := openClawPluginState{Installed: true, Allowed: true, Enabled: true, Dir: pluginDir}
	installedState.readInstalledPluginMetadata()
	if !openClawPluginManaged(pluginDir) || !openClawPluginCurrent(installedState) {
		return fmt.Errorf("OpenClaw reported success but did not install the current managed Rampart plugin files")
	}
	if validate == nil {
		return fmt.Errorf("OpenClaw plugin runtime validation operation is required")
	}
	if err := validate(); err != nil {
		return err
	}

	// Older Rampart/OpenClaw integrations could leave a second managed hook
	// directory. The current native plugin supersedes it; remove only after the
	// host transaction succeeds and only while its ownership remains positive.
	hookDir := filepath.Join(stateDir, "hooks", "rampart")
	if exists, err := inspectOpenClawInstallPath(hookDir, "hook", openClawHookManaged); err != nil {
		return fmt.Errorf("validate legacy OpenClaw hook after install: %w", err)
	} else if exists {
		if err := os.RemoveAll(hookDir); err != nil {
			return fmt.Errorf("remove superseded managed OpenClaw hook %s: %w", hookDir, err)
		}
		fmt.Fprintf(errW, "ℹ Removed superseded managed OpenClaw hook: %s\n", hookDir)
	}
	return nil
}

// runSetupOpenClawMigrate migrates from the legacy dist-patch/bridge approach
// to the native plugin-based integration.
//
// Steps:
//  1. Install and validate the native plugin (calls runSetupOpenClawPlugin).
//  2. Restore positively identified legacy dist/tool patches.
//  3. Remove positively identified legacy bridge configuration.
//  4. Print migration summary.
func runSetupOpenClawMigrate(w io.Writer, errW io.Writer) error {
	return runSetupOpenClawMigrateWith(
		w,
		errW,
		runSetupOpenClawPlugin,
		legacyOpenClawPatchDirs,
		cleanOpenClawConfig,
	)
}

func runSetupOpenClawMigrateWith(
	w io.Writer,
	errW io.Writer,
	installNative func(io.Writer, io.Writer) error,
	patchDirs func() []string,
	cleanLegacyConfig func(io.Writer, io.Writer) error,
) error {
	fmt.Fprintln(w, "Migrating from legacy OpenClaw integration to native plugin...")
	fmt.Fprintln(w, "")

	// Native installation is the protection handoff. Do not retire any legacy
	// boundary until the host has loaded and validated the replacement.
	fmt.Fprintln(w, "Installing Rampart native plugin...")
	if err := installNative(w, errW); err != nil {
		return fmt.Errorf("plugin install failed during migration; legacy protection was left unchanged: %w", err)
	}

	var removed []string

	// Restore only files that still contain a known Rampart legacy marker and
	// have a regular, non-symlink backup. A planted backup beside an unrelated
	// OpenClaw file is not proof of ownership.
	for _, distDir := range patchDirs() {
		allJS, _ := filepath.Glob(filepath.Join(distDir, "*.js"))
		for _, file := range allJS {
			backup := file + ".rampart-backup"
			fileInfo, fileErr := os.Lstat(file)
			backupInfo, backupErr := os.Lstat(backup)
			if fileErr != nil || backupErr != nil {
				continue
			}
			if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() ||
				backupInfo.Mode()&os.ModeSymlink != 0 || !backupInfo.Mode().IsRegular() {
				fmt.Fprintf(errW, "⚠ Refusing linked or non-regular legacy patch pair: %s\n", file)
				continue
			}
			current, readErr := os.ReadFile(file)
			if readErr != nil {
				fmt.Fprintf(errW, "⚠ Could not inspect %s: %v\n", file, readErr)
				continue
			}
			if !hasLegacyOpenClawPatchMarker(current) {
				fmt.Fprintf(errW, "⚠ Left unowned backup unchanged beside %s\n", file)
				continue
			}
			data, readErr := os.ReadFile(backup)
			if readErr != nil {
				fmt.Fprintf(errW, "⚠ Could not read legacy backup for %s: %v\n", file, readErr)
				continue
			}
			if err := atomicWritePrivateFileWithMode(file, data, fileInfo.Mode().Perm()); err != nil {
				fmt.Fprintf(errW, "⚠ Could not restore %s: %v\n", file, err)
				continue
			}
			if err := os.Remove(backup); err != nil {
				fmt.Fprintf(errW, "⚠ Restored %s but could not remove backup: %v\n", file, err)
				continue
			}
			removed = append(removed, filepath.Base(file)+" (legacy patch restored)")
		}
	}
	if len(removed) > 0 {
		fmt.Fprintf(w, "✓ Restored %d legacy-patched file(s) from backup\n", len(removed))
	} else {
		fmt.Fprintln(w, "  No owned legacy patch backups found (already clean or not applied)")
	}

	if err := cleanLegacyConfig(w, errW); err != nil {
		fmt.Fprintf(errW, "⚠ Could not clean openclaw.json: %v\n", err)
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Migration complete!")
	if len(removed) > 0 {
		for _, r := range removed {
			fmt.Fprintf(w, "  Cleaned: %s\n", r)
		}
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The legacy dist patches and bridge are no longer needed.")
	fmt.Fprintln(w, "The native before_tool_call hook intercepts all OpenClaw tool calls.")
	fmt.Fprintln(w, "Sensitive-vs-fail-open behavior still depends on tool class and plugin configuration.")

	return nil
}

func legacyOpenClawPatchDirs() []string {
	dirs := append([]string(nil), openclawDistCandidates()...)
	return append(dirs, openclawToolsCandidates()...)
}

func hasLegacyOpenClawPatchMarker(content []byte) bool {
	text := string(content)
	for _, marker := range []string{
		"/* RAMPART_READ_CHECK */",
		"/* RAMPART_WRITE_CHECK */",
		"/* RAMPART_EDIT_CHECK */",
		"/* RAMPART_GREP_CHECK */",
		"/* RAMPART_DIST_CHECK_",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// findOpenClawBinary returns the path to the openclaw binary.
func findOpenClawBinary() (string, error) {
	if override := strings.TrimSpace(os.Getenv("RAMPART_OPENCLAW_BIN")); override != "" {
		if err := validateExecutableFile(override); err != nil {
			return "", fmt.Errorf("RAMPART_OPENCLAW_BIN=%q is not usable: %w", override, err)
		}
		return override, nil
	}

	// Try PATH first. This usually matches the OpenClaw install the human uses.
	if p, err := execLookPath("openclaw"); err == nil {
		return p, nil
	}
	// Try common install paths. PATH is preferred, but newly installed Windows
	// npm/git shims may not be visible until the user opens another terminal.
	home, _ := os.UserHomeDir()
	candidates := make([]string, 0, 8)
	if runtime.GOOS == "windows" {
		if appData := strings.TrimSpace(os.Getenv("APPDATA")); appData != "" {
			candidates = append(candidates, filepath.Join(appData, "npm", "openclaw.cmd"))
		}
		if localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localAppData != "" {
			candidates = append(candidates, filepath.Join(localAppData, "OpenClaw", "bin", "openclaw.cmd"))
		}
		candidates = append(candidates,
			filepath.Join(home, ".local", "bin", "openclaw.cmd"),
			filepath.Join(home, "AppData", "Roaming", "npm", "openclaw.cmd"),
		)
	} else {
		candidates = append(candidates,
			filepath.Join(home, ".local", "bin", "openclaw"),
			"/usr/local/bin/openclaw",
			"/usr/bin/openclaw",
			filepath.Join(home, ".npm-global", "bin", "openclaw"),
			"/opt/homebrew/bin/openclaw",
		)
	}
	for _, p := range candidates {
		if err := validateExecutableFile(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("openclaw binary not found in PATH or common locations; set RAMPART_OPENCLAW_BIN=/path/to/openclaw if you use a custom install")
}

func validateExecutableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("is a directory")
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("not executable")
	}
	return nil
}

func resolveOpenClawStateDir(openclawBin string) (stateDir string, configPath string, err error) {
	stateOverride := strings.TrimSpace(os.Getenv("OPENCLAW_STATE_DIR"))
	configOverride := strings.TrimSpace(os.Getenv("OPENCLAW_CONFIG_PATH"))
	if stateOverride != "" {
		stateDir = expandHomePath(stateOverride)
	}
	if configOverride != "" {
		configPath = expandHomePath(configOverride)
	}
	if stateDir != "" && configPath != "" {
		return stateDir, configPath, nil
	}
	if stateDir != "" {
		return stateDir, filepath.Join(stateDir, "openclaw.json"), nil
	}
	if configPath != "" {
		stateDir, err = defaultOpenClawStateDir()
		return stateDir, configPath, err
	}
	if strings.TrimSpace(openclawBin) != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := osexec.CommandContext(ctx, openclawBin, "config", "file")
		cmd.Env = append(os.Environ(), "OPENCLAW_HIDE_BANNER=1", "OPENCLAW_SUPPRESS_NOTES=1")
		out, runErr := cmd.Output()
		if runErr == nil {
			configPath, parseErr := parseOpenClawConfigPath(out)
			if parseErr == nil {
				return filepath.Dir(configPath), configPath, nil
			}
		}
	}
	stateDir, err = defaultOpenClawStateDir()
	if err != nil {
		return "", "", err
	}
	return stateDir, filepath.Join(stateDir, "openclaw.json"), nil
}

func defaultOpenClawStateDir() (string, error) {
	home := strings.TrimSpace(os.Getenv("OPENCLAW_HOME"))
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	} else {
		home = expandHomePath(home)
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return "", fmt.Errorf("resolve OpenClaw home: %w", err)
	}

	name := ".openclaw"
	if profile := strings.TrimSpace(os.Getenv("OPENCLAW_PROFILE")); profile != "" && profile != "default" {
		if strings.ContainsRune(profile, 0) {
			return "", fmt.Errorf("OPENCLAW_PROFILE contains a NUL byte")
		}
		name += "-" + profile
	}
	stateDir := filepath.Clean(filepath.Join(home, name))
	rel, err := filepath.Rel(home, stateDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("OPENCLAW_PROFILE resolves outside OPENCLAW_HOME")
	}
	return stateDir, nil
}

func expandHomePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

// getOpenClawVersion runs `openclaw --version` and returns the version string.
func getOpenClawVersion(openclawBin string) (string, error) {
	out, err := osexec.Command(openclawBin, "--version").Output()
	if err != nil {
		// Try version subcommand.
		out, err = osexec.Command(openclawBin, "version").Output()
		if err != nil {
			return "", fmt.Errorf("run %s --version: %w", openclawBin, err)
		}
	}
	fields := strings.Fields(string(out))
	for i := len(fields) - 1; i >= 0; i-- {
		candidate := strings.Trim(fields[i], "\"'`()[]{}<>,;:")
		candidate = strings.TrimPrefix(strings.TrimPrefix(candidate, "v"), "V")
		if parseCalVer(candidate) != nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not find an OpenClaw CalVer in version output %q", strings.TrimSpace(string(out)))
}

// openclawVersionAtLeast returns true if gotVersion >= minVersion.
// Version format: YYYY.M.D (e.g. 2026.3.28).
func openclawVersionAtLeast(gotVersion, minVersion string) (bool, error) {
	got := parseCalVer(gotVersion)
	min := parseCalVer(minVersion)
	if got == nil || min == nil {
		return false, fmt.Errorf("could not parse versions: got=%q min=%q", gotVersion, minVersion)
	}
	for i := range min {
		if i >= len(got) {
			return false, nil
		}
		if got[i] > min[i] {
			return true, nil
		}
		if got[i] < min[i] {
			return false, nil
		}
	}
	return true, nil
}

// parseCalVer splits a CalVer string like "2026.3.28" into []int{2026, 3, 28}.
func parseCalVer(v string) []int {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V"))
	main, suffix, hasSuffix := strings.Cut(v, "-")
	if hasSuffix {
		if suffix == "" {
			return nil
		}
		for _, r := range suffix {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '-' {
				return nil
			}
		}
	}
	parts := strings.Split(main, ".")
	if len(parts) < 3 {
		return nil
	}
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		result = append(result, n)
	}
	return result
}

const openClawExecAskReceiptVersion = 1

type openClawExecAskReceipt struct {
	Version         int    `json:"version"`
	ConfigPath      string `json:"configPath"`
	ManagedValue    string `json:"managedValue"`
	PreviousPresent bool   `json:"previousPresent"`
	PreviousValue   string `json:"previousValue,omitempty"`
	CreatedTools    bool   `json:"createdTools,omitempty"`
	CreatedExec     bool   `json:"createdExec,omitempty"`
}

func openClawExecAskReceiptPath(stateDir string) string {
	return filepath.Join(stateDir, ".rampart-exec-ask-receipt.json")
}

func normalizedOpenClawConfigPath(path string) string {
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
}

func readOpenClawExecAskReceipt(stateDir, configPath string) (openClawExecAskReceipt, bool, error) {
	path := openClawExecAskReceiptPath(stateDir)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return openClawExecAskReceipt{}, false, nil
	}
	if err != nil {
		return openClawExecAskReceipt{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return openClawExecAskReceipt{}, false, fmt.Errorf("refusing linked or non-regular OpenClaw ownership receipt %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return openClawExecAskReceipt{}, false, err
	}
	var receipt openClawExecAskReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return openClawExecAskReceipt{}, false, fmt.Errorf("parse OpenClaw ownership receipt: %w", err)
	}
	if receipt.Version != openClawExecAskReceiptVersion || receipt.ManagedValue == "" ||
		normalizedOpenClawConfigPath(receipt.ConfigPath) != normalizedOpenClawConfigPath(configPath) {
		return openClawExecAskReceipt{}, false, fmt.Errorf("OpenClaw ownership receipt does not match config %s", configPath)
	}
	return receipt, true, nil
}

func validOpenClawExecMode(value any) (string, bool) {
	mode, ok := value.(string)
	if !ok {
		return "", false
	}
	switch mode {
	case "deny", "allowlist", "ask", "auto", "full":
		return mode, true
	default:
		return "", false
	}
}

func expectedOpenClawExecPolicyForMode(mode string) (security, ask string) {
	switch mode {
	case "deny":
		return "deny", "off"
	case "allowlist":
		return "allowlist", "off"
	case "ask", "auto":
		return "allowlist", "on-miss"
	case "full":
		return "full", "off"
	default:
		return "", ""
	}
}

func ensureOpenClawExecApprovalConfig(_ string, stateDir, configPath string) error {
	if err := guardOpenClawExecModeReceiptTransition(stateDir, configPath); err != nil {
		return err
	}
	if _, err := normalizeOpenClawExecModeConfigAt(configPath); err != nil {
		return err
	}
	doc, err := loadOpenClawToolsConfigDocument(configPath)
	if err != nil {
		return err
	}
	var execCfg map[string]any
	if doc.tools != nil {
		if execValue, present := doc.tools["exec"]; present {
			var ok bool
			execCfg, ok = execValue.(map[string]any)
			if !ok {
				return fmt.Errorf("tools.exec must be a JSON object")
			}
			if modeValue, present := execCfg["mode"]; present {
				if _, ok := validOpenClawExecMode(modeValue); !ok {
					return fmt.Errorf("tools.exec.mode must be a supported string")
				}
				if _, present := execCfg["security"]; present {
					return fmt.Errorf("tools.exec.security cannot be combined with canonical tools.exec.mode")
				}
				if _, present := execCfg["ask"]; present {
					return fmt.Errorf("tools.exec.ask cannot be combined with canonical tools.exec.mode")
				}
				return nil
			}
		}
	}
	if doc.included {
		if askValue, present := execCfg["ask"]; present && askValue == "off" {
			// The included file is operator-authored. Its already-compatible
			// legacy value needs no Rampart ownership receipt or rewrite.
			return nil
		}
		return fmt.Errorf("include-backed exec policy requires operator resolution: set tools.exec.ask to off on legacy hosts, or migrate to tools.exec.mode on current hosts")
	}
	// Missing mode is expected on older supported hosts. Their legacy ask
	// field remains ownership-tracked so uninstall can restore user state.
	return setOpenClawExecAskAt(stateDir, configPath, "off")
}

type openClawExecModeMigration struct {
	configPath string
	before     []byte
	after      []byte
}

type openClawToolsConfigDocument struct {
	targetPath string
	target     map[string]any
	tools      map[string]any
	before     []byte
	included   bool
}

func loadOpenClawToolsConfigDocument(configPath string) (*openClawToolsConfigDocument, error) {
	doc := &openClawToolsConfigDocument{targetPath: configPath}
	info, err := os.Lstat(configPath)
	if os.IsNotExist(err) {
		return doc, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", configPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing linked or non-regular OpenClaw config %s", configPath)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", configPath, err)
	}
	var cfg map[string]any
	if err := decodeUserJSON(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configPath, err)
	}
	doc.target = cfg
	doc.before = data
	toolsValue, toolsPresent := cfg["tools"]
	if !toolsPresent {
		return doc, nil
	}
	tools, ok := toolsValue.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tools must be a JSON object")
	}
	includeValue, included := tools["$include"]
	if !included {
		doc.tools = tools
		return doc, nil
	}
	if len(tools) != 1 {
		return nil, fmt.Errorf("tools.$include cannot be combined with sibling keys")
	}
	include, ok := includeValue.(string)
	if !ok || include == "" || strings.ContainsRune(include, 0) {
		return nil, fmt.Errorf("tools.$include must be a non-empty path string")
	}
	targetPath := include
	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(filepath.Dir(configPath), targetPath)
	}
	root, rootErr := filepath.Abs(filepath.Dir(configPath))
	target, targetErr := filepath.Abs(targetPath)
	if rootErr != nil || targetErr != nil {
		return nil, fmt.Errorf("resolve tools.$include path")
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("tools.$include resolves outside the OpenClaw config directory")
	}
	includeInfo, err := os.Lstat(target)
	if err != nil {
		return nil, fmt.Errorf("inspect tools.$include: %w", err)
	}
	if includeInfo.Mode()&os.ModeSymlink != 0 || !includeInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("tools.$include must reference a regular, non-symlink file")
	}
	includedData, err := os.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("read tools.$include: %w", err)
	}
	var includedTools map[string]any
	if err := decodeUserJSON(includedData, &includedTools); err != nil {
		return nil, fmt.Errorf("parse tools.$include: %w", err)
	}
	if _, nested := includedTools["$include"]; nested {
		return nil, fmt.Errorf("nested tools.$include is unsupported")
	}
	doc.targetPath = target
	doc.target = includedTools
	doc.tools = includedTools
	doc.before = includedData
	doc.included = true
	return doc, nil
}

func (m *openClawExecModeMigration) changed() bool {
	return m != nil && len(m.after) != 0
}

func (m *openClawExecModeMigration) rollbackIfUnchanged() error {
	if !m.changed() {
		return nil
	}
	current, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("read current config: %w", err)
	}
	if !bytes.Equal(current, m.after) {
		return fmt.Errorf("refusing to overwrite OpenClaw config changed after exec-policy migration")
	}
	if err := atomicWritePrivateFile(m.configPath, m.before); err != nil {
		return fmt.Errorf("restore prior config: %w", err)
	}
	return nil
}

func guardOpenClawExecModeReceiptTransition(stateDir, configPath string) error {
	receipt, present, err := readOpenClawExecAskReceipt(stateDir, configPath)
	if err != nil || !present || !receipt.PreviousPresent {
		return err
	}
	doc, err := loadOpenClawToolsConfigDocument(configPath)
	if err != nil {
		return err
	}
	if doc.tools == nil {
		return nil
	}
	execValue, present := doc.tools["exec"]
	if !present {
		return nil
	}
	execCfg, ok := execValue.(map[string]any)
	if !ok {
		return fmt.Errorf("tools.exec must be a JSON object")
	}
	if _, modePresent := execCfg["mode"]; modePresent {
		return fmt.Errorf("tools.exec.mode conflicts with Rampart's receipt for a prior operator-owned tools.exec.ask value; resolve which policy to keep before continuing")
	}
	return nil
}

// migrateOpenClawExecModeConfigAt applies only OpenClaw's narrow tools.exec
// migration. It removes retired siblings only when every present legacy value
// exactly matches the canonical mode; mismatched or malformed evidence fails
// closed instead of silently weakening an operator's policy.
func migrateOpenClawExecModeConfigAt(configPath string) (*openClawExecModeMigration, error) {
	doc, err := loadOpenClawToolsConfigDocument(configPath)
	if err != nil {
		return nil, err
	}
	if doc.tools == nil {
		return nil, nil
	}
	execValue, execPresent := doc.tools["exec"]
	if !execPresent {
		return nil, nil
	}
	execCfg, ok := execValue.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tools.exec must be a JSON object")
	}
	modeValue, modePresent := execCfg["mode"]
	if !modePresent {
		return nil, nil
	}
	mode, ok := validOpenClawExecMode(modeValue)
	if !ok {
		return nil, fmt.Errorf("tools.exec.mode must be a supported string")
	}
	_, askPresent := execCfg["ask"]
	_, securityPresent := execCfg["security"]
	if !askPresent && !securityPresent {
		return nil, nil
	}
	expectedSecurity, expectedAsk := expectedOpenClawExecPolicyForMode(mode)
	if securityPresent && execCfg["security"] != expectedSecurity {
		return nil, fmt.Errorf("tools.exec.security conflicts with canonical tools.exec.mode %q", mode)
	}
	if askPresent && execCfg["ask"] != expectedAsk {
		return nil, fmt.Errorf("tools.exec.ask conflicts with canonical tools.exec.mode %q", mode)
	}
	delete(execCfg, "ask")
	delete(execCfg, "security")
	out, err := json.MarshalIndent(doc.target, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", doc.targetPath, err)
	}
	after := append(out, '\n')
	if err := atomicWritePrivateFile(doc.targetPath, after); err != nil {
		return nil, fmt.Errorf("write %s: %w", doc.targetPath, err)
	}
	return &openClawExecModeMigration{
		configPath: doc.targetPath,
		before:     append([]byte(nil), doc.before...),
		after:      append([]byte(nil), after...),
	}, nil
}

func normalizeOpenClawExecModeConfigAt(configPath string) (bool, error) {
	migration, err := migrateOpenClawExecModeConfigAt(configPath)
	return migration.changed(), err
}

func runWithOpenClawExecModeMigration(stateDir, configPath string, hostOperation func() error, w io.Writer) error {
	if err := guardOpenClawExecModeReceiptTransition(stateDir, configPath); err != nil {
		return err
	}
	migration, err := migrateOpenClawExecModeConfigAt(configPath)
	if err != nil {
		return fmt.Errorf("normalize OpenClaw exec policy: %w", err)
	}
	if err := hostOperation(); err != nil {
		if rollbackErr := migration.rollbackIfUnchanged(); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("roll back OpenClaw exec-policy migration: %w", rollbackErr))
		}
		return err
	}
	if migration.changed() {
		fmt.Fprintln(w, "✓ Removed equivalent retired tools.exec.ask/security fields superseded by tools.exec.mode")
	}
	return nil
}

func setOpenClawExecAskAt(stateDir, configPath, value string) error {
	if _, err := normalizeOpenClawExecModeConfigAt(configPath); err != nil {
		return err
	}
	// Load existing config or start fresh.
	var cfg map[string]any
	if data, err := os.ReadFile(configPath); err == nil {
		if err := decodeUserJSON(data, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", configPath, err)
		}
	} else if os.IsNotExist(err) {
		cfg = make(map[string]any)
		// Ensure parent directory exists.
		if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
			return fmt.Errorf("create .openclaw dir: %w", err)
		}
	} else {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	toolsValue, toolsPresent := cfg["tools"]
	tools, ok := toolsValue.(map[string]any)
	if toolsPresent && !ok {
		return fmt.Errorf("tools must be a JSON object")
	}
	if !toolsPresent {
		tools = make(map[string]any)
		cfg["tools"] = tools
	}
	if _, included := tools["$include"]; included {
		return fmt.Errorf("tools.exec.ask is include-backed; use `openclaw config set tools.exec.ask %s` so OpenClaw can preserve the authored include layout", value)
	}
	execValue, execPresent := tools["exec"]
	execCfg, ok := execValue.(map[string]any)
	if execPresent && !ok {
		return fmt.Errorf("tools.exec must be a JSON object")
	}
	if !execPresent {
		execCfg = make(map[string]any)
		tools["exec"] = execCfg
	}
	if modeValue, modePresent := execCfg["mode"]; modePresent {
		if _, ok := validOpenClawExecMode(modeValue); !ok {
			return fmt.Errorf("tools.exec.mode must be a supported string")
		}
		if value != "off" {
			return fmt.Errorf("tools.exec.mode is canonical; refusing to manage legacy tools.exec.ask=%q", value)
		}
		return nil
	}
	previousValue, previousPresent := execCfg["ask"]
	if previousPresent {
		if _, ok := previousValue.(string); !ok {
			return fmt.Errorf("tools.exec.ask must be a string")
		}
	}

	receipt, receiptExists, err := readOpenClawExecAskReceipt(stateDir, configPath)
	if err != nil {
		return err
	}
	if receiptExists && receipt.ManagedValue != value {
		return fmt.Errorf("OpenClaw ownership receipt manages tools.exec.ask=%q, not %q", receipt.ManagedValue, value)
	}
	if previousPresent && previousValue == value {
		// Do not invent ownership when the operator already configured this
		// value, but do validate any receipt that is present.
		return nil
	}

	receiptPath := openClawExecAskReceiptPath(stateDir)
	var priorReceiptData []byte
	if receiptExists {
		priorReceiptData, err = os.ReadFile(receiptPath)
		if err != nil {
			return fmt.Errorf("read prior OpenClaw ownership receipt: %w", err)
		}
	}
	// If an operator changed ask after a previous setup, this explicit setup run
	// takes ownership again while remembering the operator's latest value. That
	// value, rather than a stale older receipt, is restored on uninstall.
	receipt = openClawExecAskReceipt{
		Version:         openClawExecAskReceiptVersion,
		ConfigPath:      normalizedOpenClawConfigPath(configPath),
		ManagedValue:    value,
		PreviousPresent: previousPresent,
		CreatedTools:    !toolsPresent,
		CreatedExec:     !execPresent,
	}
	if previousPresent {
		receipt.PreviousValue = previousValue.(string)
	}
	receiptData, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWritePrivateFile(receiptPath, append(receiptData, '\n')); err != nil {
		return fmt.Errorf("write OpenClaw ownership receipt: %w", err)
	}
	execCfg["ask"] = value

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	if err := atomicWritePrivateFile(configPath, data); err != nil {
		if receiptExists {
			if restoreErr := atomicWritePrivateFile(receiptPath, priorReceiptData); restoreErr != nil {
				return fmt.Errorf("write %s: %w (also failed to restore prior ownership receipt: %v)", configPath, err, restoreErr)
			}
		} else {
			_ = os.Remove(openClawExecAskReceiptPath(stateDir))
		}
		return fmt.Errorf("write %s: %w", configPath, err)
	}
	return nil
}

func restoreOpenClawExecAskFromReceipt(stateDir, configPath string) (bool, error) {
	receipt, exists, err := readOpenClawExecAskReceipt(stateDir, configPath)
	if err != nil || !exists {
		return false, err
	}
	receiptPath := openClawExecAskReceiptPath(stateDir)
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return false, os.Remove(receiptPath)
	}
	if err != nil {
		return false, err
	}
	var cfg map[string]any
	if err := decodeUserJSON(data, &cfg); err != nil {
		return false, fmt.Errorf("parse %s while restoring tools.exec.ask: %w", configPath, err)
	}
	tools, _ := cfg["tools"].(map[string]any)
	execCfg, _ := tools["exec"].(map[string]any)
	if _, modePresent := execCfg["mode"]; modePresent {
		// A canonical mode supersedes both legacy fields. Never reintroduce a
		// receipt's old ask value next to mode because current OpenClaw rejects
		// that combination.
		if receipt.PreviousPresent {
			return false, fmt.Errorf("tools.exec.mode conflicts with Rampart's receipt for a prior operator-owned tools.exec.ask value; resolve which policy to keep before uninstalling")
		}
		if err := os.Remove(receiptPath); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		return false, nil
	}
	current, currentPresent := execCfg["ask"]
	if !currentPresent || current != receipt.ManagedValue {
		if err := os.Remove(receiptPath); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		return false, nil
	}
	if receipt.PreviousPresent {
		execCfg["ask"] = receipt.PreviousValue
	} else {
		delete(execCfg, "ask")
		if receipt.CreatedExec && len(execCfg) == 0 {
			delete(tools, "exec")
		}
		if receipt.CreatedTools && len(tools) == 0 {
			delete(cfg, "tools")
		}
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err
	}
	if err := atomicWritePrivateFile(configPath, append(out, '\n')); err != nil {
		return false, err
	}
	if err := os.Remove(receiptPath); err != nil && !os.IsNotExist(err) {
		return true, err
	}
	return true, nil
}

// installOpenClawPolicy copies the embedded openclaw.yaml policy to ~/.rampart/policies/.
func installOpenClawPolicy(w io.Writer, errW io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}

	policyDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		return fmt.Errorf("create policy dir: %w", err)
	}

	policyData, err := policies.Profile("openclaw")
	if err != nil {
		return fmt.Errorf("load embedded openclaw.yaml: %w", err)
	}

	destPath := filepath.Join(policyDir, "openclaw.yaml")
	if err := atomicWritePrivateFile(destPath, versionStampedPolicyContent(policyData)); err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}

	fmt.Fprintf(w, "✓ OpenClaw policy profile installed at %s\n", destPath)
	return nil
}

// cleanOpenClawConfig removes legacy approval settings only when a top-level
// Rampart bridge key positively identifies the old integration. Generic ask
// settings alone may be operator-authored and are never sufficient ownership.
func cleanOpenClawConfig(w io.Writer, errW io.Writer) error {
	bin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("find openclaw: %w", err)
	}
	_, configPath, err := resolveOpenClawStateDir(bin)
	if err != nil {
		return fmt.Errorf("resolve OpenClaw config: %w", err)
	}
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		fmt.Fprintln(w, "  No openclaw.json found — nothing to clean")
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	var cfg map[string]any
	if err := decodeUserJSON(data, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", configPath, err)
	}

	bridgeKeys := []string{"rampart", "rampartBridge", "rampart_bridge", "rampartUrl", "rampart_url"}
	ownedBridgeKeys := make([]string, 0, len(bridgeKeys))
	for _, key := range bridgeKeys {
		if _, ok := cfg[key]; ok {
			ownedBridgeKeys = append(ownedBridgeKeys, key)
		}
	}
	if len(ownedBridgeKeys) == 0 {
		fmt.Fprintln(w, "  No positively owned legacy bridge config found")
		return nil
	}

	changed := false

	// Remove top-level ask: on-miss (legacy; Rampart plugin handles it now).
	if askVal, ok := cfg["ask"].(string); ok && (askVal == "on-miss" || askVal == "always") {
		delete(cfg, "ask")
		changed = true
		fmt.Fprintf(w, "  Removed top-level ask: %s\n", askVal)
	}

	// Remove tools.exec.ask: on-miss if present (plugin hook replaces this).
	if tools, ok := cfg["tools"].(map[string]any); ok {
		if execCfg, ok := tools["exec"].(map[string]any); ok {
			if askVal, ok := execCfg["ask"].(string); ok && (askVal == "on-miss" || askVal == "always") {
				delete(execCfg, "ask")
				changed = true
				fmt.Fprintf(w, "  Removed tools.exec.ask: %s\n", askVal)
			}
		}
	}

	// Remove legacy rampart bridge config keys if present.
	for _, key := range ownedBridgeKeys {
		delete(cfg, key)
		changed = true
		fmt.Fprintf(w, "  Removed legacy bridge config key: %s\n", key)
	}

	if !changed {
		fmt.Fprintln(w, "  openclaw.json is already clean")
		return nil
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	out = append(out, '\n')

	if err := atomicWritePrivateFile(configPath, out); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}

	return nil
}

// isOpenClawInstalled returns true if the openclaw binary can be found.
func isOpenClawInstalled() bool {
	_, err := findOpenClawBinary()
	return err == nil
}

type openClawPluginState struct {
	Installed       bool
	Allowed         bool
	Enabled         bool
	Dir             string
	ManifestVersion string
	RuntimeVersion  string
	StartupExplicit bool
}

func getOpenClawPluginState() openClawPluginState {
	bin, err := findOpenClawBinary()
	var stateDir, configPath string
	if err == nil {
		stateDir, configPath, err = resolveOpenClawStateDir(bin)
		if err != nil {
			return openClawPluginState{}
		}
	} else {
		if strings.TrimSpace(os.Getenv("RAMPART_OPENCLAW_BIN")) != "" {
			return openClawPluginState{}
		}
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return openClawPluginState{}
		}
		stateDir = filepath.Join(home, ".openclaw")
		configPath = filepath.Join(stateDir, "openclaw.json")
	}

	return getOpenClawPluginStateAt(stateDir, configPath)
}

func getOpenClawPluginStateAt(stateDir, configPath string) openClawPluginState {
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	info, err := os.Lstat(pluginDir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return openClawPluginState{}
	}

	state := openClawPluginState{Installed: true, Dir: pluginDir}
	state.readInstalledPluginMetadata()
	plugins, err := loadOpenClawPluginsConfig(configPath)
	if err != nil {
		return state
	}
	state.Enabled = true
	state.Allowed = true
	if allowValue, present := plugins["allow"]; present {
		allow, ok := allowValue.([]any)
		if !ok {
			state.Allowed = false
			return state
		}
		state.Allowed = false
		for _, id := range allow {
			if id == "rampart" {
				state.Allowed = true
				break
			}
		}
	}
	if entriesValue, present := plugins["entries"]; present {
		entries, ok := entriesValue.(map[string]any)
		if !ok {
			state.Enabled = false
			return state
		}
		if entryValue, present := entries["rampart"]; present {
			entry, ok := entryValue.(map[string]any)
			if !ok {
				state.Enabled = false
				return state
			}
			if enabledValue, present := entry["enabled"]; present {
				enabled, ok := enabledValue.(bool)
				if !ok {
					state.Enabled = false
					return state
				}
				state.Enabled = enabled
			}
		}
	}
	return state
}

func (s *openClawPluginState) readInstalledPluginMetadata() {
	manifestPath := filepath.Join(s.Dir, "openclaw.plugin.json")
	data, err := os.ReadFile(manifestPath)
	if err == nil {
		var manifest struct {
			Version    string `json:"version"`
			Activation struct {
				OnStartup *bool `json:"onStartup"`
			} `json:"activation"`
		}
		if json.Unmarshal(data, &manifest) == nil {
			s.ManifestVersion = strings.TrimSpace(manifest.Version)
			s.StartupExplicit = manifest.Activation.OnStartup != nil && *manifest.Activation.OnStartup
		}
	}
	indexData, err := os.ReadFile(filepath.Join(s.Dir, "index.js"))
	if err != nil {
		return
	}
	s.RuntimeVersion = extractOpenClawPluginRuntimeVersion(string(indexData))
}

func extractOpenClawPluginRuntimeVersion(js string) string {
	marker := "export const version = \""
	idx := strings.Index(js, marker)
	if idx < 0 {
		return ""
	}
	start := idx + len(marker)
	end := strings.Index(js[start:], "\"")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(js[start : start+end])
}

// isOpenClawPluginInstalled returns true if the Rampart plugin directory
// exists under the active OpenClaw state directory.
func isOpenClawPluginInstalled() bool {
	return getOpenClawPluginState().Installed
}

// openClawPluginManaged verifies ownership before an integration directory is
// removed. The directory name alone is insufficient: a user could have a
// different plugin named rampart. Older Rampart releases consistently shipped
// the manifest identity and this runtime banner even when their versions
// differed from the current binary.
func openClawPluginManaged(pluginDir string) bool {
	manifestPath := filepath.Join(pluginDir, "openclaw.plugin.json")
	runtimePath := filepath.Join(pluginDir, "index.js")
	for _, path := range []string{manifestPath, runtimePath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return false
	}
	var manifest struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Author     string `json:"author"`
		Homepage   string `json:"homepage"`
		Repository string `json:"repository"`
	}
	if json.Unmarshal(manifestData, &manifest) != nil || manifest.ID != "rampart" || manifest.Name != "Rampart" {
		return false
	}
	author := strings.ToLower(strings.TrimSpace(manifest.Author))
	homepage := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(manifest.Homepage)), "/")
	repository := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(manifest.Repository)), "/"), ".git")
	if author != "peg" || (homepage != "https://rampart.sh" && repository != "https://github.com/peg/rampart") {
		return false
	}
	runtimeData, err := os.ReadFile(runtimePath)
	return err == nil && strings.Contains(string(runtimeData), "Rampart OpenClaw Plugin")
}

// removeOpenClawRampartConfig removes only Rampart-owned plugin records from a
// directly authored JSON config. Current host-native removal is preferred
// because OpenClaw also owns include write-through and its SQLite plugin index.
func removeOpenClawRampartConfig(configPath string) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read OpenClaw config %s: %w", configPath, err)
	}
	var cfg map[string]any
	if err := decodeUserJSON(data, &cfg); err != nil {
		return false, fmt.Errorf("parse OpenClaw config %s: %w", configPath, err)
	}

	changed := false
	if plugins, ok := cfg["plugins"].(map[string]any); ok {
		for _, key := range []string{"entries", "installs"} {
			if records, ok := plugins[key].(map[string]any); ok {
				if _, exists := records["rampart"]; exists {
					delete(records, "rampart")
					changed = true
				}
			}
		}
		if allow, ok := plugins["allow"].([]any); ok {
			kept := make([]any, 0, len(allow))
			for _, value := range allow {
				if id, ok := value.(string); ok && id == "rampart" {
					changed = true
					continue
				}
				kept = append(kept, value)
			}
			// Preserve an explicitly configured allowlist even when Rampart was
			// its only entry. Deleting the key would widen plugin discovery.
			plugins["allow"] = kept
		}
	}
	if !changed {
		return false, nil
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal OpenClaw config %s: %w", configPath, err)
	}
	out = append(out, '\n')
	if err := atomicWritePrivateFile(configPath, out); err != nil {
		return false, fmt.Errorf("write OpenClaw config %s: %w", configPath, err)
	}
	return true, nil
}

func openClawConfigHasRampart(configPath string) bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var cfg map[string]any
	if json.Unmarshal(data, &cfg) != nil {
		return false
	}
	plugins, _ := cfg["plugins"].(map[string]any)
	if plugins == nil {
		return false
	}
	for _, key := range []string{"entries", "installs"} {
		if records, ok := plugins[key].(map[string]any); ok {
			if _, exists := records["rampart"]; exists {
				return true
			}
		}
	}
	if allow, ok := plugins["allow"].([]any); ok {
		for _, value := range allow {
			if id, ok := value.(string); ok && id == "rampart" {
				return true
			}
		}
	}
	return false
}

// removeOpenClawNativePluginWithHostAt uses OpenClaw's lifecycle transaction
// when available so config includes and the SQLite plugin index stay coherent.
// Direct removal is a host-unavailable fallback and is still limited to paths
// with positive Rampart identity.
func removeOpenClawNativePluginWithHostAt(stateDir, configPath string, hostUninstall func() error) (bool, error) {
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	hookDir := filepath.Join(stateDir, "hooks", "rampart")
	configOwned := openClawConfigHasRampart(configPath) || openClawConfigMayReferenceRampart(configPath)
	pluginOwned, err := inspectOpenClawInstallPath(pluginDir, "plugin", openClawPluginManaged)
	if err != nil {
		return false, err
	}
	hookOwned, err := inspectOpenClawInstallPath(hookDir, "hook", openClawHookManaged)
	if err != nil {
		return false, err
	}
	if configOwned && !pluginOwned && !hookOwned {
		return false, fmt.Errorf("refusing to remove config-only OpenClaw plugin ID rampart without a positively owned Rampart plugin path")
	}
	if !pluginOwned && !hookOwned && !configOwned {
		if _, receiptPresent, receiptErr := readOpenClawExecAskReceipt(stateDir, configPath); receiptErr != nil {
			return false, receiptErr
		} else if receiptPresent {
			return restoreOpenClawExecAskFromReceipt(stateDir, configPath)
		}
		return false, nil
	}
	if hostUninstall != nil && (pluginOwned || configOwned) {
		// Current OpenClaw rejects mode combined with its retired security/ask
		// fields. Repair only equivalent pairs for the duration of the host
		// transaction, and restore exact bytes if the host operation fails.
		if err := runWithOpenClawExecModeMigration(stateDir, configPath, hostUninstall, io.Discard); err != nil {
			return false, fmt.Errorf("OpenClaw managed plugin uninstall: %w", err)
		}
		if _, err := os.Lstat(pluginDir); err == nil {
			return false, fmt.Errorf("OpenClaw reported successful uninstall but managed plugin path remains at %s", pluginDir)
		} else if !os.IsNotExist(err) {
			return false, fmt.Errorf("validate OpenClaw plugin removal: %w", err)
		}
	} else {
		var migration *openClawExecModeMigration
		_, receiptPresent, receiptErr := readOpenClawExecAskReceipt(stateDir, configPath)
		if receiptErr != nil {
			return false, fmt.Errorf("inspect OpenClaw exec ownership receipt: %w", receiptErr)
		}
		if configOwned || receiptPresent {
			if err := guardOpenClawExecModeReceiptTransition(stateDir, configPath); err != nil {
				return false, err
			}
			migration, err = migrateOpenClawExecModeConfigAt(configPath)
			if err != nil {
				return false, fmt.Errorf("normalize OpenClaw exec policy before fallback uninstall: %w", err)
			}
		}
		rollbackMigration := func(operationErr error) error {
			if rollbackErr := migration.rollbackIfUnchanged(); rollbackErr != nil {
				return errors.Join(operationErr, fmt.Errorf("roll back OpenClaw exec-policy migration: %w", rollbackErr))
			}
			return operationErr
		}
		if pluginOwned {
			if err := os.RemoveAll(pluginDir); err != nil {
				return false, rollbackMigration(fmt.Errorf("remove Rampart OpenClaw plugin %s: %w", pluginDir, err))
			}
		}
		if _, err := removeOpenClawRampartConfig(configPath); err != nil {
			return false, rollbackMigration(err)
		}
	}

	// A legacy hook path is outside the native plugin's managed install target,
	// so older hosts can leave it behind even after their lifecycle uninstall.
	if hookOwned {
		if stillOwned, err := inspectOpenClawInstallPath(hookDir, "hook", openClawHookManaged); err != nil {
			return false, err
		} else if stillOwned {
			if err := os.RemoveAll(hookDir); err != nil {
				return false, fmt.Errorf("remove managed legacy OpenClaw hook %s: %w", hookDir, err)
			}
		}
	}
	if _, err := restoreOpenClawExecAskFromReceipt(stateDir, configPath); err != nil {
		return false, fmt.Errorf("restore OpenClaw tools.exec.ask from ownership receipt: %w", err)
	}
	return true, nil
}

func isOpenClawPluginConfigured() bool {
	state := getOpenClawPluginState()
	if !state.Installed {
		return false
	}
	return state.Allowed && state.Enabled
}

// detectOpenClawVersion finds the OpenClaw binary and returns its version string.
// Returns an error if OpenClaw is not installed or version cannot be determined.
func detectOpenClawVersion() (string, error) {
	bin, err := findOpenClawBinary()
	if err != nil {
		return "", err
	}
	return getOpenClawVersion(bin)
}

func modernOpenClawVersion() (string, bool) {
	version, err := detectOpenClawVersion()
	if err != nil {
		return "", false
	}
	ok, err := openclawVersionAtLeast(version, openclawMinVersion)
	return version, err == nil && ok
}

func ensureServeRunningForURL(w io.Writer, errW io.Writer, serveURL string) error {
	serveURL = strings.TrimRight(strings.TrimSpace(serveURL), "/")
	if serveURL == "" {
		return fmt.Errorf("rampart policy service URL is empty")
	}
	if isSetupServeReachableAt(serveURL) {
		fmt.Fprintf(w, "✓ Rampart serve is running at %s\n", serveURL)
		return nil
	}
	defaultURL := fmt.Sprintf("http://localhost:%d", defaultServePort)
	if serveURL != defaultURL {
		return fmt.Errorf("configured Rampart policy service %s is unreachable; start that service or remove the endpoint override before retrying", serveURL)
	}

	fmt.Fprintln(w, "Starting rampart serve...")
	rampartBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find rampart binary: %w", err)
	}

	installCmd := osexec.Command(rampartBin, "serve", "install")
	installCmd.Stdout = w
	installCmd.Stderr = errW
	installErr := installCmd.Run()
	if installErr == nil {
		// Wait up to 3 seconds for serve to come up.
		for i := 0; i < 6; i++ {
			time.Sleep(500 * time.Millisecond)
			if isSetupServeReachableAt(serveURL) {
				fmt.Fprintln(w, "✓ Rampart serve started (system service)")
				return nil
			}
		}
		fmt.Fprintln(errW, "⚠ rampart serve service install did not become reachable; trying background fallback")
	} else {
		fmt.Fprintf(errW, "⚠ rampart serve service install failed (%v); trying background fallback\n", installErr)
	}

	if err := startServeBackgroundFallback(rampartBin, serveURL, w, errW); err != nil {
		if installErr != nil {
			return fmt.Errorf("rampart serve service install failed (%v) and background fallback failed: %w", installErr, err)
		}
		return fmt.Errorf("rampart serve installed but not reachable after 3s; background fallback failed: %w", err)
	}
	return nil
}

func startServeBackgroundFallback(rampartBin, serveURL string, w io.Writer, errW io.Writer) error {
	cmd := osexec.Command(rampartBin, "serve", "--background")
	cmd.Stdout = w
	cmd.Stderr = errW
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rampart serve --background: %w", err)
	}
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		if isSetupServeReachableAt(serveURL) {
			fmt.Fprintln(w, "✓ Rampart serve started (background fallback)")
			return nil
		}
	}
	return fmt.Errorf("rampart serve --background did not become reachable after 5s")
}

func isSetupServeReachableAt(serveURL string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	healthURL := strings.TrimRight(serveURL, "/") + "/healthz"
	return isRampartHealthReady(ctx, newRampartHTTPClient(2*time.Second), healthURL)
}
