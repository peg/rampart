// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

func newProtectCmd() *cobra.Command {
	var noRestart bool
	var noVerify bool
	var reinstall bool
	var serveURL string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "protect [openclaw]",
		Short: "Protect an installed agent with safe managed defaults",
		Long: `Install and activate Rampart's managed safety guard for an agent harness.

No policy file or rule authoring is required. Protect installs the native
integration, starts Rampart's policy service, enables fail-closed degraded
behavior, and verifies the live boundary with non-destructive canaries.

OpenClaw is the first fully supported zero-configuration target.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDefaultRampartDirAccessible(); err != nil {
				return fmt.Errorf("protect: prepare Rampart data directory: %w", err)
			}
			target := ""
			if len(args) == 1 {
				target = strings.ToLower(strings.TrimSpace(args[0]))
			}
			if target == "" {
				if !isOpenClawInstalled() {
					return fmt.Errorf("protect: no supported agent harness detected; OpenClaw is currently the zero-configuration target (Hermes support remains experimental)")
				}
				target = "openclaw"
			}
			if target != "openclaw" {
				return fmt.Errorf("protect: unsupported target %q; OpenClaw is currently supported and Hermes remains experimental", target)
			}
			if !isOpenClawInstalled() {
				return fmt.Errorf("protect: OpenClaw was not found; install OpenClaw first, then rerun `rampart protect openclaw`")
			}

			return runProtectOpenClaw(cmd, protectOpenClawOptions{
				NoRestart: noRestart,
				NoVerify:  noVerify,
				Reinstall: reinstall,
				ServeURL:  serveURL,
				Timeout:   timeout,
			})
		},
	}

	cmd.Flags().BoolVar(&noRestart, "no-restart", false, "Do not restart the OpenClaw gateway after configuration")
	cmd.Flags().BoolVar(&noVerify, "no-verify", false, "Skip active behavioral verification")
	cmd.Flags().BoolVar(&reinstall, "reinstall", false, "Reinstall the bundled OpenClaw plugin even when it is current")
	cmd.Flags().StringVar(&serveURL, "serve-url", "", "Rampart service URL override used for verification")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Timeout for each active verification check")
	return cmd
}

type protectOpenClawOptions struct {
	NoRestart bool
	NoVerify  bool
	Reinstall bool
	ServeURL  string
	Timeout   time.Duration
}

func runProtectOpenClaw(cmd *cobra.Command, opts protectOpenClawOptions) error {
	w := cmd.OutOrStdout()
	errW := cmd.ErrOrStderr()
	fmt.Fprintln(w, "Protecting OpenClaw with Rampart managed defaults...")

	guardPath, err := installManagedGuardPolicy()
	if err != nil {
		return fmt.Errorf("protect: install managed Guard policy: %w", err)
	}
	fmt.Fprintf(w, "✓ Managed Guard policy installed at %s\n", guardPath)
	// Install every managed policy before setup starts rampart serve. A fresh
	// protect run must never briefly start with only the Guard layer loaded.
	if err := installOpenClawPolicy(w, errW); err != nil {
		return fmt.Errorf("protect: install managed OpenClaw policy: %w", err)
	}

	state := getOpenClawPluginState()
	if opts.Reinstall || !openClawPluginCurrent(state) {
		if err := runSetupOpenClawPlugin(w, errW); err != nil {
			return fmt.Errorf("protect: configure OpenClaw integration: %w", err)
		}
	} else {
		fmt.Fprintf(w, "✓ OpenClaw plugin v%s is installed and enabled\n", ocplugin.Version())
		if err := ensureServeRunning(w, errW); err != nil {
			return fmt.Errorf("protect: start Rampart policy service: %w", err)
		}
	}
	bin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("protect: find OpenClaw: %w", err)
	}
	_, configPath, err := resolveOpenClawStateDir(bin)
	if err != nil {
		return fmt.Errorf("protect: resolve OpenClaw config: %w", err)
	}
	changed, err := configureOpenClawGuardModeAtPath(configPath)
	if err != nil {
		return fmt.Errorf("protect: enable fail-closed OpenClaw guard mode: %w", err)
	}
	if changed {
		fmt.Fprintln(w, "✓ Enabled fail-closed behavior when Rampart is unavailable")
	} else {
		fmt.Fprintln(w, "✓ Fail-closed degraded behavior is already enabled")
	}

	if !opts.NoRestart {
		if err := restartOpenClawGateway(); err != nil {
			return fmt.Errorf("protect: restart OpenClaw gateway: %w", err)
		}
		fmt.Fprintln(w, "✓ Restarted the OpenClaw gateway")
	} else {
		fmt.Fprintln(w, "! Gateway restart skipped; restart OpenClaw before relying on the new boundary")
	}

	if opts.NoVerify {
		fmt.Fprintln(w, "\nRampart protection is configured. Behavioral verification was skipped.")
		fmt.Fprintln(w, "Run `rampart verify openclaw` after the gateway is running.")
		return nil
	}

	resolvedURL, err := resolveServeURLStrict(opts.ServeURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return fmt.Errorf("protect: resolve serve URL: %w", err)
	}
	// The policy directory is hot-reloaded. A short delay also gives a freshly
	// restarted local gateway a chance to expose the plugin verification method.
	time.Sleep(350 * time.Millisecond)
	report := runBehavioralVerification(cmd.Context(), "openclaw", resolvedURL, opts.Timeout)
	fmt.Fprintln(w)
	printVerificationReport(w, report)
	if report.Summary.Failed > 0 {
		return exitCodeError{code: 1}
	}
	if report.Summary.Unverified > 0 {
		return exitCodeError{code: 2}
	}
	fmt.Fprintln(w, "\nRampart is actively protecting OpenClaw.")
	return nil
}

func openClawPluginCurrent(state openClawPluginState) bool {
	want := strings.TrimSpace(ocplugin.Version())
	if !state.Installed || !state.Allowed || !state.Enabled || !state.StartupExplicit ||
		state.ManifestVersion != want || state.RuntimeVersion != want {
		return false
	}
	installed, err := os.ReadFile(filepath.Join(state.Dir, "index.js"))
	if err != nil {
		return false
	}
	bundled, err := ocplugin.PluginFS.ReadFile("index.js")
	return err == nil && bytes.Equal(installed, bundled)
}

func installManagedGuardPolicy() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	policyDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		return "", fmt.Errorf("create policy directory: %w", err)
	}
	content, err := policies.Profile("guard")
	if err != nil {
		return "", err
	}
	dest := filepath.Join(policyDir, "guard.yaml")
	if err := atomicWritePrivateFile(dest, versionStampedPolicyContent(content)); err != nil {
		return "", err
	}
	return dest, nil
}

func configureOpenClawGuardModeAtPath(configPath string) (bool, error) {
	var cfg map[string]any
	data, err := os.ReadFile(configPath)
	if err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return false, fmt.Errorf("parse %s: %w", configPath, err)
		}
	} else if os.IsNotExist(err) {
		cfg = make(map[string]any)
	} else {
		return false, fmt.Errorf("read %s: %w", configPath, err)
	}

	plugins, err := jsonObject(cfg, "plugins")
	if err != nil {
		return false, err
	}
	entries, err := jsonObject(plugins, "entries")
	if err != nil {
		return false, err
	}
	rampartEntry, err := jsonObject(entries, "rampart")
	if err != nil {
		return false, err
	}
	pluginConfig, err := jsonObject(rampartEntry, "config")
	if err != nil {
		return false, err
	}

	changed := false
	if enabled, ok := rampartEntry["enabled"].(bool); !ok || !enabled {
		rampartEntry["enabled"] = true
		changed = true
	}
	if failOpen, ok := pluginConfig["failOpen"].(bool); !ok || failOpen {
		pluginConfig["failOpen"] = false
		changed = true
	}
	const managedServeURL = "http://localhost:9090"
	if serveURL, ok := pluginConfig["serveUrl"].(string); !ok || serveURL != managedServeURL {
		pluginConfig["serveUrl"] = managedServeURL
		changed = true
	}
	if _, ok := pluginConfig["failOpenTools"]; ok {
		delete(pluginConfig, "failOpenTools")
		changed = true
	}
	if !changed {
		return false, nil
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal %s: %w", configPath, err)
	}
	out = append(out, '\n')
	if err := atomicWritePrivateFile(configPath, out); err != nil {
		return false, fmt.Errorf("write %s: %w", configPath, err)
	}
	return true, nil
}

func jsonObject(parent map[string]any, key string) (map[string]any, error) {
	value, ok := parent[key]
	if !ok {
		child := make(map[string]any)
		parent[key] = child
		return child, nil
	}
	child, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON object", key)
	}
	return child, nil
}

func atomicWritePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".rampart-write-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
