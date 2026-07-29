// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peg/rampart/internal/filetxn"
	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

func newProtectCmd(rootOpts *rootOptions) *cobra.Command {
	var noRestart bool
	var noVerify bool
	var reinstall bool
	var serveURL string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "protect [agent]",
		Short: "Protect an installed agent with safe managed defaults",
		Long: `Install and activate Rampart's managed safety guard for an agent harness.

No policy file or rule authoring is required. Protect installs the native
integration, starts Rampart's policy service, enables fail-closed degraded
behavior, and verifies the installed boundary. Native-hook integrations use
non-destructive adapter canaries; OpenClaw exercises its live plugin path.

Without an agent argument, Rampart detects installed supported agents and
protects each one through its strongest available native boundary.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDefaultRampartDirAccessible(); err != nil {
				return fmt.Errorf("protect: prepare Rampart data directory: %w", err)
			}
			target := ""
			if len(args) == 1 {
				target = strings.ToLower(strings.TrimSpace(args[0]))
			}
			var drivers []integrationDriver
			if target == "" {
				detected, err := detectInstalledIntegrationDrivers()
				if err != nil {
					return fmt.Errorf("protect: detect installed agents: %w", err)
				}
				if len(detected) == 0 {
					return fmt.Errorf("protect: no supported agent detected (supported: OpenClaw, Claude Code, Codex, Antigravity, GitHub Copilot, Cline; Gemini CLI and Hermes remain experimental)")
				}
				drivers = detected
				fmt.Fprintf(cmd.OutOrStdout(), "Detected %d supported agent(s): ", len(drivers))
				for i, driver := range drivers {
					if i > 0 {
						fmt.Fprint(cmd.OutOrStdout(), ", ")
					}
					fmt.Fprint(cmd.OutOrStdout(), driver.DisplayName)
				}
				fmt.Fprintln(cmd.OutOrStdout())
			} else {
				driver, ok := findIntegrationDriver(target)
				if !ok {
					return fmt.Errorf("protect: unsupported target %q (supported: openclaw, claude-code, codex, antigravity, copilot, cline; Gemini CLI and Hermes remain experimental)", target)
				}
				if !driver.AutoProtect {
					return fmt.Errorf("protect: %s remains experimental; use `rampart setup %s` and `rampart verify %s` for explicit testing", driver.DisplayName, driver.ID, driver.VerifyTarget)
				}
				if !integrationDriverSupportsPlatform(driver, runtime.GOOS) {
					return fmt.Errorf("protect: %s is not supported on %s", driver.DisplayName, runtime.GOOS)
				}
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("protect: resolve home: %w", err)
				}
				if driver.Installed == nil || !driver.Installed(home) {
					return fmt.Errorf("protect: %s was not found; install it first, then rerun `rampart protect %s`", driver.DisplayName, driver.ID)
				}
				drivers = []integrationDriver{driver}
				if !driver.OpenClaw && (cmd.Flags().Changed("no-restart") || cmd.Flags().Changed("reinstall")) {
					return fmt.Errorf("protect: --no-restart and --reinstall apply only to OpenClaw")
				}
			}

			var protectErrors []error
			for _, driver := range drivers {
				if driver.OpenClaw {
					if err := runProtectOpenClaw(cmd, protectOpenClawOptions{NoRestart: noRestart, NoVerify: noVerify, Reinstall: reinstall, ServeURL: serveURL, Timeout: timeout}); err != nil {
						protectErrors = append(protectErrors, fmt.Errorf("%s: %w", driver.DisplayName, err))
					}
					continue
				}
				if err := runProtectHookDriver(cmd, rootOpts, driver, protectHookOptions{NoVerify: noVerify, ServeURL: serveURL, Timeout: timeout}); err != nil {
					protectErrors = append(protectErrors, fmt.Errorf("%s: %w", driver.DisplayName, err))
				}
			}
			return errors.Join(protectErrors...)
		},
	}

	cmd.Flags().BoolVar(&noRestart, "no-restart", false, "Do not restart the OpenClaw gateway after configuration")
	cmd.Flags().BoolVar(&noVerify, "no-verify", false, "Skip active behavioral verification")
	cmd.Flags().BoolVar(&reinstall, "reinstall", false, "Reinstall the bundled OpenClaw plugin even when it is current")
	cmd.Flags().StringVar(&serveURL, "serve-url", "", "Rampart service URL override used for verification")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Timeout for each active verification check")
	return cmd
}

type protectHookOptions struct {
	NoVerify bool
	ServeURL string
	Timeout  time.Duration
}

func runProtectHookDriver(cmd *cobra.Command, rootOpts *rootOptions, driver integrationDriver, opts protectHookOptions) error {
	w := cmd.OutOrStdout()
	errW := cmd.ErrOrStderr()
	fmt.Fprintf(w, "\nProtecting %s through %s...\n", driver.DisplayName, driver.Boundary)
	guardPath, err := installManagedGuardPolicy()
	if err != nil {
		return fmt.Errorf("protect %s: install managed Guard policy: %w", driver.ID, err)
	}
	fmt.Fprintf(w, "✓ Managed Guard policy installed at %s\n", guardPath)
	if err := ensureServeRunning(w, errW); err != nil {
		return fmt.Errorf("protect %s: start Rampart policy service: %w", driver.ID, err)
	}
	if err := runIntegrationSetup(cmd, rootOpts, driver); err != nil {
		return fmt.Errorf("protect %s: configure native integration: %w", driver.ID, err)
	}
	if opts.NoVerify {
		fmt.Fprintf(w, "Rampart protection is configured for %s. Behavioral verification was skipped.\n", driver.DisplayName)
		fmt.Fprintf(w, "Run `rampart verify %s` to prove the boundary.\n", driver.VerifyTarget)
		return nil
	}
	resolvedURL, err := resolveServeURLStrict(opts.ServeURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return fmt.Errorf("protect %s: resolve serve URL: %w", driver.ID, err)
	}
	time.Sleep(150 * time.Millisecond)
	report := runBehavioralVerification(cmd.Context(), driver.VerifyTarget, resolvedURL, opts.Timeout)
	fmt.Fprintln(w)
	printVerificationReport(w, report)
	if report.Summary.Failed > 0 {
		return exitCodeError{code: 1}
	}
	if report.Summary.Unverified > 0 {
		return exitCodeError{code: 2}
	}
	fmt.Fprintf(w, "\nRampart configuration and adapter verification passed for %s. Restart or reload the host if setup requested it.\n", driver.DisplayName)
	return nil
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
	if err := configureOpenClawGuardMode(bin, w, errW); err != nil {
		return fmt.Errorf("protect: enable fail-closed OpenClaw guard mode: %w", err)
	}
	fmt.Fprintln(w, "✓ Enabled fail-closed behavior when Rampart is unavailable")

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
	return ocplugin.Current(state.Dir)
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

func configureOpenClawGuardMode(openclawBin string, w, errW io.Writer) error {
	stateDir, configPath, err := resolveOpenClawStateDir(openclawBin)
	if err != nil {
		return fmt.Errorf("resolve active OpenClaw state: %w", err)
	}
	if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
		return fmt.Errorf("repair tools.exec.ask ownership: %w", err)
	}
	if err := ensureOpenClawApprovalHardening(w, errW); err != nil {
		return fmt.Errorf("repair OpenClaw approval timeout: %w", err)
	}

	const patch = `{"plugins":{"entries":{"rampart":{"enabled":true,"config":{"failOpen":false,"failOpenTools":null,"serveUrl":"http://localhost:9090"}}}}}`
	var stdout, stderr bytes.Buffer
	cmd := osexec.Command(openclawBin, "config", "patch", "--stdin")
	cmd.Stdin = strings.NewReader(patch)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	patchErr := cmd.Run()
	if patchErr == nil {
		_, _ = io.Copy(w, &stdout)
		_, _ = io.Copy(errW, &stderr)
		return nil
	}

	// config patch is newer than Rampart's original OpenClaw host floor. Probe
	// the command before falling back: a supported command that rejected the
	// write (schema, Nix mode, permissions) must remain a hard failure.
	if err := osexec.Command(openclawBin, "config", "patch", "--help").Run(); err == nil {
		_, _ = io.Copy(w, &stdout)
		_, _ = io.Copy(errW, &stderr)
		return fmt.Errorf("OpenClaw config patch: %w", patchErr)
	}

	// Older supported hosts still provide path-based config set. Apply the
	// fail-closed values before enablement. Each host-owned write is validated
	// and include-aware; no Rampart whole-file rewrite is used.
	legacyWrites := [][]string{
		{"config", "set", "plugins.entries.rampart.config.failOpenTools", "[]", "--json"},
		{"config", "set", "plugins.entries.rampart.config.failOpen", "false", "--json"},
		{"config", "set", "plugins.entries.rampart.config.serveUrl", `"http://localhost:9090"`, "--json"},
		{"config", "set", "plugins.entries.rampart.enabled", "true", "--json"},
	}
	for _, args := range legacyWrites {
		legacyCmd := osexec.Command(openclawBin, args...)
		legacyCmd.Stdout = w
		legacyCmd.Stderr = errW
		if err := legacyCmd.Run(); err != nil {
			return fmt.Errorf("OpenClaw config patch unavailable (%v); fallback `%s` failed: %w", patchErr, strings.Join(args, " "), err)
		}
	}
	return nil
}

func atomicWritePrivateFile(path string, data []byte) error {
	return atomicWritePrivateFileWithMode(path, data, 0o600)
}

func atomicWritePrivateFileWithMode(path string, data []byte, mode os.FileMode) error {
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
	if err := secureFilePermissions(tmpPath); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure temporary file: %w", err)
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
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if err := filetxn.Replace(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
