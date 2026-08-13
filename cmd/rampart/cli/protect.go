// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
			if err := prepareManagedProtection(rootOpts); err != nil {
				return err
			}
			target := ""
			if len(args) == 1 {
				target = strings.ToLower(strings.TrimSpace(args[0]))
			}
			drivers, err := resolveProtectionTargets(target)
			if err != nil {
				return err
			}
			if target == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Detected %d supported agent(s): ", len(drivers))
				for i, driver := range drivers {
					if i > 0 {
						fmt.Fprint(cmd.OutOrStdout(), ", ")
					}
					fmt.Fprint(cmd.OutOrStdout(), driver.DisplayName)
				}
				fmt.Fprintln(cmd.OutOrStdout())
			} else {
				driver := drivers[0]
				if !driver.OpenClaw && (cmd.Flags().Changed("no-restart") || cmd.Flags().Changed("reinstall")) {
					return fmt.Errorf("protect: --no-restart and --reinstall apply only to OpenClaw")
				}
			}

			_, err = runProtectionPlan(cmd, rootOpts, drivers, protectionPlanOptions{
				NoRestart: noRestart,
				NoVerify:  noVerify,
				Reinstall: reinstall,
				ServeURL:  serveURL,
				Timeout:   timeout,
			})
			return err
		},
	}

	cmd.Flags().BoolVar(&noRestart, "no-restart", false, "Do not restart the OpenClaw gateway after configuration")
	cmd.Flags().BoolVar(&noVerify, "no-verify", false, "Skip active behavioral verification")
	cmd.Flags().BoolVar(&reinstall, "reinstall", false, "Reinstall the bundled OpenClaw plugin even when it is current")
	cmd.Flags().StringVar(&serveURL, "serve-url", "", "Rampart service URL override used for startup, host configuration, and verification")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Timeout for each active verification check")
	return cmd
}

func resolveProtectionTargets(target string) ([]integrationDriver, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		drivers, err := detectInstalledIntegrationDrivers()
		if err != nil {
			return nil, fmt.Errorf("protect: detect installed agents: %w", err)
		}
		if len(drivers) == 0 {
			return nil, fmt.Errorf("protect: no supported agent detected (supported: OpenClaw, Claude Code, Codex, Antigravity, GitHub Copilot, Cline; Gemini CLI and Hermes remain experimental)")
		}
		return drivers, nil
	}

	driver, ok := findIntegrationDriver(target)
	if !ok {
		return nil, fmt.Errorf("protect: unsupported target %q (supported: openclaw, claude-code, codex, antigravity, copilot, cline; Gemini CLI and Hermes remain experimental)", target)
	}
	if !driver.AutoProtect {
		verification := integrationDriverVerificationCommand(driver)
		if verification == "" {
			verification = "rampart doctor"
		}
		return nil, fmt.Errorf("protect: %s remains experimental; use `rampart setup %s` and `%s` for explicit testing", driver.DisplayName, driver.ID, verification)
	}
	if !integrationDriverSupportsPlatform(driver, runtime.GOOS) {
		return nil, fmt.Errorf("protect: %s is not supported on %s", driver.DisplayName, runtime.GOOS)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("protect: resolve home: %w", err)
	}
	if driver.Installed == nil || !driver.Installed(home) {
		return nil, fmt.Errorf("protect: %s was not found; install it first, then rerun `rampart protect %s`", driver.DisplayName, driver.ID)
	}
	return []integrationDriver{driver}, nil
}

type protectionPlanOptions struct {
	NoRestart bool
	NoVerify  bool
	Reinstall bool
	ServeURL  string
	Timeout   time.Duration
}

type protectionPlanSummary struct {
	Attempted int
	Succeeded int
}

// runProtectionPlan is the single managed setup-and-verification path used by
// protect and compatibility onboarding commands. Global Guard installation is
// performed once, while each integration retains ownership of its host-specific
// transaction and verification semantics.
func runProtectionPlan(cmd *cobra.Command, rootOpts *rootOptions, drivers []integrationDriver, opts protectionPlanOptions) (protectionPlanSummary, error) {
	summary := protectionPlanSummary{Attempted: len(drivers)}
	if err := prepareManagedProtection(rootOpts); err != nil {
		return summary, err
	}
	resolvedURL, err := resolveServeURLStrict(opts.ServeURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return summary, fmt.Errorf("protect: resolve serve URL: %w", err)
	}
	guardPath, err := installManagedGuardPolicy()
	if err != nil {
		return summary, fmt.Errorf("protect: install managed Guard policy: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Managed Guard policy installed at %s\n", guardPath)

	ordered := make([]integrationDriver, 0, len(drivers))
	for _, driver := range drivers {
		if driver.OpenClaw {
			ordered = append(ordered, driver)
		}
	}
	for _, driver := range drivers {
		if !driver.OpenClaw {
			ordered = append(ordered, driver)
		}
	}

	serviceReady := false
	var protectErrors []error
	for _, driver := range ordered {
		if driver.OpenClaw {
			err := runProtectOpenClaw(cmd, protectOpenClawOptions{
				NoRestart: opts.NoRestart,
				NoVerify:  opts.NoVerify,
				Reinstall: opts.Reinstall,
				ServeURL:  resolvedURL,
				Timeout:   opts.Timeout,
			})
			if err != nil {
				protectErrors = append(protectErrors, fmt.Errorf("%s: %w", driver.DisplayName, err))
				continue
			}
			serviceReady = true
			summary.Succeeded++
			continue
		}

		if !serviceReady {
			if err := ensureServeRunningForURL(cmd.OutOrStdout(), cmd.ErrOrStderr(), resolvedURL); err != nil {
				protectErrors = append(protectErrors, fmt.Errorf("start Rampart policy service: %w", err))
				break
			}
			serviceReady = true
		}
		if err := runProtectHookDriver(cmd, rootOpts, driver, protectHookOptions{
			NoVerify: opts.NoVerify,
			ServeURL: resolvedURL,
			Timeout:  opts.Timeout,
		}); err != nil {
			protectErrors = append(protectErrors, fmt.Errorf("%s: %w", driver.DisplayName, err))
			continue
		}
		summary.Succeeded++
	}

	// quickstart historically supports a policy-and-service-only mode through
	// --agents none. Preserve that compatibility without inventing a second
	// service startup path.
	if len(ordered) == 0 {
		if err := ensureServeRunningForURL(cmd.OutOrStdout(), cmd.ErrOrStderr(), resolvedURL); err != nil {
			protectErrors = append(protectErrors, fmt.Errorf("start Rampart policy service: %w", err))
		}
	}
	return summary, errors.Join(protectErrors...)
}

func validateManagedProtectionConfig(rootOpts *rootOptions) error {
	if rootOpts == nil {
		return nil
	}
	configPath := strings.TrimSpace(rootOpts.configPath)
	if configPath == "" || configPath == "rampart.yaml" {
		return nil
	}
	return fmt.Errorf("protect: custom --config is not supported by managed protection yet; use the default configuration or manage the service explicitly with `rampart serve install`")
}

func prepareManagedProtection(rootOpts *rootOptions) error {
	if err := validateManagedProtectionConfig(rootOpts); err != nil {
		return err
	}
	if err := ensureDefaultRampartDirAccessible(); err != nil {
		return fmt.Errorf("protect: prepare Rampart data directory: %w", err)
	}
	return nil
}

type protectHookOptions struct {
	NoVerify bool
	ServeURL string
	Timeout  time.Duration
}

func runProtectHookDriver(cmd *cobra.Command, rootOpts *rootOptions, driver integrationDriver, opts protectHookOptions) error {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "\nProtecting %s through %s...\n", driver.DisplayName, driver.Boundary)
	if err := runIntegrationSetup(cmd, rootOpts, driver); err != nil {
		return fmt.Errorf("protect %s: configure native integration: %w", driver.ID, err)
	}
	if opts.NoVerify {
		fmt.Fprintf(w, "Rampart protection is configured for %s. Behavioral verification was skipped.\n", driver.DisplayName)
		fmt.Fprintf(w, "Run `rampart verify %s` to prove the boundary.\n", driver.VerifyTarget)
		return nil
	}
	time.Sleep(150 * time.Millisecond)
	report := runBehavioralVerification(cmd.Context(), driver.VerifyTarget, opts.ServeURL, opts.Timeout)
	receiptErr := writeVerificationReceipt(report)
	fmt.Fprintln(w)
	printVerificationReport(w, report)
	if report.Summary.Failed > 0 {
		return exitCodeError{code: 1}
	}
	if report.Summary.Unverified > 0 {
		return exitCodeError{code: 2}
	}
	if receiptErr != nil {
		return fmt.Errorf("protect %s: persist assurance evidence: %w", driver.ID, receiptErr)
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
	resolvedURL, err := resolveServeURLStrict(opts.ServeURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return fmt.Errorf("protect: resolve serve URL: %w", err)
	}
	resolvedURL, err = normalizeOpenClawServeURL(resolvedURL)
	if err != nil {
		return fmt.Errorf("protect: invalid OpenClaw policy service URL: %w", err)
	}
	fmt.Fprintln(w, "Protecting OpenClaw with Rampart managed defaults...")
	// Install every managed policy before setup starts rampart serve. A fresh
	// protect run must never briefly start with only the Guard layer loaded.
	if err := installOpenClawPolicy(w, errW); err != nil {
		return fmt.Errorf("protect: install managed OpenClaw policy: %w", err)
	}

	state := getOpenClawPluginState()
	if opts.Reinstall || !openClawPluginCurrent(state) {
		if err := runSetupOpenClawPluginForServeURL(w, errW, resolvedURL); err != nil {
			return fmt.Errorf("protect: configure OpenClaw integration: %w", err)
		}
	} else {
		fmt.Fprintf(w, "✓ OpenClaw plugin v%s is installed and enabled\n", ocplugin.Version())
		if err := ensureServeRunningForURL(w, errW, resolvedURL); err != nil {
			return fmt.Errorf("protect: start Rampart policy service: %w", err)
		}
	}
	bin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("protect: find OpenClaw: %w", err)
	}
	if err := configureOpenClawGuardMode(bin, resolvedURL, w, errW); err != nil {
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

	// The policy directory is hot-reloaded. A short delay also gives a freshly
	// restarted local gateway a chance to expose the plugin verification method.
	time.Sleep(350 * time.Millisecond)
	report := runBehavioralVerification(cmd.Context(), "openclaw", resolvedURL, opts.Timeout)
	receiptErr := writeVerificationReceipt(report)
	fmt.Fprintln(w)
	printVerificationReport(w, report)
	if report.Summary.Failed > 0 {
		return exitCodeError{code: 1}
	}
	if report.Summary.Unverified > 0 {
		return exitCodeError{code: 2}
	}
	if receiptErr != nil {
		return fmt.Errorf("protect: persist assurance evidence: %w", receiptErr)
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

func configureOpenClawGuardMode(openclawBin, serveURL string, w, errW io.Writer) error {
	serveURL, err := normalizeOpenClawServeURL(serveURL)
	if err != nil {
		return err
	}
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

	patch := fmt.Sprintf(`{"plugins":{"entries":{"rampart":{"enabled":true,"config":{"failOpen":false,"failOpenTools":null,"serveUrl":%s}}}}}`, strconv.Quote(serveURL))
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
		{"config", "set", "plugins.entries.rampart.config.serveUrl", strconv.Quote(serveURL), "--json"},
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

func normalizeOpenClawServeURL(raw string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("expected an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("credentials, paths, queries, and fragments are not allowed")
	}
	if !isLoopbackURL(trimmed) {
		return "", fmt.Errorf("OpenClaw's native plugin accepts only a loopback Rampart service")
	}
	return trimmed, nil
}

func atomicWritePrivateFile(path string, data []byte) error {
	return atomicWritePrivateFileWithMode(path, data, 0o600)
}

func atomicWritePrivateFileWithMode(path string, data []byte, mode os.FileMode) error {
	return atomicWritePrivateFileWithModeAndDurability(path, data, mode, true)
}

// atomicWriteRecoverablePrivateFile atomically publishes owner-only derived
// state without forcing it to stable storage. It is only for files that are
// safely regenerated when absent, stale, or partial after a system crash.
func atomicWriteRecoverablePrivateFile(path string, data []byte) error {
	return atomicWritePrivateFileWithModeAndDurability(path, data, 0o600, false)
}

func atomicWritePrivateFileWithModeAndDurability(path string, data []byte, mode os.FileMode, durable bool) error {
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
	if durable {
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	replace := filetxn.ReplaceAtomic
	if durable {
		replace = filetxn.Replace
	}
	if err := replace(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
