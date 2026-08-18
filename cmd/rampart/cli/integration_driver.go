// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peg/rampart/internal/detect"
	"github.com/spf13/cobra"
)

// integrationDriver is Rampart's in-tree contract for an agent boundary. It
// deliberately contains only lifecycle operations shared by the CLI. Tool
// payload normalization remains in the adapter that owns the host protocol.
type integrationDriver struct {
	ID           string
	Aliases      []string
	DisplayName  string
	Boundary     string
	VerifyTarget string
	// VerificationCommand names the non-behavioral proof command for drivers
	// that cannot safely participate in `rampart verify --all`.
	VerificationCommand string
	ProofLevel          assuranceLevel
	Executables         []string
	Installed           func(home string) bool
	SetupCommand        func(opts *rootOptions) *cobra.Command
	VerifyChecks        func(ctx context.Context, timeout time.Duration) []verificationCheck
	OpenClaw            bool
	AutoProtect         bool
	ServiceRequired     bool
	Platforms           []string
	Configured          func(home string) bool
	AssuranceConfigured func(home string) bool
	ProtectionLabel     string
	ProtectionState     func(home string) string
}

func supportedIntegrationDrivers() []integrationDriver {
	return []integrationDriver{
		{
			ID: "openclaw", DisplayName: "OpenClaw", Boundary: "native plugin", VerifyTarget: "openclaw", OpenClaw: true,
			ProofLevel: assuranceHostVerified, Executables: []string{"openclaw"},
			AutoProtect: true, ServiceRequired: true, Platforms: []string{"linux", "darwin"},
			Installed:       func(_ string) bool { return isOpenClawInstalled() },
			Configured:      func(_ string) bool { return isOpenClawPluginConfigured() },
			ProtectionState: openClawProtectionState,
			VerifyChecks: func(ctx context.Context, timeout time.Duration) []verificationCheck {
				return []verificationCheck{verifyOpenClawPluginLive(ctx, timeout)}
			},
		},
		{
			ID: "claude-code", Aliases: []string{"claude"}, DisplayName: "Claude Code", Boundary: "native hooks", VerifyTarget: "claude-code",
			ProofLevel: assuranceAdapterVerified, Executables: []string{"claude"},
			AutoProtect: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed: func(home string) bool {
				return integrationBinaryOrPathInstalled("claude", claudeConfigDir(home))
			},
			SetupCommand: func(opts *rootOptions) *cobra.Command { return newSetupClaudeCodeCmd(opts) },
			Configured:   claudeHooksConfiguredForHome,
			AssuranceConfigured: func(home string) bool {
				assessment := claudeHookLoadAssessmentForHome(home)
				return !assessment.Blocked && !assessment.Unverified
			},
			ProtectionLabel: "Claude Code (hooks)",
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyClaudeHooksInstalled(), verifyNativeHookAdapter(ctx, "claude-code")}
			},
		},
		{
			ID: "codex", DisplayName: "Codex", Boundary: "native hooks", VerifyTarget: "codex",
			ProofLevel: assuranceAdapterVerified, Executables: []string{"codex"},
			AutoProtect: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed: func(home string) bool {
				return integrationBinaryOrPathInstalled("codex", codexHomeDir(home))
			},
			SetupCommand:    func(opts *rootOptions) *cobra.Command { return newSetupCodexCmd(opts) },
			Configured:      codexHooksConfiguredForHome,
			ProtectionState: codexProtectionState,
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyCodexHooksInstalled(), verifyCodexHookAdapter(ctx)}
			},
		},
		{
			ID: "hermes", DisplayName: "Hermes Agent", Boundary: "experimental native plugin",
			VerificationCommand: "rampart doctor", Executables: []string{"hermes"},
			AutoProtect: false, ServiceRequired: true, Platforms: []string{"linux", "darwin"},
			Installed: func(home string) bool {
				state := detectHermesPluginStateForHome(home)
				if state.Installed {
					return true
				}
				_, err := execLookPath("hermes")
				return err == nil
			},
			SetupCommand:    func(_ *rootOptions) *cobra.Command { return newSetupHermesCmd() },
			ProtectionLabel: "Hermes Agent (plugin)",
			Configured: func(home string) bool {
				state := detectHermesPluginStateForHome(home)
				return state.Installed && state.Enabled && state.ManifestValid && state.HookDeclared
			},
		},
		{
			ID: "gemini", Aliases: []string{"gemini-cli"}, DisplayName: "Gemini CLI", Boundary: "experimental native hooks", VerifyTarget: "gemini",
			ProofLevel: assuranceAdapterVerified, Executables: []string{"gemini"},
			AutoProtect: false, Platforms: []string{"linux", "darwin"},
			Installed: func(home string) bool {
				_, err := execLookPath("gemini")
				return err == nil
			},
			SetupCommand:    func(_ *rootOptions) *cobra.Command { return newSetupGeminiCmd() },
			Configured:      geminiHooksConfiguredForHome,
			ProtectionLabel: "Gemini CLI (hooks)",
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyGeminiHooksInstalled(), verifyGeminiHookAdapter(ctx)}
			},
		},
		{
			ID: "antigravity", Aliases: []string{"agy"}, DisplayName: "Antigravity CLI / IDE", Boundary: "native plugin hook", VerifyTarget: "antigravity",
			ProofLevel: assuranceAdapterVerified, Executables: []string{"agy"},
			AutoProtect: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed: func(home string) bool {
				return integrationBinaryOrPathInstalled("agy",
					filepath.Join(home, ".gemini", "antigravity"),
					filepath.Join(home, ".gemini", "antigravity-cli"),
				)
			},
			SetupCommand:    func(_ *rootOptions) *cobra.Command { return newSetupAntigravityCmd() },
			Configured:      antigravityPluginConfiguredForHome,
			ProtectionLabel: "Antigravity CLI / IDE (plugin)",
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyAntigravityPluginInstalled(), verifyAntigravityHookAdapter(ctx)}
			},
		},
		{
			ID: "copilot", Aliases: []string{"copilot-cli", "github-copilot"}, DisplayName: "GitHub Copilot CLI / VS Code", Boundary: "native hooks", VerifyTarget: "copilot",
			ProofLevel: assuranceAdapterVerified, Executables: []string{"copilot"},
			AutoProtect: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed:    func(home string) bool { return copilotInstalledForHome(home) },
			SetupCommand: func(_ *rootOptions) *cobra.Command { return newSetupCopilotCmd() },
			Configured:   copilotHooksConfiguredForHome,
			AssuranceConfigured: func(home string) bool {
				workingDir, _ := os.Getwd()
				_, disabled := copilotCLIUserHooksDisabled(home, workingDir)
				return !disabled
			},
			ProtectionLabel: "GitHub Copilot CLI / VS Code (hooks)",
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyCopilotHooksInstalled(), verifyCopilotHookAdapter(ctx)}
			},
		},
		{
			ID: "cursor", DisplayName: "Cursor", Boundary: "native hook", VerifyTarget: "cursor",
			ProofLevel: assuranceAdapterVerified, Executables: []string{"cursor", "cursor-agent"},
			AutoProtect: true, ServiceRequired: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed:       cursorInstalledForHome,
			SetupCommand:    func(opts *rootOptions) *cobra.Command { return newSetupCursorCmd(opts) },
			Configured:      cursorHooksConfiguredForHome,
			ProtectionLabel: "Cursor (Agent hook)",
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyCursorHooksInstalled(), verifyCursorHookAdapter(ctx)}
			},
		},
		{
			ID: "cline", DisplayName: "Cline", Boundary: "native hooks", VerifyTarget: "cline",
			ProofLevel: assuranceAdapterVerified, Executables: []string{"cline"},
			AutoProtect: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed: func(home string) bool {
				return integrationBinaryOrPathInstalled("cline", filepath.Join(home, "Documents", "Cline"), filepath.Join(home, ".cline")) ||
					detect.ClineExtensionInstalled(home)
			},
			SetupCommand:    func(opts *rootOptions) *cobra.Command { return newSetupClineCmd(opts) },
			Configured:      clineHooksConfiguredForHome,
			ProtectionLabel: "Cline (hooks)",
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyClineHooksInstalled(), verifyNativeHookAdapter(ctx, "cline")}
			},
		},
	}
}

func integrationDriverConfigured(driver integrationDriver, home string) bool {
	return driver.Configured != nil && driver.Configured(home)
}

func integrationConfiguredForAssurance(driver integrationDriver, home string) bool {
	if !integrationDriverConfigured(driver, home) {
		return false
	}
	return driver.AssuranceConfigured == nil || driver.AssuranceConfigured(home)
}

func integrationProtectionState(driver integrationDriver, home string) string {
	if driver.ProtectionState != nil {
		return driver.ProtectionState(home)
	}
	if integrationConfiguredForAssurance(driver, home) {
		return driver.ProtectionLabel
	}
	return ""
}

func integrationBinaryOrPathInstalled(binary string, paths ...string) bool {
	if _, err := execLookPath(binary); err == nil {
		return true
	}
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func findIntegrationDriver(target string) (integrationDriver, bool) {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, driver := range supportedIntegrationDrivers() {
		if target == driver.ID {
			return driver, true
		}
		for _, alias := range driver.Aliases {
			if target == alias {
				return driver, true
			}
		}
	}
	return integrationDriver{}, false
}

func integrationDriverSupportsPlatform(driver integrationDriver, goos string) bool {
	for _, platform := range driver.Platforms {
		if platform == goos {
			return true
		}
	}
	return false
}

func integrationDriverVerificationCommand(driver integrationDriver) string {
	if command := strings.TrimSpace(driver.VerificationCommand); command != "" {
		return command
	}
	if target := strings.TrimSpace(driver.VerifyTarget); target != "" && driver.VerifyChecks != nil {
		return "rampart verify " + target
	}
	return ""
}

func detectInstalledIntegrationDrivers() ([]integrationDriver, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home: %w", err)
	}
	var detected []integrationDriver
	for _, driver := range supportedIntegrationDrivers() {
		if driver.AutoProtect && integrationDriverSupportsPlatform(driver, runtime.GOOS) && driver.Installed != nil && driver.Installed(home) {
			detected = append(detected, driver)
		}
	}
	return detected, nil
}

func runIntegrationSetup(parent *cobra.Command, opts *rootOptions, driver integrationDriver) error {
	if driver.SetupCommand == nil {
		return fmt.Errorf("no setup command registered for %s", driver.DisplayName)
	}
	setup := driver.SetupCommand(opts)
	setup.SetContext(parent.Context())
	setup.SetIn(parent.InOrStdin())
	setup.SetOut(parent.OutOrStdout())
	setup.SetErr(parent.ErrOrStderr())
	if setup.RunE == nil {
		return fmt.Errorf("no setup implementation registered for %s", driver.DisplayName)
	}
	return setup.RunE(setup, nil)
}
