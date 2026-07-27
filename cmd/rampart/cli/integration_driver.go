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
	Installed    func(home string) bool
	SetupCommand func(opts *rootOptions) *cobra.Command
	VerifyChecks func(ctx context.Context, timeout time.Duration) []verificationCheck
	OpenClaw     bool
	AutoProtect  bool
	Platforms    []string
}

func supportedIntegrationDrivers() []integrationDriver {
	return []integrationDriver{
		{
			ID: "openclaw", DisplayName: "OpenClaw", Boundary: "native plugin", VerifyTarget: "openclaw", OpenClaw: true,
			AutoProtect: true, Platforms: []string{"linux", "darwin"},
			Installed: func(_ string) bool { return isOpenClawInstalled() },
			VerifyChecks: func(ctx context.Context, timeout time.Duration) []verificationCheck {
				return []verificationCheck{verifyOpenClawPluginLive(ctx, timeout)}
			},
		},
		{
			ID: "claude-code", Aliases: []string{"claude"}, DisplayName: "Claude Code", Boundary: "native hooks", VerifyTarget: "claude-code",
			AutoProtect: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed: func(home string) bool {
				return integrationBinaryOrPathInstalled("claude", filepath.Join(home, ".claude"))
			},
			SetupCommand: func(opts *rootOptions) *cobra.Command { return newSetupClaudeCodeCmd(opts) },
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyClaudeHooksInstalled(), verifyNativeHookAdapter(ctx, "claude-code")}
			},
		},
		{
			ID: "codex", DisplayName: "Codex", Boundary: "native hooks", VerifyTarget: "codex",
			AutoProtect: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed: func(home string) bool {
				return integrationBinaryOrPathInstalled("codex", codexHomeDir(home))
			},
			SetupCommand: func(opts *rootOptions) *cobra.Command { return newSetupCodexCmd(opts) },
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyCodexHooksInstalled(), verifyCodexHookAdapter(ctx)}
			},
		},
		{
			ID: "gemini", Aliases: []string{"gemini-cli"}, DisplayName: "Gemini CLI", Boundary: "experimental native hooks", VerifyTarget: "gemini",
			AutoProtect: false, Platforms: []string{"linux", "darwin"},
			Installed: func(home string) bool {
				_, err := execLookPath("gemini")
				return err == nil
			},
			SetupCommand: func(_ *rootOptions) *cobra.Command { return newSetupGeminiCmd() },
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyGeminiHooksInstalled(), verifyGeminiHookAdapter(ctx)}
			},
		},
		{
			ID: "copilot", Aliases: []string{"copilot-cli", "github-copilot"}, DisplayName: "GitHub Copilot CLI / VS Code", Boundary: "native hooks", VerifyTarget: "copilot",
			AutoProtect: true, Platforms: []string{"linux", "darwin", "windows"},
			Installed:    func(home string) bool { return copilotInstalledForHome(home) },
			SetupCommand: func(_ *rootOptions) *cobra.Command { return newSetupCopilotCmd() },
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyCopilotHooksInstalled(), verifyCopilotHookAdapter(ctx)}
			},
		},
		{
			ID: "cline", DisplayName: "Cline", Boundary: "native hooks", VerifyTarget: "cline",
			AutoProtect: true, Platforms: []string{"linux", "darwin"},
			Installed: func(home string) bool {
				return integrationBinaryOrPathInstalled("cline", filepath.Join(home, "Documents", "Cline"))
			},
			SetupCommand: func(opts *rootOptions) *cobra.Command { return newSetupClineCmd(opts) },
			VerifyChecks: func(ctx context.Context, _ time.Duration) []verificationCheck {
				return []verificationCheck{verifyClineHooksInstalled(), verifyNativeHookAdapter(ctx, "cline")}
			},
		},
	}
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
	setup.SetIn(parent.InOrStdin())
	setup.SetOut(parent.OutOrStdout())
	setup.SetErr(parent.ErrOrStderr())
	if setup.RunE == nil {
		return fmt.Errorf("no setup implementation registered for %s", driver.DisplayName)
	}
	return setup.RunE(setup, nil)
}
