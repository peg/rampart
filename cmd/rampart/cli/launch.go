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
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// launchTarget says how to start one agent against a local model. Keys of
// launchTargets are integration driver IDs, so driver aliases (for example
// "claude" for "claude-code") resolve for free. Adding an agent is one entry.
type launchTarget struct {
	// ollama is the `ollama launch <integration>` name.
	ollama string
	// direct builds a fallback invocation for when ollama is not on PATH.
	// Nil means the agent can only be launched through ollama.
	direct func(model string) (bin string, args []string)
}

var launchTargets = map[string]launchTarget{
	"claude-code": {ollama: "claude"},
	"codex": {ollama: "codex", direct: func(model string) (string, []string) {
		if model == "" {
			return "codex", []string{"--oss"}
		}
		return "codex", []string{"--oss", "-m", model}
	}},
}

func launchTargetNames() string {
	names := make([]string, 0, len(launchTargets))
	for id := range launchTargets {
		driver, _ := findIntegrationDriver(id)
		name := id
		if len(driver.Aliases) > 0 {
			name = driver.Aliases[0]
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// launchDeps are the side effects of launch, injected so tests can prove the
// agent is never started when protection cannot be confirmed.
type launchDeps struct {
	lookPath func(string) (string, error)
	protect  func(cmd *cobra.Command, opts *rootOptions, driver integrationDriver, serveURL string, timeout time.Duration) error
	run      func(cmd *cobra.Command, bin string, args []string) error
}

func newLaunchCmd(opts *rootOptions) *cobra.Command {
	return newLaunchCmdWith(opts, launchDeps{lookPath: execLookPath, protect: protectForLaunch, run: runLaunchedAgent})
}

func newLaunchCmdWith(opts *rootOptions, deps launchDeps) *cobra.Command {
	var model, serveURL string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "launch <agent> [--model <name>] [-- agent args...]",
		Short: "Verify Rampart protection, then start an agent on a local model",
		Long: `Start a coding agent against a local model with Rampart enforcing every
tool call.

Launch installs Rampart's hooks for the agent if they are missing, then runs
the same safe canaries as ` + "`rampart verify`" + `. If any check fails or cannot be
verified, the agent is not started. Otherwise it delegates to
` + "`ollama launch <agent>`" + ` (or, for Codex without Ollama, ` + "`codex --oss`" + `).

Supported agents: ` + launchTargetNames() + `.`,
		Example: `  rampart launch claude --model qwen3-coder
  rampart launch codex --model gpt-oss:20b -- --sandbox workspace-write`,
		Args: func(cmd *cobra.Command, args []string) error {
			n := len(args)
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				n = dash
			}
			if n != 1 {
				return fmt.Errorf("launch: expected exactly one agent (%s) before --", launchTargetNames())
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			driver, target, err := resolveLaunchTarget(args[0])
			if err != nil {
				return err
			}
			model = strings.TrimSpace(model)
			if strings.HasPrefix(model, "-") {
				return fmt.Errorf("launch: invalid --model %q", model)
			}
			bin, argv, err := launchCommand(target, model, args[1:], deps.lookPath)
			if err != nil {
				return err
			}
			// Fail closed: nothing below runs unless protection is confirmed.
			if err := deps.protect(cmd, opts, driver, serveURL, timeout); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "\nrampart launch: refusing to start %s: %v\n", driver.DisplayName, err)
				fmt.Fprintf(cmd.ErrOrStderr(), "Fix the checks above, or run `rampart verify %s` for details.\n", driver.VerifyTarget)
				return exitCodeError{code: 1}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\n✓ Rampart protection verified for %s. Starting: %s %s\n", driver.DisplayName, bin, strings.Join(argv, " "))
			return deps.run(cmd, bin, argv)
		},
	}
	cmd.Flags().StringVar(&model, "model", "", "Local model name passed to the agent (for example qwen3-coder)")
	cmd.Flags().StringVar(&serveURL, "serve-url", "", "Rampart service URL override used for verification")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Timeout for each verification check")
	return cmd
}

func resolveLaunchTarget(agent string) (integrationDriver, launchTarget, error) {
	driver, ok := findIntegrationDriver(agent)
	target, supported := launchTargets[driver.ID]
	if !ok || !supported {
		return integrationDriver{}, launchTarget{}, fmt.Errorf("launch: unsupported agent %q (supported: %s)", agent, launchTargetNames())
	}
	return driver, target, nil
}

// launchCommand maps an agent, model, and pass-through args to the command
// to execute. Ollama is preferred because it configures the agent's endpoint.
func launchCommand(target launchTarget, model string, extra []string, lookPath func(string) (string, error)) (string, []string, error) {
	if _, err := lookPath("ollama"); err == nil {
		argv := []string{"launch", target.ollama}
		if model != "" {
			argv = append(argv, "--model", model)
		}
		if len(extra) > 0 {
			argv = append(append(argv, "--"), extra...)
		}
		return "ollama", argv, nil
	}
	if target.direct == nil {
		return "", nil, fmt.Errorf("launch: `ollama` was not found on PATH; install Ollama (https://ollama.com) to launch %s on a local model", target.ollama)
	}
	bin, argv := target.direct(model)
	if _, err := lookPath(bin); err != nil {
		return "", nil, fmt.Errorf("launch: neither `ollama` nor `%s` was found on PATH", bin)
	}
	return bin, append(argv, extra...), nil
}

// protectForLaunch installs the agent's hooks when they are missing, then
// requires every safe canary to pass. Unverified counts as failure.
func protectForLaunch(cmd *cobra.Command, opts *rootOptions, driver integrationDriver, serveURL string, timeout time.Duration) error {
	if err := prepareManagedProtection(opts); err != nil {
		return err
	}
	if _, err := resolveProtectionTargets(driver.ID); err != nil {
		return err
	}
	resolvedURL, err := resolveServeURLStrict(serveURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return fmt.Errorf("resolve serve URL: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	if !integrationConfiguredForAssurance(driver, home) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s is not protected yet; installing Rampart %s...\n", driver.DisplayName, driver.Boundary)
		if _, err := installManagedGuardPolicy(); err != nil {
			return fmt.Errorf("install managed Guard policy: %w", err)
		}
		if err := runIntegrationSetup(cmd, opts, driver); err != nil {
			return fmt.Errorf("configure native integration: %w", err)
		}
	}
	if err := ensureServeRunningForURL(cmd.OutOrStdout(), cmd.ErrOrStderr(), resolvedURL); err != nil {
		return fmt.Errorf("start Rampart policy service: %w", err)
	}
	report := runBehavioralVerification(cmd.Context(), driver.VerifyTarget, resolvedURL, timeout)
	_ = writeVerificationReceipt(report)
	fmt.Fprintln(cmd.OutOrStdout())
	printVerificationReport(cmd.OutOrStdout(), report)
	return launchVerificationError(report)
}

func launchVerificationError(report verificationReport) error {
	if report.Summary.Checks == 0 || report.Summary.Failed > 0 || report.Summary.Unverified > 0 {
		return fmt.Errorf("verification did not pass (%d failed, %d unverified of %d checks)",
			report.Summary.Failed, report.Summary.Unverified, report.Summary.Checks)
	}
	return nil
}

// runLaunchedAgent runs the agent in the foreground with this terminal. While
// it runs, Rampart ignores interrupts so Ctrl-C reaches only the agent; the
// agent's exit status becomes Rampart's.
func runLaunchedAgent(cmd *cobra.Command, bin string, args []string) error {
	path, err := execLookPath(bin)
	if err != nil {
		return fmt.Errorf("launch: %w", err)
	}
	child := osexec.Command(path, args...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	err = child.Run()
	var exitErr *osexec.ExitError
	if errors.As(err, &exitErr) {
		return exitCodeError{code: exitErr.ExitCode()}
	}
	return err
}
