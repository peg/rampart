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
	"runtime"
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
	// local builds an invocation against any OpenAI- or Anthropic-compatible
	// server, such as llama.cpp's llama-server or LM Studio. Nil means the
	// agent has no command-line way to point at one.
	local func(baseURL, model string) (bin string, args, env []string)
}

var launchTargets = map[string]launchTarget{
	"claude-code": {ollama: "claude", local: func(baseURL, model string) (string, []string, []string) {
		// Claude Code appends /v1/messages itself. The placeholder token keeps
		// a real Anthropic key from being sent to the local server.
		env := []string{"ANTHROPIC_BASE_URL=" + strings.TrimSuffix(baseURL, "/v1"), "ANTHROPIC_AUTH_TOKEN=local", "ANTHROPIC_API_KEY="}
		return "claude", withModel(nil, "--model", model), env
	}},
	"codex": {ollama: "codex", direct: func(model string) (string, []string) {
		return "codex", withModel([]string{"--oss"}, "-m", model)
	}, local: func(baseURL, model string) (string, []string, []string) {
		if !strings.HasSuffix(baseURL, "/v1") {
			baseURL += "/v1"
		}
		provider := fmt.Sprintf(`model_providers.local={ name = "Local model", base_url = %q, wire_api = "responses" }`, baseURL)
		return "codex", withModel([]string{"-c", `model_provider="local"`, "-c", provider}, "-m", model), nil
	}},
	"opencode": {ollama: "opencode"},
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
func withModel(args []string, flag, model string) []string {
	if model == "" {
		return args
	}
	return append(args, flag, model)
}

type launchDeps struct {
	lookPath func(string) (string, error)
	protect  func(cmd *cobra.Command, opts *rootOptions, driver integrationDriver, serveURL string, timeout time.Duration) error
	run      func(cmd *cobra.Command, bin string, args, env []string) error
}

func newLaunchCmd(opts *rootOptions) *cobra.Command {
	return newLaunchCmdWith(opts, launchDeps{lookPath: execLookPath, protect: protectForLaunch, run: runLaunchedAgent})
}

func newLaunchCmdWith(opts *rootOptions, deps launchDeps) *cobra.Command {
	var model, baseURL, serveURL string
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
With --base-url it starts the agent against that server instead, for
llama.cpp, LM Studio, or any OpenAI-compatible (Codex) or
Anthropic-compatible (Claude Code) endpoint.

Supported agents: ` + launchTargetNames() + `.`,
		Example: `  rampart launch claude --model qwen3-coder
  rampart launch claude --base-url http://127.0.0.1:8080 --model local
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
			bin, argv, env, err := launchCommand(target, model, strings.TrimRight(strings.TrimSpace(baseURL), "/"), args[1:], deps.lookPath)
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
			return deps.run(cmd, bin, argv, env)
		},
	}
	cmd.Flags().StringVar(&model, "model", "", "Local model name passed to the agent (for example qwen3-coder)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Model server URL (llama.cpp, LM Studio) to use instead of Ollama")
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
func launchCommand(target launchTarget, model, baseURL string, extra []string, lookPath func(string) (string, error)) (string, []string, []string, error) {
	if baseURL != "" {
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			return "", nil, nil, fmt.Errorf("launch: --base-url must start with http:// or https://")
		}
		if target.local == nil {
			return "", nil, nil, fmt.Errorf("launch: --base-url is not supported for %s; set the provider in its own config", target.ollama)
		}
		bin, argv, env := target.local(baseURL, model)
		if _, err := lookPath(bin); err != nil {
			return "", nil, nil, fmt.Errorf("launch: `%s` was not found on PATH", bin)
		}
		return bin, append(argv, extra...), env, nil
	}
	if _, err := lookPath("ollama"); err == nil {
		argv := []string{"launch", target.ollama}
		if model != "" {
			argv = append(argv, "--model", model)
		}
		if len(extra) > 0 {
			argv = append(append(argv, "--"), extra...)
		}
		return "ollama", argv, nil, nil
	}
	if target.direct == nil {
		return "", nil, nil, fmt.Errorf("launch: `ollama` was not found on PATH; install Ollama (https://ollama.com), or pass --base-url to use another model server")
	}
	bin, argv := target.direct(model)
	if _, err := lookPath(bin); err != nil {
		return "", nil, nil, fmt.Errorf("launch: neither `ollama` nor `%s` was found on PATH", bin)
	}
	return bin, append(argv, extra...), nil, nil
}

// protectForLaunch installs the agent's hooks when they are missing, then
// requires every safe canary to pass. Unverified counts as failure.
func protectForLaunch(cmd *cobra.Command, opts *rootOptions, driver integrationDriver, serveURL string, timeout time.Duration) error {
	if err := prepareManagedProtection(opts); err != nil {
		return err
	}
	// Launch is an explicit request for this agent, so experimental
	// integrations are allowed here; verification still has to pass.
	if !integrationDriverSupportsPlatform(driver, runtime.GOOS) {
		return fmt.Errorf("launch: %s is not supported on %s", driver.DisplayName, runtime.GOOS)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	if driver.Installed == nil || !driver.Installed(home) {
		return fmt.Errorf("launch: %s was not found; install it first", driver.DisplayName)
	}
	resolvedURL, err := resolveServeURLStrict(serveURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return fmt.Errorf("resolve serve URL: %w", err)
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
	// A service that was already running loads a newly installed policy on
	// its next reload, so give it a moment before treating a failure as final.
	for attempt := 0; attempt < launchVerifyRetries && launchVerificationError(report) != nil; attempt++ {
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		case <-time.After(launchVerifyRetryDelay):
		}
		report = runBehavioralVerification(cmd.Context(), driver.VerifyTarget, resolvedURL, timeout)
	}
	_ = writeVerificationReceipt(report)
	fmt.Fprintln(cmd.OutOrStdout())
	printVerificationReport(cmd.OutOrStdout(), report)
	return launchVerificationError(report)
}

// Verification is retried for up to about five seconds while a running
// service picks up policy changes.
var (
	launchVerifyRetries    = 5
	launchVerifyRetryDelay = time.Second
)

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
func runLaunchedAgent(cmd *cobra.Command, bin string, args, env []string) error {
	path, err := execLookPath(bin)
	if err != nil {
		return fmt.Errorf("launch: %w", err)
	}
	child := osexec.Command(path, args...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = append(os.Environ(), env...)
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
