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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/proxy"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

type wrapDeps struct {
	listen      func(network, address string) (net.Listener, error)
	commandPath func(file string) (string, error)
	signalNotify func(chan<- os.Signal, ...os.Signal)
	signalStop   func(chan<- os.Signal)
}

func defaultWrapDeps() wrapDeps {
	return wrapDeps{
		listen:      net.Listen,
		commandPath: exec.LookPath,
		signalNotify: signal.Notify,
		signalStop:   signal.Stop,
	}
}

func newWrapCmd(opts *rootOptions, deps *wrapDeps) *cobra.Command {
	var mode string
	var auditDir string
	var token string

	resolvedDeps := defaultWrapDeps()
	if deps != nil {
		if deps.listen != nil {
			resolvedDeps.listen = deps.listen
		}
		if deps.commandPath != nil {
			resolvedDeps.commandPath = deps.commandPath
		}
		if deps.signalNotify != nil {
			resolvedDeps.signalNotify = deps.signalNotify
		}
		if deps.signalStop != nil {
			resolvedDeps.signalStop = deps.signalStop
		}
	}

	cmd := &cobra.Command{
		Use:   "wrap -- <command> [args...]",
		Short: "Wrap a process with Rampart policy enforcement",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("wrap: command is required (use: rampart wrap -- <command> [args...])")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if mode != "enforce" && mode != "monitor" {
				return fmt.Errorf("wrap: invalid mode %q (must be enforce or monitor)", mode)
			}

			if auditDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("wrap: resolve home directory: %w", err)
				}
				auditDir = filepath.Join(home, ".rampart", "audit")
			}
			if err := os.MkdirAll(auditDir, 0o755); err != nil {
				return fmt.Errorf("wrap: create audit dir %s: %w", auditDir, err)
			}

			logLevel := slog.LevelInfo
			if opts.verbose {
				logLevel = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: logLevel}))

			policyPath, cleanupPolicy, err := resolveWrapPolicyPath(opts.configPath)
			if err != nil {
				return err
			}
			defer cleanupPolicy()

			store := engine.NewFileStore(policyPath)
			eng, err := engine.New(store, logger)
			if err != nil {
				return fmt.Errorf("wrap: create engine: %w", err)
			}

			sink, err := audit.NewJSONLSink(auditDir, audit.WithLogger(logger))
			if err != nil {
				return fmt.Errorf("wrap: create audit sink: %w", err)
			}
			countedSink := &decisionCounterSink{sink: sink}
			defer func() {
				_ = countedSink.Close()
			}()

			listener, err := resolvedDeps.listen("tcp", "127.0.0.1:0")
			if err != nil {
				return fmt.Errorf("wrap: start proxy listener: %w", err)
			}
			defer func() {
				_ = listener.Close()
			}()

			var proxyOpts []proxy.Option
			proxyOpts = append(proxyOpts, proxy.WithMode(mode), proxy.WithLogger(logger))
			if token != "" {
				proxyOpts = append(proxyOpts, proxy.WithToken(token))
			}
			proxyServer := proxy.New(eng, countedSink, proxyOpts...)

			proxyErrCh := make(chan error, 1)
			go func() {
				proxyErrCh <- proxyServer.Serve(listener)
			}()

			proxyURL := "http://" + listener.Addr().String()
			if err := waitForProxyReady(cmd.Context(), proxyURL); err != nil {
				return fmt.Errorf("wrap: proxy failed health check: %w", err)
			}
			logger.Info("proxy: listening", "url", proxyURL)

			realShell, err := resolveRealShell(resolvedDeps.commandPath)
			if err != nil {
				return err
			}
			shimPath, err := createShellShim(proxyURL, proxyServer.Token(), mode, realShell)
			if err != nil {
				return err
			}
			defer func() {
				_ = os.Remove(shimPath)
			}()

			child := exec.Command(args[0], args[1:]...)
			child.Stdin = cmd.InOrStdin()
			child.Stdout = cmd.OutOrStdout()
			child.Stderr = cmd.ErrOrStderr()
			// Filter sensitive Rampart vars from child environment.
			// The shim script has the token baked in — no need to expose it.
			childEnv := make([]string, 0, len(os.Environ())+5)
			for _, e := range os.Environ() {
				// Strip sensitive vars and vars we'll override
				if strings.HasPrefix(e, "RAMPART_TOKEN=") ||
					strings.HasPrefix(e, "CLAUDE_CODE_SHELL=") {
					continue
				}
				childEnv = append(childEnv, e)
			}
			// Create PATH-based shell wrappers for agents that ignore $SHELL
			shimDir, err := createShellWrappers(proxyURL, proxyServer.Token(), mode)
			if err != nil {
				return fmt.Errorf("wrap: create shell wrappers: %w", err)
			}
			defer func() {
				_ = os.RemoveAll(shimDir)
			}()

			// Prepend shim dir to PATH so wrappers shadow /bin/bash, /bin/zsh, etc.
			currentPath := os.Getenv("PATH")
			childEnv = append(childEnv,
				"SHELL="+shimPath,
				"CLAUDE_CODE_SHELL="+shimPath,
				"PATH="+shimDir+":"+currentPath,
				"RAMPART_PROXY="+proxyURL,
				"RAMPART_MODE="+mode,
				"RAMPART_ACTIVE=1",
			)
			child.Env = childEnv

			if err := child.Start(); err != nil {
				return fmt.Errorf("wrap: start child process: %w", err)
			}

			sigCh := make(chan os.Signal, 2)
			resolvedDeps.signalNotify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			forwardDone := make(chan struct{})
			go func() {
				defer close(forwardDone)
				for sig := range sigCh {
					if child.Process != nil {
						_ = child.Process.Signal(sig)
					}
				}
			}()

			waitErr := child.Wait()
			resolvedDeps.signalStop(sigCh)
			close(sigCh)
			<-forwardDone

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			shutdownErr := proxyServer.Shutdown(shutdownCtx)
			cancel()

			if serveErr := <-proxyErrCh; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				return fmt.Errorf("wrap: proxy serve error: %w", serveErr)
			}
			if shutdownErr != nil && !errors.Is(shutdownErr, http.ErrServerClosed) {
				return fmt.Errorf("wrap: proxy shutdown: %w", shutdownErr)
			}

			if err := countedSink.Flush(); err != nil {
				return fmt.Errorf("wrap: flush audit sink: %w", err)
			}

			evaluated, denied, logged := countedSink.Counts()
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Rampart: %d calls evaluated, %d denied, %d logged\n", evaluated, denied, logged); err != nil {
				return fmt.Errorf("wrap: write summary: %w", err)
			}

			if waitErr == nil {
				return nil
			}

			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				return exitCodeError{code: exitErr.ExitCode()}
			}
			return fmt.Errorf("wrap: wait for child process: %w", waitErr)
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Directory for audit logs (default: ~/.rampart/audit)")
	cmd.Flags().StringVar(&token, "token", "", "Bearer token for proxy auth (default: auto-generated)")

	return cmd
}

func resolveWrapPolicyPath(path string) (string, func(), error) {
	if strings.TrimSpace(path) == "" {
		path = "rampart.yaml"
	}

	_, err := os.Stat(path)
	if err == nil {
		return path, func() {}, nil
	}
	if !os.IsNotExist(err) {
		return "", nil, fmt.Errorf("wrap: check policy config %s: %w", path, err)
	}

	data, err := policies.Profile("standard")
	if err != nil {
		return "", nil, fmt.Errorf("wrap: load embedded standard policy: %w", err)
	}

	tmp, err := os.CreateTemp("", "rampart-wrap-policy-*.yaml")
	if err != nil {
		return "", nil, fmt.Errorf("wrap: create temporary policy file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("wrap: write temporary policy file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("wrap: close temporary policy file: %w", err)
	}

	return tmp.Name(), func() { _ = os.Remove(tmp.Name()) }, nil
}

func resolveRealShell(lookPath func(string) (string, error)) (string, error) {
	shell := strings.TrimSpace(os.Getenv("SHELL"))
	if shell == "" {
		shell = "/bin/bash"
	}
	resolved, err := lookPath(shell)
	if err == nil {
		return resolved, nil
	}

	resolved, fallbackErr := lookPath("bash")
	if fallbackErr == nil {
		return resolved, nil
	}

	return "", fmt.Errorf("wrap: resolve real shell %q: %w", shell, err)
}

func waitForProxyReady(ctx context.Context, proxyURL string) error {
	deadline := time.Now().Add(2 * time.Second)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	url := proxyURL + "/healthz"

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for proxy at %s", url)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("create health request: %w", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func createShellShim(proxyURL, token, mode, realShell string) (string, error) {
	tmp, err := os.CreateTemp("", "rampart-shim-*")
	if err != nil {
		return "", fmt.Errorf("wrap: create shell shim: %w", err)
	}

	script := fmt.Sprintf(`#!/usr/bin/env bash
# Rampart shell shim - auto-generated.
REAL_SHELL=%q
RAMPART_URL=%q
RAMPART_TOKEN=%q
RAMPART_MODE=%q

# Parse shell flags — collect flags before -c, extract the command after -c.
# Agents may call: shim -c "cmd" OR shim -l -c "cmd" OR shim -i -l -c "cmd"
SHELL_FLAGS=""
CMD=""
FOUND_C=false
ORIG_ARGS="$@"
while [ $# -gt 0 ]; do
    case "$1" in
        -c)
            FOUND_C=true
            shift
            CMD="$1"
            shift
            break
            ;;
        -*)
            SHELL_FLAGS="$SHELL_FLAGS $1"
            shift
            ;;
        *)
            break
            ;;
    esac
done

if [ "$FOUND_C" = "true" ]; then

    if ! command -v curl >/dev/null 2>&1; then
        echo "rampart: warning: curl is unavailable, allowing command" >&2
        exec "$REAL_SHELL" $SHELL_FLAGS -c "$CMD" "$@"
    fi

    ENCODED=$(printf '%%s' "$CMD" | base64 | tr -d '\n\r')
    PAYLOAD=$(printf '{"agent":"wrapped","session":"wrap","params":{"command_b64":"%%s"}}' "$ENCODED")
    DECISION=$(curl -sfS -X POST "${RAMPART_URL}/v1/preflight/exec" \
        -H "Authorization: Bearer ${RAMPART_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" 2>/dev/null)

    if [ -z "$DECISION" ]; then
        echo "rampart: warning: preflight unavailable, allowing command" >&2
        exec "$REAL_SHELL" $SHELL_FLAGS -c "$CMD" "$@"
    fi

    ALLOWED=$(printf '%%s' "$DECISION" | grep -o '"allowed":[a-z]*' | grep -o 'true\|false' | head -n 1)
    if [ "$RAMPART_MODE" = "enforce" ] && [ "$ALLOWED" != "true" ]; then
        MSG=$(printf '%%s' "$DECISION" | grep -o '"message":"[^"]*"' | head -n 1 | sed 's/"message":"//;s/"$//')
        if [ -z "$MSG" ]; then
            MSG="policy denied"
        fi
        echo "rampart: blocked - ${MSG}" >&2
        exit 126
    fi

    exec "$REAL_SHELL" $SHELL_FLAGS -c "$CMD" "$@"
fi

exec "$REAL_SHELL" $ORIG_ARGS
`, realShell, proxyURL, token, mode)

	if _, err := io.WriteString(tmp, script); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("wrap: write shell shim: %w", err)
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("wrap: close shell shim: %w", err)
	}

	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("wrap: chmod shell shim: %w", err)
	}

	return tmp.Name(), nil
}

// createShellWrappers creates a temp directory with wrapper scripts for common
// shells (bash, zsh, sh). Each wrapper checks RAMPART_ACTIVE — if set, routes
// through Rampart policy before executing. If not set, passes straight through
// to the real shell. This catches agents that hardcode /bin/bash or /bin/zsh
// instead of reading $SHELL.
func createShellWrappers(proxyURL, token, mode string) (string, error) {
	dir, err := os.MkdirTemp("", "rampart-shells-*")
	if err != nil {
		return "", fmt.Errorf("create shell wrapper dir: %w", err)
	}

	shells := []struct {
		name     string
		realPath string
	}{
		{"bash", "/bin/bash"},
		{"zsh", "/bin/zsh"},
		{"sh", "/bin/sh"},
	}

	for _, s := range shells {
		// Only create wrapper if the real shell exists
		if _, err := os.Stat(s.realPath); err != nil {
			continue
		}

		script := fmt.Sprintf(`#!/bin/sh
# Rampart shell wrapper for %s — auto-generated.
# Only intercepts when RAMPART_ACTIVE=1 (inside rampart wrap).
REAL=%q
if [ "$RAMPART_ACTIVE" != "1" ]; then
    exec "$REAL" "$@"
fi

# Parse shell flags before -c (e.g. -l -c "cmd")
SHELL_FLAGS=""
CMD=""
FOUND_C=false
ORIG_ARGS="$@"
while [ $# -gt 0 ]; do
    case "$1" in
        -c) FOUND_C=true; shift; CMD="$1"; shift; break ;;
        -*) SHELL_FLAGS="$SHELL_FLAGS $1"; shift ;;
        *) break ;;
    esac
done

if [ "$FOUND_C" = "true" ]; then

    if ! command -v curl >/dev/null 2>&1; then
        exec "$REAL" $SHELL_FLAGS -c "$CMD" "$@"
    fi

    ENCODED=$(printf '%%s' "$CMD" | base64 | tr -d '\n\r')
    PAYLOAD=$(printf '{"agent":"wrapped","session":"wrap","params":{"command_b64":"%%s"}}' "$ENCODED")
    DECISION=$(curl -sfS -X POST "%s/v1/preflight/exec" \
        -H "Authorization: Bearer %s" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" 2>/dev/null)

    if [ -z "$DECISION" ]; then
        exec "$REAL" $SHELL_FLAGS -c "$CMD" "$@"
    fi

    ALLOWED=$(printf '%%s' "$DECISION" | grep -o '"allowed":[a-z]*' | grep -o 'true\|false' | head -n 1)
    if [ "%s" = "enforce" ] && [ "$ALLOWED" != "true" ]; then
        MSG=$(printf '%%s' "$DECISION" | grep -o '"message":"[^"]*"' | head -n 1 | sed 's/"message":"//;s/"$//')
        if [ -z "$MSG" ]; then
            MSG="policy denied"
        fi
        echo "rampart: blocked - ${MSG}" >&2
        exit 126
    fi

    exec "$REAL" $SHELL_FLAGS -c "$CMD" "$@"
fi

# Interactive or non -c usage — pass through directly
exec "$REAL" $ORIG_ARGS
`, s.name, s.realPath, proxyURL, token, mode)

		wrapperPath := filepath.Join(dir, s.name)
		if err := os.WriteFile(wrapperPath, []byte(script), 0o755); err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("write shell wrapper %s: %w", s.name, err)
		}
	}

	return dir, nil
}

type decisionCounterSink struct {
	sink audit.AuditSink

	mu        sync.Mutex
	evaluated int
	denied    int
	logged    int
}

func (s *decisionCounterSink) Write(event audit.Event) error {
	s.mu.Lock()
	s.evaluated++
	switch strings.ToLower(event.Decision.Action) {
	case "deny":
		s.denied++
	case "log":
		s.logged++
	}
	s.mu.Unlock()
	return s.sink.Write(event)
}

func (s *decisionCounterSink) Flush() error {
	return s.sink.Flush()
}

func (s *decisionCounterSink) Close() error {
	return s.sink.Close()
}

func (s *decisionCounterSink) Counts() (evaluated, denied, logged int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evaluated, s.denied, s.logged
}

type exitCodeError struct {
	code int
}

func (e exitCodeError) Error() string {
	return fmt.Sprintf("exit status %d", e.code)
}

func (e exitCodeError) ExitCode() int {
	if e.code < 1 {
		return 1
	}
	return e.code
}
