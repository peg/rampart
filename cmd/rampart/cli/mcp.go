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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/mcp"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

type mcpDeps struct {
	signalNotify func(chan<- os.Signal, ...os.Signal)
	signalStop   func(chan<- os.Signal)
}

func defaultMCPDeps() mcpDeps {
	return mcpDeps{
		signalNotify: signal.Notify,
		signalStop:   signal.Stop,
	}
}

func newMCPCmd(opts *rootOptions, deps *mcpDeps) *cobra.Command {
	var mode string
	var auditDir string
	var filterTools bool

	resolvedDeps := defaultMCPDeps()
	if deps != nil {
		if deps.signalNotify != nil {
			resolvedDeps.signalNotify = deps.signalNotify
		}
		if deps.signalStop != nil {
			resolvedDeps.signalStop = deps.signalStop
		}
	}

	cmd := &cobra.Command{
		Use:   "mcp -- <mcp-server-command> [args...]",
		Short: "Proxy MCP stdio with Rampart policy enforcement",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("mcp: command is required (use: rampart mcp -- <command> [args...])")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if mode != "enforce" && mode != "monitor" {
				return fmt.Errorf("mcp: invalid mode %q (must be enforce or monitor)", mode)
			}

			if auditDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("mcp: resolve home directory: %w", err)
				}
				auditDir = filepath.Join(home, ".rampart", "audit")
			}
			if err := os.MkdirAll(auditDir, 0o700); err != nil {
				return fmt.Errorf("mcp: create audit dir %s: %w", auditDir, err)
			}

			logLevel := slog.LevelInfo
			if opts.verbose {
				logLevel = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: logLevel}))

			policyPath, cleanupPolicy, err := resolveMCPPolicyPath(opts.configPath)
			if err != nil {
				return err
			}
			defer cleanupPolicy()

			store := engine.NewFileStore(policyPath)
			eng, err := engine.New(store, logger)
			if err != nil {
				return fmt.Errorf("mcp: create engine: %w", err)
			}

			// Use a daily file matching the hook naming convention so
			// `rampart watch` picks up events from both hook and MCP.
			today := time.Now().UTC().Format("2006-01-02")
			auditPath := filepath.Join(auditDir, "audit-hook-"+today+".jsonl")
			auditFile, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return fmt.Errorf("mcp: open audit file: %w", err)
			}
			sink := &appendSink{file: auditFile}
			countedSink := &decisionCounterSink{sink: sink}
			defer func() {
				_ = countedSink.Close()
			}()

			child := exec.Command(args[0], args[1:]...)
			child.Stderr = cmd.ErrOrStderr()

			childIn, err := child.StdinPipe()
			if err != nil {
				return fmt.Errorf("mcp: create child stdin pipe: %w", err)
			}
			childOut, err := child.StdoutPipe()
			if err != nil {
				return fmt.Errorf("mcp: create child stdout pipe: %w", err)
			}

			if err := child.Start(); err != nil {
				return fmt.Errorf("mcp: start child process: %w", err)
			}

			proxy := mcp.NewProxy(
				eng,
				countedSink,
				childIn,
				childOut,
				mcp.WithMode(mode),
				mcp.WithFilterTools(filterTools),
				mcp.WithLogger(logger),
			)

			proxyCtx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			proxyErrCh := make(chan error, 1)
			go func() {
				proxyErrCh <- proxy.Run(proxyCtx, cmd.InOrStdin(), cmd.OutOrStdout())
			}()

			waitCh := make(chan error, 1)
			go func() {
				waitCh <- child.Wait()
			}()

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

			waitErr := <-waitCh
			cancel()
			proxyErr := <-proxyErrCh

			resolvedDeps.signalStop(sigCh)
			close(sigCh)
			<-forwardDone

			if err := countedSink.Flush(); err != nil {
				return fmt.Errorf("mcp: flush audit sink: %w", err)
			}

			evaluated, denied, logged := countedSink.Counts()
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Rampart: %d calls evaluated, %d denied, %d logged\n", evaluated, denied, logged); err != nil {
				return fmt.Errorf("mcp: write summary: %w", err)
			}

			if proxyErr != nil {
				return fmt.Errorf("mcp: proxy failed: %w", proxyErr)
			}

			if waitErr == nil {
				return nil
			}

			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				return exitCodeError{code: exitErr.ExitCode()}
			}
			return fmt.Errorf("mcp: wait for child process: %w", waitErr)
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Directory for audit logs (default: ~/.rampart/audit)")
	cmd.Flags().BoolVar(&filterTools, "filter-tools", false, "Filter denied tools from tools/list responses")

	return cmd
}

func resolveMCPPolicyPath(path string) (string, func(), error) {
	if strings.TrimSpace(path) == "" {
		path = "rampart.yaml"
	}

	_, err := os.Stat(path)
	if err == nil {
		return path, func() {}, nil
	}
	if !os.IsNotExist(err) {
		return "", nil, fmt.Errorf("mcp: check policy config %s: %w", path, err)
	}

	data, err := policies.Profile("standard")
	if err != nil {
		return "", nil, fmt.Errorf("mcp: load embedded standard policy: %w", err)
	}

	tmp, err := os.CreateTemp("", "rampart-mcp-policy-*.yaml")
	if err != nil {
		return "", nil, fmt.Errorf("mcp: create temporary policy file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("mcp: write temporary policy file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("mcp: close temporary policy file: %w", err)
	}

	return tmp.Name(), func() { _ = os.Remove(tmp.Name()) }, nil
}

// appendSink implements audit.AuditSink by appending JSON lines to a file.
// Used by hook and MCP modes to share a single daily audit file.
type appendSink struct {
	file *os.File
}

func (s *appendSink) Write(event audit.Event) error {
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	_, err = s.file.Write(line)
	return err
}

func (s *appendSink) Flush() error {
	return s.file.Sync()
}

func (s *appendSink) Close() error {
	return s.file.Close()
}
