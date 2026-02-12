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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/peg/rampart/internal/daemon"
	"github.com/spf13/cobra"
)

func newDaemonCmd(opts *rootOptions) *cobra.Command {
	var gatewayURL string
	var gatewayToken string
	var auditDir string
	var apiAddr string
	var reconnectSeconds int

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run Rampart as an OpenClaw approval daemon",
		Long: `Connect to an OpenClaw Gateway WebSocket and auto-resolve exec approval
requests based on Rampart policies.

The daemon acts as an operator client with approval permissions. When the
agent attempts an exec command that requires approval, the daemon evaluates
it against your policies and responds immediately — allow, deny, or log.

This gives you automated, policy-driven enforcement for OpenClaw without
requiring human approval for every command.

Prerequisites:
  1. OpenClaw must be running with exec approvals enabled:
     tools.exec.host: "gateway"
     tools.exec.security: "allowlist"
     tools.exec.ask: "on-miss"

  2. The gateway token must be set (OPENCLAW_GATEWAY_TOKEN or --token)

Example:
  rampart daemon --gateway ws://127.0.0.1:18789 --token YOUR_TOKEN`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath := opts.configPath

			// Resolve audit directory.
			if auditDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("daemon: resolve home: %w", err)
				}
				auditDir = filepath.Join(home, ".rampart", "audit")
			}

			// Ensure audit directory exists.
			if err := os.MkdirAll(auditDir, 0o700); err != nil {
				return fmt.Errorf("daemon: create audit dir: %w", err)
			}

			// Resolve token from env if not set.
			if gatewayToken == "" {
				gatewayToken = os.Getenv("OPENCLAW_GATEWAY_TOKEN")
			}
			if gatewayToken == "" {
				return fmt.Errorf("daemon: gateway token required (--token or OPENCLAW_GATEWAY_TOKEN)")
			}

			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))

			cfg := daemon.Config{
				GatewayURL:        gatewayURL,
				GatewayToken:      gatewayToken,
				PolicyPath:        configPath,
				AuditDir:          auditDir,
				Logger:            logger,
				ReconnectInterval: time.Duration(reconnectSeconds) * time.Second,
			}

			d, err := daemon.New(cfg)
			if err != nil {
				return err
			}
			defer d.Close()

			// Handle graceful shutdown.
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			fmt.Fprintf(cmd.OutOrStdout(), "Rampart daemon starting\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  Gateway: %s\n", gatewayURL)
			fmt.Fprintf(cmd.OutOrStdout(), "  Policy:  %s\n", configPath)
			fmt.Fprintf(cmd.OutOrStdout(), "  Audit:   %s\n", auditDir)
			fmt.Fprintf(cmd.OutOrStdout(), "  API:     %s\n\n", apiAddr)

			// Start the approval API server (shares gateway token for auth).
			api := daemon.NewAPI(d.Approvals(), gatewayToken, logger)
			apiServer := &http.Server{Addr: apiAddr, Handler: api.Handler()}
			go func() {
				if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Error("daemon api failed", "error", err)
				}
			}()
			defer apiServer.Shutdown(ctx)

			return d.Run(ctx)
		},
	}

	cmd.Flags().StringVar(&gatewayURL, "gateway", "ws://127.0.0.1:18789", "OpenClaw Gateway WebSocket URL")
	cmd.Flags().StringVar(&gatewayToken, "token", "", "Gateway authentication token (or set OPENCLAW_GATEWAY_TOKEN)")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Audit log directory (default ~/.rampart/audit)")
	cmd.Flags().StringVar(&apiAddr, "api", "127.0.0.1:9091", "Daemon API listen address (for approval management)")
	cmd.Flags().IntVar(&reconnectSeconds, "reconnect", 5, "Reconnect interval in seconds")

	return cmd
}
