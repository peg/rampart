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
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/peg/rampart/internal/bridge"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

func newBridgeCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bridge",
		Short: "Bridge integrations with external approval systems",
	}

	cmd.AddCommand(newBridgeOpenClawCmd(opts))
	return cmd
}

func newBridgeOpenClawCmd(opts *rootOptions) *cobra.Command {
	var gatewayURL string
	var gatewayToken string
	var policyDir string
	var serveURL string

	cmd := &cobra.Command{
		Use:   "openclaw",
		Short: "Connect to OpenClaw gateway for exec approval routing",
		Long: `Start a bridge that connects to the OpenClaw gateway WebSocket and routes
exec approval requests through Rampart's policy engine.

Commands that match allow/deny rules are auto-resolved immediately.
Commands that require human approval are escalated to a running
Rampart serve instance.

By default, the gateway URL and token are auto-discovered from
~/.openclaw/openclaw.json.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			level := slog.LevelInfo
			if opts.verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			// Auto-discover gateway config if not provided.
			if gatewayURL == "" || gatewayToken == "" {
				url, token, err := bridge.DiscoverGatewayConfig()
				if err != nil {
					return fmt.Errorf("bridge openclaw: auto-discover gateway config: %w\n\nSet --gateway-url and --gateway-token manually, or ensure ~/.openclaw/openclaw.json exists", err)
				}
				if gatewayURL == "" {
					gatewayURL = url
				}
				if gatewayToken == "" {
					gatewayToken = token
				}
			}

			// Resolve policy store.
			effectivePolicyDir := policyDir
			if effectivePolicyDir == "" {
				if home, err := os.UserHomeDir(); err == nil {
					effectivePolicyDir = filepath.Join(home, ".rampart", "policies")
				}
			}

			var store engine.PolicyStore
			configExists := true
			if _, err := os.Stat(opts.configPath); os.IsNotExist(err) {
				configExists = false
			}

			if !configExists && opts.configPath == "rampart.yaml" && policyDir == "" {
				// Use embedded standard policy.
				embeddedData, err := policies.Profile("standard")
				if err != nil {
					return fmt.Errorf("bridge openclaw: load embedded standard policy: %w", err)
				}
				if effectivePolicyDir != "" {
					if _, err := os.Stat(effectivePolicyDir); err == nil {
						memStore := engine.NewMemoryStore(embeddedData, "embedded:standard")
						store = engine.NewMixedStore(memStore, effectivePolicyDir, logger)
					} else {
						store = engine.NewMemoryStore(embeddedData, "embedded:standard")
					}
				} else {
					store = engine.NewMemoryStore(embeddedData, "embedded:standard")
				}
				logger.Info("bridge: using embedded standard policy")
			} else if effectivePolicyDir != "" {
				if _, err := os.Stat(effectivePolicyDir); err == nil {
					store = engine.NewMultiStore(opts.configPath, effectivePolicyDir, logger)
				} else {
					store = engine.NewFileStore(opts.configPath)
				}
			} else {
				store = engine.NewFileStore(opts.configPath)
			}

			eng, err := engine.New(store, logger)
			if err != nil {
				return fmt.Errorf("bridge openclaw: create engine: %w", err)
			}
			defer eng.Stop()

			b := bridge.NewOpenClawBridge(eng, bridge.Config{
				GatewayURL:   gatewayURL,
				GatewayToken: gatewayToken,
				ServeURL:     serveURL,
				Logger:       logger,
			})
			defer b.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Fprintf(cmd.ErrOrStderr(), "bridge: connecting to OpenClaw gateway at %s\n", gatewayURL)

			return b.Start(ctx)
		},
	}

	cmd.Flags().StringVar(&gatewayURL, "gateway-url", "", "OpenClaw gateway WebSocket URL (default: auto-discover)")
	cmd.Flags().StringVar(&gatewayToken, "gateway-token", "", "OpenClaw gateway auth token (default: auto-discover from ~/.openclaw/openclaw.json)")
	cmd.Flags().StringVar(&policyDir, "policy-dir", "", "Directory of policy YAML files (default: ~/.rampart/policies/)")
	cmd.Flags().StringVar(&serveURL, "serve-url", "http://127.0.0.1:19090", "Rampart serve URL for human-review escalation")

	return cmd
}
