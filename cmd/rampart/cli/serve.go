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
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/proxy"
	"github.com/peg/rampart/internal/signing"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

type serveDeps struct {
	newWatcher    func() (*fsnotify.Watcher, error)
	notifyContext func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)
}

func defaultServeDeps() serveDeps {
	return serveDeps{
		newWatcher:    fsnotify.NewWatcher,
		notifyContext: signal.NotifyContext,
	}
}

func newServeCmd(opts *rootOptions, deps *serveDeps) *cobra.Command {
	var auditDir string
	var mode string
	var port int
	var listenAddr string
	var syslogAddr string
	var cef bool
	var resolveBaseURL string
	var signingKeyPath string
	var metrics bool
	var configDir string
	var reloadInterval time.Duration
	var approvalTimeout time.Duration

	resolvedDeps := defaultServeDeps()
	if deps != nil {
		if deps.newWatcher != nil {
			resolvedDeps.newWatcher = deps.newWatcher
		}
		if deps.notifyContext != nil {
			resolvedDeps.notifyContext = deps.notifyContext
		}
	}

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start Rampart policy runtime and file watcher",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if mode != "enforce" && mode != "monitor" && mode != "disabled" {
				return fmt.Errorf("serve: invalid mode %q (must be enforce, monitor, or disabled)", mode)
			}

			if listenAddr != "" && net.ParseIP(listenAddr) == nil {
				return fmt.Errorf("serve: invalid --addr %q (must be a valid IP address, e.g. 127.0.0.1 or ::1)", listenAddr)
			}

			level := slog.LevelInfo
			if opts.verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			// Build policy store: file, dir, or both.
			// If the default config path is used, the file doesn't exist, and
			// no --config-dir is set, fall back to the embedded standard policy.
			var store engine.PolicyStore
			usingEmbedded := false

			effectiveDir := configDir
			if effectiveDir == "" {
				// Default: include ~/.rampart/policies/ so auto-allowed rules are picked up.
				if home, hErr := os.UserHomeDir(); hErr == nil {
					defaultDir := filepath.Join(home, ".rampart", "policies")
					if _, sErr := os.Stat(defaultDir); sErr == nil {
						effectiveDir = defaultDir
					}
				}
			}

			configExists := true
			if _, statErr := os.Stat(opts.configPath); os.IsNotExist(statErr) {
				configExists = false
			}

			if !configExists && opts.configPath == "rampart.yaml" && configDir == "" {
				// No config file and no explicit config-dir: use embedded standard policy.
				embeddedData, embErr := policies.Profile("standard")
				if embErr != nil {
					return fmt.Errorf("serve: load embedded standard policy: %w", embErr)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "serve: using embedded standard policy (no config file found — create one with 'rampart init')\n")
				usingEmbedded = true
				if effectiveDir != "" {
					// Combine embedded standard with the ~/.rampart/policies/ dir.
					memStore := engine.NewMemoryStore(embeddedData, "embedded:standard")
					store = engine.NewMixedStore(memStore, effectiveDir, logger)
				} else {
					store = engine.NewMemoryStore(embeddedData, "embedded:standard")
				}
			} else if effectiveDir != "" {
				store = engine.NewMultiStore(opts.configPath, effectiveDir, logger)
			} else {
				store = engine.NewFileStore(opts.configPath)
			}

			eng, err := engine.New(store, logger)
			if err != nil {
				return fmt.Errorf("serve: create engine: %w", err)
			}

			// Start periodic policy reload for picking up auto-allowed rules.
			eng.StartPeriodicReload(reloadInterval)
			defer eng.Stop()

			jsonlSink, err := audit.NewJSONLSink(auditDir, audit.WithLogger(logger))
			if err != nil {
				return fmt.Errorf("serve: create audit sink: %w", err)
			}

			// Build the final sink, optionally wrapping with syslog/CEF outputs.
			var sink audit.AuditSink = jsonlSink
			var syslogSender audit.SyslogSender
			var cefFilePtr *audit.CEFFileSink

			if syslogAddr != "" {
				s, sErr := audit.NewSyslogSink(syslogAddr, cef, logger)
				if sErr != nil {
					logger.Warn("serve: syslog init failed, continuing without syslog", "error", sErr)
				} else {
					syslogSender = s
					logger.Info("serve: syslog output enabled", "addr", syslogAddr, "cef", cef)
				}
			}

			if cef && syslogAddr == "" {
				// CEF standalone mode — write to cef.log file.
				cefPath := filepath.Join(auditDir, "cef.log")
				cf, cErr := audit.NewCEFFileSink(cefPath, logger)
				if cErr != nil {
					return fmt.Errorf("serve: create cef file sink: %w", cErr)
				}
				cefFilePtr = cf
				logger.Info("serve: CEF file output enabled", "path", cefPath)
			}

			if syslogSender != nil || cefFilePtr != nil {
				sink = audit.NewMultiSink(jsonlSink, syslogSender, cefFilePtr, logger)
			}

			defer func() {
				_ = sink.Close()
			}()

			watcher, err := resolvedDeps.newWatcher()
			if err != nil {
				return fmt.Errorf("serve: create file watcher: %w", err)
			}
			defer func() {
				_ = watcher.Close()
			}()

			var configAbs string
			if !usingEmbedded {
				configAbs, err = filepath.Abs(opts.configPath)
				if err != nil {
					return fmt.Errorf("serve: resolve config path %s: %w", opts.configPath, err)
				}
				if err := watcher.Add(configAbs); err != nil {
					return fmt.Errorf("serve: watch config file %s: %w", configAbs, err)
				}
			}

			logger.Info("serve: started",
				"mode", mode,
				"policy_count", eng.PolicyCount(),
				"audit_dir", auditDir,
				"port", port,
			)

			var (
				proxyServer *proxy.Server
				proxyErrCh  chan error
			)
			if port > 0 {
				var proxyOpts []proxy.Option
				configPathDisplay := opts.configPath
				if usingEmbedded {
					configPathDisplay = "embedded:standard"
				}
				proxyOpts = append(proxyOpts, proxy.WithMode(mode), proxy.WithLogger(logger), proxy.WithMetrics(metrics), proxy.WithAuditDir(auditDir), proxy.WithConfigPath(configPathDisplay))
				if approvalTimeout > 0 {
					proxyOpts = append(proxyOpts, proxy.WithApprovalTimeout(approvalTimeout))
				}
				if envToken := os.Getenv("RAMPART_TOKEN"); envToken != "" {
					proxyOpts = append(proxyOpts, proxy.WithToken(envToken))
				}
				if resolveBaseURL != "" {
					proxyOpts = append(proxyOpts, proxy.WithResolveBaseURL(resolveBaseURL))
				}
				// Load or auto-generate signing key for approval resolve URLs.
				if signingKeyPath == "" {
					home, _ := os.UserHomeDir()
					if home != "" {
						signingKeyPath = filepath.Join(home, ".rampart", "signing.key")
					}
				}
				if signingKeyPath != "" {
					key, keyErr := signing.LoadOrCreateKey(signingKeyPath)
					if keyErr != nil {
						logger.Warn("serve: failed to load signing key, resolve URLs will be unsigned", "error", keyErr)
					} else {
						proxyOpts = append(proxyOpts, proxy.WithSigner(signing.NewSigner(key)))
						logger.Info("serve: approval URL signing enabled", "key_path", signingKeyPath)
					}
				}
				// Load notify config from policy file
				if cfg, loadErr := store.Load(); loadErr == nil && cfg.Notify != nil {
					proxyOpts = append(proxyOpts, proxy.WithNotify(cfg.Notify))
					logger.Info("serve: webhook notifications enabled", "url", cfg.Notify.URL)
				}
				proxyServer = proxy.New(eng, sink, proxyOpts...)

				token := proxyServer.Token()
				display := token
				if len(token) > 8 {
					display = token[:8] + "..."
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "serve: proxy listening on :%d (token=%s)\n", port, display)
				fmt.Fprintf(cmd.ErrOrStderr(), "serve: full token: %s\n", token)
				fmt.Fprintf(cmd.ErrOrStderr(), "serve: dashboard: http://localhost:%d/dashboard/\n", port)
				fmt.Fprintf(cmd.ErrOrStderr(), "serve: use the full token above to authenticate in the dashboard\n")

				if metrics {
					logger.Info("serve: metrics enabled on /metrics")
				}

				proxyErrCh = make(chan error, 1)
				go func() {
					proxyErrCh <- proxyServer.ListenAndServe(fmt.Sprintf("%s:%d", listenAddr, port))
				}()
			}

			sigCtx, stop := resolvedDeps.notifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			lastReload := time.Time{}
			for {
				select {
				case <-sigCtx.Done():
					logger.Info("serve: shutting down...")
					if proxyServer != nil {
						shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						if err := proxyServer.Shutdown(shutdownCtx); err != nil {
							logger.Error("serve: proxy shutdown failed", "error", err)
						}
						cancel()
					}
					if err := sink.Flush(); err != nil {
						logger.Error("serve: flush audit sink failed", "error", err)
					}
					if err := sink.Close(); err != nil {
						logger.Error("serve: close audit sink failed", "error", err)
					}
					return nil
				case err := <-proxyErrCh:
					if err != nil && !errors.Is(err, http.ErrServerClosed) {
						return fmt.Errorf("serve: proxy server failed: %w", err)
					}
					return nil
				case event, ok := <-watcher.Events:
					if !ok {
						return nil
					}
					if usingEmbedded || !isWriteEvent(event) || !samePath(configAbs, event.Name) {
						continue
					}
					now := time.Now()
					if !lastReload.IsZero() && now.Sub(lastReload) < 500*time.Millisecond {
						continue
					}
					lastReload = now
					// Delay briefly to let the file write complete.
					// File writes trigger events on truncation (empty file)
					// before the new content is flushed.
					time.Sleep(100 * time.Millisecond)
					if err := eng.Reload(); err != nil {
						logger.Error("serve: reload failed", "error", err)
						continue
					}
					logger.Info("serve: policy reloaded", "path", configAbs, "policy_count", eng.PolicyCount())
				case err, ok := <-watcher.Errors:
					if !ok {
						continue
					}
					logger.Error("serve: watcher error", "error", err)
				}
			}
		},
	}

	defaultAuditDir := "./audit"
	if home, err := os.UserHomeDir(); err == nil {
		defaultAuditDir = filepath.Join(home, ".rampart", "audit")
	}
	cmd.Flags().StringVar(&auditDir, "audit-dir", defaultAuditDir, "Directory for audit logs")
	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor | disabled")
	cmd.Flags().IntVar(&port, "port", defaultServePort, "Proxy listen port (0 = SDK-only mode)")
	cmd.Flags().StringVar(&listenAddr, "addr", "", "Bind address (default: all interfaces). Use 127.0.0.1 to bind localhost only")
	cmd.Flags().StringVar(&syslogAddr, "syslog", "", "Syslog server address (e.g. localhost:514)")
	cmd.Flags().BoolVar(&cef, "cef", false, "Use CEF format (with --syslog: CEF over syslog; standalone: write ~/.rampart/audit/cef.log)")
	cmd.Flags().StringVar(&resolveBaseURL, "resolve-base-url", "", "Base URL for approval resolve links (e.g. https://rampart.example.com:9090)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "Path to HMAC signing key for resolve URLs (default: ~/.rampart/signing.key, auto-generated)")
	cmd.Flags().BoolVar(&metrics, "metrics", false, "Enable Prometheus metrics endpoint on /metrics")
	cmd.Flags().StringVar(&configDir, "config-dir", "", "Directory of additional policy YAML files (default: ~/.rampart/policies/ if it exists)")
	cmd.Flags().DurationVar(&reloadInterval, "reload-interval", 30*time.Second, "How often to re-read policy files (0 to disable)")
	cmd.Flags().DurationVar(&approvalTimeout, "approval-timeout", 0, "How long approvals stay pending before expiring (default: 1h)")

	cmd.AddCommand(newServeInstallCmd(opts, nil))
	cmd.AddCommand(newServeUninstallCmd(nil))

	return cmd
}

func isWriteEvent(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write)
}

func samePath(a, b string) bool {
	return filepath.Clean(strings.TrimSpace(a)) == filepath.Clean(strings.TrimSpace(b))
}
