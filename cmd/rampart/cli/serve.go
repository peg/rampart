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

			level := slog.LevelInfo
			if opts.verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			store := engine.NewFileStore(opts.configPath)
			eng, err := engine.New(store, logger)
			if err != nil {
				return fmt.Errorf("serve: create engine: %w", err)
			}

			sink, err := audit.NewJSONLSink(auditDir, audit.WithLogger(logger))
			if err != nil {
				return fmt.Errorf("serve: create audit sink: %w", err)
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

			configAbs, err := filepath.Abs(opts.configPath)
			if err != nil {
				return fmt.Errorf("serve: resolve config path %s: %w", opts.configPath, err)
			}
			if err := watcher.Add(configAbs); err != nil {
				return fmt.Errorf("serve: watch config file %s: %w", configAbs, err)
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
				proxyOpts = append(proxyOpts, proxy.WithMode(mode), proxy.WithLogger(logger))
				if envToken := os.Getenv("RAMPART_TOKEN"); envToken != "" {
					proxyOpts = append(proxyOpts, proxy.WithToken(envToken))
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

				proxyErrCh = make(chan error, 1)
				go func() {
					proxyErrCh <- proxyServer.ListenAndServe(fmt.Sprintf(":%d", port))
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
					if !isWriteEvent(event) || !samePath(configAbs, event.Name) {
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
	cmd.Flags().IntVar(&port, "port", 9090, "Proxy listen port (0 = SDK-only mode)")

	return cmd
}

func isWriteEvent(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write)
}

func samePath(a, b string) bool {
	return filepath.Clean(strings.TrimSpace(a)) == filepath.Clean(strings.TrimSpace(b))
}
