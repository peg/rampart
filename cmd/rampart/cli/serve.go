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
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	crypto_tls "crypto/tls"

	"github.com/fsnotify/fsnotify"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/bridge"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/internal/proxy"
	"github.com/peg/rampart/internal/signing"
	"github.com/peg/rampart/internal/tlsutil"
	"github.com/peg/rampart/internal/token"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

type serveDeps struct {
	newWatcher     func() (*fsnotify.Watcher, error)
	notifyContext  func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)
	loadSigningKey func(string) ([]byte, error)
}

const (
	backgroundReadyFileEnv = "RAMPART_BACKGROUND_READY_FILE"
	maxServePIDFileBytes   = 32
)

var inspectBackgroundServeProcess = isRampartServeProcess

func printServeToken(w io.Writer, token string, interactive bool) {
	if interactive {
		fmt.Fprintf(w, "  🔑 Full token : %s\n", token)
		return
	}
	fmt.Fprintln(w, "  🔑 Token      : saved to ~/.rampart/token")
}

func defaultServeDeps() serveDeps {
	return serveDeps{
		newWatcher:     fsnotify.NewWatcher,
		notifyContext:  signal.NotifyContext,
		loadSigningKey: signing.LoadOrCreateKey,
	}
}

func notifyRequiresSignedApprovalLinks(cfg *engine.NotifyConfig) bool {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return false
	}
	if len(cfg.On) == 0 {
		// The default notification set includes ask/require_approval.
		return true
	}
	for _, action := range cfg.On {
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "ask", "require_approval":
			return true
		}
	}
	return false
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
	var background bool
	var tlsCert string
	var tlsKey string
	var tlsAuto bool
	var noOpenClawBridge bool

	resolvedDeps := defaultServeDeps()
	if deps != nil {
		if deps.newWatcher != nil {
			resolvedDeps.newWatcher = deps.newWatcher
		}
		if deps.notifyContext != nil {
			resolvedDeps.notifyContext = deps.notifyContext
		}
		if deps.loadSigningKey != nil {
			resolvedDeps.loadSigningKey = deps.loadSigningKey
		}
	}

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start Rampart policy runtime and file watcher",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if err := ensureDefaultRampartDirAccessible(); err != nil {
				return fmt.Errorf("serve: prepare Rampart data directory: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if background {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("serve: resolve home directory: %w", err)
				}

				rampartDir := filepath.Join(home, ".rampart")
				if err := os.MkdirAll(rampartDir, 0o755); err != nil {
					return fmt.Errorf("serve: create runtime directory: %w", err)
				}

				pidPath := filepath.Join(rampartDir, "serve.pid")
				return filetxn.WithLock(pidPath, func() error {
					if err := prepareBackgroundServePID(pidPath); err != nil {
						return err
					}

					logPath := filepath.Join(rampartDir, "serve.log")
					if info, statErr := os.Lstat(logPath); statErr == nil &&
						(info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
						return fmt.Errorf("serve: refusing non-regular or symlinked background log: %s", logPath)
					} else if statErr != nil && !os.IsNotExist(statErr) {
						return fmt.Errorf("serve: inspect background log: %w", statErr)
					}
					logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
					if err != nil {
						return fmt.Errorf("serve: open log file: %w", err)
					}
					defer logFile.Close()

					exePath, err := os.Executable()
					if err != nil {
						return fmt.Errorf("serve: resolve executable path: %w", err)
					}

					readyFile, err := os.CreateTemp(rampartDir, ".serve-ready-*")
					if err != nil {
						return fmt.Errorf("serve: create background readiness marker: %w", err)
					}
					readyPath := readyFile.Name()
					if closeErr := readyFile.Close(); closeErr != nil {
						_ = os.Remove(readyPath)
						return fmt.Errorf("serve: close background readiness marker: %w", closeErr)
					}
					defer os.Remove(readyPath)

					var childArgs []string
					for _, arg := range os.Args[1:] {
						if arg == "--background" || arg == "-b" || strings.HasPrefix(arg, "--background=") {
							continue
						}
						childArgs = append(childArgs, arg)
					}

					child := exec.Command(exePath, childArgs...)
					child.Stdout = logFile
					child.Stderr = logFile
					child.Env = setEnvValue(os.Environ(), backgroundReadyFileEnv, readyPath)
					setDetachAttrs(child)

					if err := child.Start(); err != nil {
						return fmt.Errorf("serve: start background process: %w", err)
					}
					childPID := child.Process.Pid
					cleanupChild := func() {
						_ = child.Process.Kill()
						_, _ = child.Process.Wait()
						removeServePIDIfMatching(pidPath, childPID)
					}

					if err := atomicWritePrivateFile(pidPath, []byte(fmt.Sprintf("%d\n", childPID))); err != nil {
						cleanupChild()
						return fmt.Errorf("serve: write pid file: %w", err)
					}
					if err := waitForBackgroundReady(readyPath, childPID, 5*time.Second); err != nil {
						cleanupChild()
						return fmt.Errorf("serve: background process did not become ready: %w (see %s)", err, logPath)
					}
					if err := child.Process.Release(); err != nil {
						cleanupChild()
						return fmt.Errorf("serve: release background process handle: %w", err)
					}

					fmt.Fprintf(cmd.OutOrStdout(), "rampart serve running in background (pid=%d, log=~/.rampart/serve.log)\n", childPID)
					printNextStep(cmd.OutOrStdout(), "rampart status")
					return nil
				})
			}

			if mode != "enforce" && mode != "monitor" && mode != "disabled" {
				return fmt.Errorf("serve: invalid mode %q (must be enforce, monitor, or disabled)", mode)
			}

			// Resolve ~/.rampart dir for state/token files.
			rampartDir := ""
			if home, hErr := os.UserHomeDir(); hErr == nil {
				rampartDir = filepath.Join(home, ".rampart")
			}
			readyPath, err := consumeBackgroundReadyPath(rampartDir)
			if err != nil {
				return err
			}

			if listenAddr != "" && net.ParseIP(listenAddr) == nil {
				return fmt.Errorf("serve: invalid --addr %q (must be a valid IP address, e.g. 127.0.0.1 or ::1)", listenAddr)
			}

			// Validate TLS flags.
			if (tlsCert == "") != (tlsKey == "") {
				return fmt.Errorf("serve: --tls-cert and --tls-key must be used together")
			}
			if tlsCert != "" && tlsAuto {
				return fmt.Errorf("serve: --tls-cert/--tls-key and --tls-auto are mutually exclusive")
			}

			// Resolve TLS config.
			var tlsCfg *crypto_tls.Config
			var tlsFingerprint string
			if tlsAuto {
				var err error
				tlsCfg, tlsFingerprint, err = tlsutil.LoadOrGenerate(tlsutil.DefaultCertDir())
				if err != nil {
					return fmt.Errorf("serve: tls auto: %w", err)
				}
			} else if tlsCert != "" {
				var err error
				tlsCfg, tlsFingerprint, err = tlsutil.LoadFromFiles(tlsCert, tlsKey)
				if err != nil {
					return fmt.Errorf("serve: tls: %w", err)
				}
			}

			level := slog.LevelInfo
			if opts.verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
			if ip := net.ParseIP(listenAddr); ip != nil && !ip.IsLoopback() && tlsCfg == nil && port > 0 {
				logger.Warn("serve: listening on a non-loopback interface without TLS; bearer tokens and approval traffic will cross the network in plaintext",
					"addr", listenAddr,
					"guidance", "enable --tls-auto/--tls-cert or use a trusted HTTPS reverse proxy",
				)
			}

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

			// Migrate old-format allow-always rules (space before glob: "cmd *" → "cmd*").
			// Safe to run on every startup — no-ops if already migrated.
			autoAllowedPath := engine.DefaultAutoAllowedPath()
			if n, mErr := engine.MigrateAllowRuleGlobs(autoAllowedPath); mErr != nil {
				logger.Warn("serve: auto-allowed glob migration failed", "error", mErr)
			} else if n > 0 {
				logger.Info("serve: migrated allow-always glob patterns", "count", n, "path", autoAllowedPath)
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
			var policyDirAbs string
			if effectiveDir != "" {
				policyDirAbs, err = filepath.Abs(effectiveDir)
				if err != nil {
					return fmt.Errorf("serve: resolve policy directory %s: %w", effectiveDir, err)
				}
				if err := watcher.Add(policyDirAbs); err != nil {
					return fmt.Errorf("serve: watch policy directory %s: %w", policyDirAbs, err)
				}
			}

			logger.Info("serve: started",
				"mode", mode,
				"policy_count", eng.PolicyCount(),
				"audit_dir", auditDir,
				"port", port,
			)

			// Show a startup spinner when running in a terminal with a proxy port.
			var startSpin *cliSpinner
			var startSpinDone bool
			if port > 0 {
				startSpin = newCliSpinner(cmd.ErrOrStderr(), "Starting Rampart")
				defer func() {
					if !startSpinDone && startSpin != nil {
						startSpin.Fail("Rampart failed to start")
					}
				}()
			}

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
				proxyOpts = append(proxyOpts, proxy.WithMode(mode), proxy.WithLogger(logger), proxy.WithMetrics(metrics), proxy.WithAuditDir(auditDir), proxy.WithConfigPath(configPathDisplay), proxy.WithTLS(tlsCfg != nil))
				if approvalTimeout > 0 {
					proxyOpts = append(proxyOpts, proxy.WithApprovalTimeout(approvalTimeout))
				}
				// Persist pending approvals so they survive a serve restart.
				if rampartDir != "" {
					persistFile := filepath.Join(rampartDir, "pending-approvals.jsonl")
					proxyOpts = append(proxyOpts, proxy.WithApprovalPersistenceFile(persistFile))
				}
				// Resolve token: flag > env > persisted file > generate new.
				// Mirrors serve install behaviour so the token survives restarts.
				{
					if tok, _ := resolveTokenValue(); tok != "" {
						proxyOpts = append(proxyOpts, proxy.WithToken(tok))
					}
				}
				if resolveBaseURL != "" {
					proxyOpts = append(proxyOpts, proxy.WithResolveBaseURL(resolveBaseURL))
				}
				// Load notify config once so signing requirements and proxy delivery
				// cannot disagree about whether approval links will be emitted.
				var notifyConfig *engine.NotifyConfig
				if cfg, loadErr := store.Load(); loadErr == nil && cfg.Notify != nil {
					notifyConfig = cfg.Notify
				}

				// Load or auto-generate signing key for approval resolve URLs. A
				// configured key that cannot be secured is a startup failure: silently
				// emitting bearerless unsigned links creates an unusable and misleading
				// approval surface.
				if signingKeyPath == "" {
					home, _ := os.UserHomeDir()
					if home != "" {
						signingKeyPath = filepath.Join(home, ".rampart", "signing.key")
					}
				}
				if signingKeyPath != "" {
					key, keyErr := resolvedDeps.loadSigningKey(signingKeyPath)
					if keyErr != nil {
						return fmt.Errorf("serve: approval resolve URL signing unavailable: %w", keyErr)
					}
					proxyOpts = append(proxyOpts, proxy.WithSigner(signing.NewSigner(key)))
					logger.Info("serve: approval URL signing enabled", "key_path", signingKeyPath)
				} else if notifyRequiresSignedApprovalLinks(notifyConfig) {
					return fmt.Errorf("serve: approval notifications require a signing key, but no user home or --signing-key path is available")
				}
				if notifyConfig != nil {
					proxyOpts = append(proxyOpts, proxy.WithNotify(notifyConfig))
					logger.Info("serve: webhook notifications enabled", "platform", notifyConfig.Platform)
				}
				// Load per-agent token store.
				if tokenStorePath, tsErr := token.DefaultStorePath(); tsErr == nil {
					if ts, tsErr := token.NewStore(tokenStorePath); tsErr == nil {
						proxyOpts = append(proxyOpts, proxy.WithTokenStore(ts))
						if n := ts.Count(); n > 0 {
							logger.Info("serve: per-agent tokens loaded", "count", n)
						}
					} else {
						logger.Warn("serve: failed to load token store", "error", tsErr)
					}
				}
				proxyServer = proxy.New(eng, sink, proxyOpts...)
				listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", listenAddr, port))
				if err != nil {
					return fmt.Errorf("serve: proxy listen failed: %w", err)
				}

				if err := writeActivePolicyMarkdown(eng); err != nil {
					logger.Warn("serve: failed to write ACTIVE_POLICY.md", "error", err)
				}

				token := proxyServer.Token()
				display := token
				if len(token) > 8 {
					display = token[:8] + "..."
				}
				listenPort := listener.Addr().(*net.TCPAddr).Port

				// Persist before reporting readiness or starting the server.
				// Hooks cannot authenticate safely without the shared token.
				if err := persistToken(token); err != nil {
					_ = listener.Close()
					return fmt.Errorf("serve: persist token: %w", err)
				}

				// Stop the startup spinner and print a clean ready message.
				if startSpin != nil {
					startSpin.Stop(fmt.Sprintf("Rampart ready  —  :%d (token=%s)", listenPort, display))
					startSpinDone = true
				}

				// Only print the full token to an interactive terminal, never to
				// a log file or redirected stderr (background mode redirects stderr to serve.log).
				interactiveStderr := isTerminal(os.Stderr)
				printServeToken(cmd.ErrOrStderr(), token, interactiveStderr)
				scheme := "http"
				if tlsCfg != nil {
					scheme = "https"
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "  🌐 Dashboard  : %s://localhost:%d/dashboard/\n", scheme, listenPort)
				if tlsCfg != nil && tlsFingerprint != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "  🔒 TLS        : sha256:%s\n", tlsFingerprint[:23]+"...")
				}

				if metrics {
					logger.Info("serve: metrics enabled on /metrics")
				}

				// Write serve state file for discovery by doctor/watch/log.
				if rampartDir != "" {
					if err := writeServeState(rampartDir, listenPort, os.Getpid(), tlsCfg != nil); err != nil {
						logger.Warn("serve: failed to write state file", "error", err)
					}
				}

				proxyErrCh = make(chan error, 1)
				go func() {
					if tlsCfg != nil {
						// Wrap the listener with TLS.
						tlsListener := crypto_tls.NewListener(listener, tlsCfg)
						proxyErrCh <- proxyServer.Serve(tlsListener)
					} else {
						proxyErrCh <- proxyServer.Serve(listener)
					}
				}()
			}

			// Auto-start OpenClaw bridge if gateway is discoverable.
			var openclawBridge *bridge.OpenClawBridge
			if !noOpenClawBridge {
				gwURL, gwToken, autoResolveAllowDecisions, discoverErr := bridge.DiscoverGatewayConfigForBridge()
				if discoverErr == nil {
					openclawBridge = bridge.NewOpenClawBridge(eng, bridge.Config{
						GatewayURL:                gwURL,
						GatewayToken:              gwToken,
						Logger:                    logger,
						AuditSink:                 sink,
						AutoResolveAllowDecisions: &autoResolveAllowDecisions,
					})
					bridgeCtx, bridgeCancel := context.WithCancel(cmd.Context())
					defer bridgeCancel()
					logger.Info("bridge: starting OpenClaw gateway bridge", "url", gwURL)
					go func() {
						if err := openclawBridge.Start(bridgeCtx); err != nil && bridgeCtx.Err() == nil {
							logger.Warn("bridge: OpenClaw bridge stopped", "error", err)
						}
					}()
				} else {
					logger.Debug("bridge: OpenClaw gateway not discoverable, skipping bridge", "error", discoverErr)
				}
			}

			if readyPath != "" {
				if err := atomicWritePrivateFile(readyPath, []byte(fmt.Sprintf("%d\n", os.Getpid()))); err != nil {
					return fmt.Errorf("serve: signal background readiness: %w", err)
				}
			}

			sigCtx, stop := resolvedDeps.notifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			lastReload := time.Time{}
			for {
				select {
				case <-sigCtx.Done():
					logger.Info("serve: shutting down...")
					if openclawBridge != nil {
						openclawBridge.Close()
					}
					if rampartDir != "" {
						removeServeState(rampartDir)
					}
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
					// Brief delay on Windows to let OS release file handles before process exits.
					// Without this, Windows Defender or the indexer can lock files briefly.
					if runtime.GOOS == "windows" {
						time.Sleep(200 * time.Millisecond)
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
					configChanged := !usingEmbedded && isWriteEvent(event) && samePath(configAbs, event.Name)
					policyDirChanged := isPolicyDirEvent(event, policyDirAbs)
					if !configChanged && !policyDirChanged {
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
					if err := writeActivePolicyMarkdown(eng); err != nil {
						logger.Warn("serve: failed to write ACTIVE_POLICY.md after reload", "error", err)
					}
					logger.Info("serve: policy reloaded", "path", event.Name, "policy_count", eng.PolicyCount())
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
	cmd.Flags().StringVar(&listenAddr, "addr", "127.0.0.1", "Bind address (default: localhost only). Non-loopback addresses require TLS or a trusted HTTPS reverse proxy")
	cmd.Flags().StringVar(&syslogAddr, "syslog", "", "Syslog server address (e.g. localhost:514)")
	cmd.Flags().BoolVar(&cef, "cef", false, "Use CEF format (with --syslog: CEF over syslog; standalone: write ~/.rampart/audit/cef.log)")
	cmd.Flags().StringVar(&resolveBaseURL, "resolve-base-url", "", "Base URL for approval resolve links (e.g. https://rampart.example.com:9090)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "Path to HMAC signing key for resolve URLs (default: ~/.rampart/signing.key, auto-generated)")
	cmd.Flags().BoolVar(&metrics, "metrics", false, "Enable Prometheus metrics endpoint on /metrics")
	cmd.Flags().BoolVarP(&background, "background", "b", false, "Run serve in background and write logs to ~/.rampart/serve.log")
	cmd.Flags().StringVar(&configDir, "config-dir", "", "Directory of additional policy YAML files (default: ~/.rampart/policies/ if it exists)")
	cmd.Flags().DurationVar(&reloadInterval, "reload-interval", 0, "How often to re-read policy files (0 = disabled; fsnotify handles hot-reload automatically)")
	cmd.Flags().DurationVar(&approvalTimeout, "approval-timeout", 0, "How long approvals stay pending before expiring (default: 2m, matches OpenClaw)")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate PEM file")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS private key PEM file")
	cmd.Flags().BoolVar(&tlsAuto, "tls-auto", false, "Auto-generate self-signed TLS certificate")
	cmd.Flags().BoolVar(&noOpenClawBridge, "no-openclaw-bridge", false, "Disable auto-starting the OpenClaw bridge even if gateway is discoverable")

	cmd.AddCommand(newServeInstallCmd(opts, nil))
	cmd.AddCommand(newServeUninstallCmd(nil))
	cmd.AddCommand(newServeStopCmd())

	return cmd
}

func newServeStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop a background rampart serve process",
		Long:  `Stop a rampart serve process started with --background by reading and authenticating the PID in ~/.rampart/serve.pid before terminating it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return stopBackgroundServe(cmd.OutOrStdout(), false)
		},
	}
}

func stopBackgroundServe(w io.Writer, missingOK bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("serve stop: %w", err)
	}
	pidPath := filepath.Join(home, ".rampart", "serve.pid")
	pid, exists, err := readServePIDFile(pidPath)
	if err != nil {
		return fmt.Errorf("serve stop: %w", err)
	}
	if !exists {
		if missingOK {
			return nil
		}
		return fmt.Errorf("serve stop: no PID file found at %s (is rampart serve --background running?)", pidPath)
	}
	owned, identity, err := isRampartServeProcess(pid)
	if err != nil {
		return fmt.Errorf("serve stop: verify pid %d before signaling: %w", pid, err)
	}
	if !owned {
		_ = os.Remove(pidPath)
		if missingOK {
			return nil
		}
		if identity == "" {
			identity = "process is no longer running"
		}
		return fmt.Errorf("serve stop: refusing to signal stale pid %d (%s)", pid, identity)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("serve stop: find process %d: %w", pid, err)
	}
	if err := terminateRampartServeProcess(proc); err != nil {
		_ = os.Remove(pidPath)
		return fmt.Errorf("serve stop: signal pid %d: %w (process may have already exited)", pid, err)
	}
	_ = os.Remove(pidPath)
	fmt.Fprintf(w, "✓ rampart serve (pid=%d) stopped\n", pid)
	return nil
}

func readServePIDFile(pidPath string) (int, bool, error) {
	info, err := os.Lstat(pidPath)
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read pid file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return 0, false, fmt.Errorf("refusing non-regular or symlinked pid file: %s", pidPath)
	}
	if info.Size() > maxServePIDFileBytes {
		return 0, false, fmt.Errorf("pid file exceeds %d bytes: %s", maxServePIDFileBytes, pidPath)
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, false, fmt.Errorf("read pid file: %w", err)
	}
	pidText := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 {
		return 0, false, fmt.Errorf("invalid PID %q in %s", pidText, pidPath)
	}
	return pid, true, nil
}

func prepareBackgroundServePID(pidPath string) error {
	pid, exists, err := readServePIDFile(pidPath)
	if err != nil || !exists {
		return err
	}
	owned, identity, err := inspectBackgroundServeProcess(pid)
	if err != nil {
		return fmt.Errorf("serve: verify existing pid %d: %w", pid, err)
	}
	if owned {
		return fmt.Errorf("serve: background server is already running (pid=%d)", pid)
	}
	if err := os.Remove(pidPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("serve: remove stale pid %d (%s): %w", pid, identity, err)
	}
	return nil
}

func removeServePIDIfMatching(pidPath string, expectedPID int) {
	pid, exists, err := readServePIDFile(pidPath)
	if err == nil && exists && pid == expectedPID {
		_ = os.Remove(pidPath)
	}
}

func consumeBackgroundReadyPath(rampartDir string) (string, error) {
	value := strings.TrimSpace(os.Getenv(backgroundReadyFileEnv))
	_ = os.Unsetenv(backgroundReadyFileEnv)
	if value == "" {
		return "", nil
	}
	if rampartDir == "" {
		return "", fmt.Errorf("serve: background readiness path requires a user home")
	}
	absPath, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("serve: resolve background readiness path: %w", err)
	}
	absDir, err := filepath.Abs(rampartDir)
	if err != nil {
		return "", fmt.Errorf("serve: resolve runtime directory: %w", err)
	}
	if !samePath(filepath.Dir(absPath), absDir) || !strings.HasPrefix(filepath.Base(absPath), ".serve-ready-") {
		return "", fmt.Errorf("serve: invalid background readiness path")
	}
	return absPath, nil
}

func waitForBackgroundReady(path string, pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	want := strconv.Itoa(pid)
	for {
		info, err := os.Lstat(path)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("readiness marker became non-regular or symlinked")
			}
			if info.Size() <= maxServePIDFileBytes {
				if data, readErr := os.ReadFile(path); readErr == nil && strings.TrimSpace(string(data)) == want {
					return nil
				}
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", timeout)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func isRampartServeCommand(comm, args string) bool {
	name := strings.ToLower(filepath.Base(strings.TrimSpace(comm)))
	if name != "rampart" && name != "rampart.exe" {
		return false
	}
	remaining, ok := commandLineAfterExecutable(args)
	if !ok {
		return false
	}
	fields := strings.Fields(remaining)
	for i := 0; i < len(fields); i++ {
		arg := fields[i]
		switch {
		case arg == "--config":
			// --config is the only root flag with a separate value. Refuse a
			// malformed command rather than treating that value as a subcommand.
			if i+1 >= len(fields) {
				return false
			}
			i++
		case arg == "--version":
			// Cobra exits after the root version flag; a later `serve` token is
			// not an executed subcommand.
			return false
		case strings.HasPrefix(arg, "--config=") || arg == "--verbose" ||
			strings.HasPrefix(arg, "--verbose="):
			continue
		case strings.HasPrefix(arg, "-"):
			// An unknown root flag may consume a value. Failing closed avoids
			// authenticating an unrelated/reused PID on ambiguous input.
			return false
		default:
			return arg == "serve"
		}
	}
	return false
}

func commandLineAfterExecutable(commandLine string) (string, bool) {
	commandLine = strings.TrimSpace(commandLine)
	if commandLine == "" {
		return "", false
	}
	if commandLine[0] == '"' || commandLine[0] == '\'' {
		quote := commandLine[0]
		escaped := false
		for i := 1; i < len(commandLine); i++ {
			if escaped {
				escaped = false
				continue
			}
			if commandLine[i] == '\\' {
				escaped = true
				continue
			}
			if commandLine[i] == quote {
				return strings.TrimSpace(commandLine[i+1:]), true
			}
		}
		return "", false
	}
	if index := strings.IndexAny(commandLine, " \t\r\n"); index >= 0 {
		return strings.TrimSpace(commandLine[index:]), true
	}
	return "", false
}

func isWriteEvent(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write)
}

func isPolicyDirEvent(event fsnotify.Event, policyDir string) bool {
	if policyDir == "" {
		return false
	}
	eventPath := filepath.Clean(strings.TrimSpace(event.Name))
	if !samePath(filepath.Dir(eventPath), policyDir) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(eventPath))
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	return event.Has(fsnotify.Write) || event.Has(fsnotify.Create) ||
		event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)
}

func samePath(a, b string) bool {
	left := filepath.Clean(strings.TrimSpace(a))
	right := filepath.Clean(strings.TrimSpace(b))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func writeActivePolicyMarkdown(eng *engine.Engine) error {
	if eng == nil {
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	rampartDir := filepath.Join(home, ".rampart")
	if err := os.MkdirAll(rampartDir, 0o700); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}
	if err := secureDirPermissions(rampartDir); err != nil {
		return fmt.Errorf("secure runtime directory: %w", err)
	}

	defaultAction, rules := eng.GetPolicySummary()
	lastLoaded := eng.LastLoadedAt().UTC().Format(time.RFC3339)

	var b strings.Builder
	b.WriteString("# Rampart Active Policy\n\n")
	b.WriteString(fmt.Sprintf("Last loaded: `%s`\n\n", lastLoaded))
	b.WriteString(fmt.Sprintf("Default action: `%s`\n\n", defaultAction))
	b.WriteString("| Name | Action | Summary |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, rule := range rules {
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
			escapeMarkdownCell(rule.Name),
			escapeMarkdownCell(rule.Action),
			escapeMarkdownCell(rule.Summary),
		))
	}
	if len(rules) == 0 {
		b.WriteString("| (none) | - | No active rules loaded |\n")
	}
	b.WriteString("\nUse `rampart watch`, `rampart log`, and `rampart approve` for live transparency and approvals.\n")

	outPath := filepath.Join(rampartDir, "ACTIVE_POLICY.md")
	if err := atomicWritePrivateFile(outPath, []byte(b.String())); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}

func escapeMarkdownCell(v string) string {
	return strings.ReplaceAll(strings.TrimSpace(v), "|", "\\|")
}
