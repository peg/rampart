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
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	upgradeLatestReleaseURL = "https://api.github.com/repos/peg/rampart/releases/latest"
	upgradeReleaseBaseURL   = "https://github.com/peg/rampart/releases/download"
	maxUpgradeDownloadBytes = int64(256 << 20)
	maxUpgradeBinaryBytes   = int64(200 << 20)
	maxUpgradeExpandedBytes = int64(512 << 20)
	maxUpgradeArchiveFiles  = 1024
)

type upgradeDeps struct {
	httpClient            *http.Client
	executablePath        func() (string, error)
	userHomeDir           func() (string, error)
	readFile              func(string) ([]byte, error)
	chmod                 func(string, os.FileMode) error
	rename                func(string, string) error
	createTemp            func(string, string) (*os.File, error)
	remove                func(string) error
	commandRunner         commandRunner
	currentVersion        func(context.Context, commandRunner, func() (string, error)) (string, error)
	latestRelease         func(context.Context, *http.Client, string) (string, error)
	downloadURL           func(context.Context, *http.Client, string) ([]byte, error)
	validateCandidate     func(context.Context, string, string) error
	inspectServePID       func(func() (string, error), func(string) ([]byte, error)) (int, bool, error)
	stopServe             func(int) error
	restartServe          func(commandRunner, string, io.Writer, io.Writer) error
	detectSystemdService  func(commandRunner, func() (string, error), string) string
	restartSystemdService func(commandRunner, string, io.Writer) error
	detectLaunchdServices func(commandRunner, func() (string, error), string) []launchdService
	restartLaunchdService func(commandRunner, launchdService, io.Writer) error
	prepareServeVerifier  func(func() (string, error), func(string) ([]byte, error)) (serveRestartVerifier, error)
	pathEnv               func() string
	lstat                 func(string) (os.FileInfo, error)
	evalSymlinks          func(string) (string, error)
	updatePolicies        func(io.Writer, bool) error
	refreshPolicies       func(commandRunner, string, io.Writer, io.Writer) error
	goos                  string
	goarch                string
}

func defaultUpgradeDeps() upgradeDeps {
	return upgradeDeps{
		httpClient:            &http.Client{Timeout: 20 * time.Second},
		executablePath:        os.Executable,
		userHomeDir:           os.UserHomeDir,
		readFile:              os.ReadFile,
		chmod:                 os.Chmod,
		rename:                filetxn.Replace,
		createTemp:            os.CreateTemp,
		remove:                os.Remove,
		commandRunner:         exec.Command,
		currentVersion:        currentVersion,
		latestRelease:         fetchLatestRelease,
		downloadURL:           downloadURL,
		validateCandidate:     validateUpgradeCandidate,
		inspectServePID:       inspectServePID,
		stopServe:             stopServeProcess,
		restartServe:          restartServe,
		detectSystemdService:  detectActiveSystemdService,
		restartSystemdService: restartSystemdUserService,
		detectLaunchdServices: detectActiveLaunchdServices,
		restartLaunchdService: restartLaunchdUserService,
		prepareServeVerifier:  prepareServeRestartVerifier,
		pathEnv: func() string {
			return os.Getenv("PATH")
		},
		lstat:           os.Lstat,
		evalSymlinks:    filepath.EvalSymlinks,
		updatePolicies:  upgradeStandardPolicies,
		refreshPolicies: refreshPoliciesWithInstalledBinary,
		goos:            runtime.GOOS,
		goarch:          runtime.GOARCH,
	}
}

func newUpgradeCmd(opts *rootOptions) *cobra.Command {
	return newUpgradeCmdWithDeps(opts, nil)
}

func newUpgradeCmdWithDeps(_ *rootOptions, deps *upgradeDeps) *cobra.Command {
	resolved := defaultUpgradeDeps()
	if deps != nil {
		if deps.httpClient != nil {
			resolved.httpClient = deps.httpClient
		}
		if deps.executablePath != nil {
			resolved.executablePath = deps.executablePath
		}
		if deps.userHomeDir != nil {
			resolved.userHomeDir = deps.userHomeDir
		}
		if deps.readFile != nil {
			resolved.readFile = deps.readFile
		}
		if deps.chmod != nil {
			resolved.chmod = deps.chmod
		}
		if deps.rename != nil {
			resolved.rename = deps.rename
		}
		if deps.createTemp != nil {
			resolved.createTemp = deps.createTemp
		}
		if deps.remove != nil {
			resolved.remove = deps.remove
		}
		if deps.commandRunner != nil {
			resolved.commandRunner = deps.commandRunner
		}
		if deps.currentVersion != nil {
			resolved.currentVersion = deps.currentVersion
		}
		if deps.latestRelease != nil {
			resolved.latestRelease = deps.latestRelease
		}
		if deps.downloadURL != nil {
			resolved.downloadURL = deps.downloadURL
		}
		if deps.validateCandidate != nil {
			resolved.validateCandidate = deps.validateCandidate
		}
		if deps.inspectServePID != nil {
			resolved.inspectServePID = deps.inspectServePID
		}
		if deps.stopServe != nil {
			resolved.stopServe = deps.stopServe
		}
		if deps.restartServe != nil {
			resolved.restartServe = deps.restartServe
		}
		if deps.detectSystemdService != nil {
			resolved.detectSystemdService = deps.detectSystemdService
		}
		if deps.restartSystemdService != nil {
			resolved.restartSystemdService = deps.restartSystemdService
		}
		if deps.detectLaunchdServices != nil {
			resolved.detectLaunchdServices = deps.detectLaunchdServices
		}
		if deps.restartLaunchdService != nil {
			resolved.restartLaunchdService = deps.restartLaunchdService
		}
		if deps.prepareServeVerifier != nil {
			resolved.prepareServeVerifier = deps.prepareServeVerifier
		}
		if deps.pathEnv != nil {
			resolved.pathEnv = deps.pathEnv
		}
		if deps.lstat != nil {
			resolved.lstat = deps.lstat
		}
		if deps.evalSymlinks != nil {
			resolved.evalSymlinks = deps.evalSymlinks
		}
		if deps.updatePolicies != nil {
			resolved.updatePolicies = deps.updatePolicies
		}
		if deps.refreshPolicies != nil {
			resolved.refreshPolicies = deps.refreshPolicies
		}
		if deps.goos != "" {
			resolved.goos = deps.goos
		}
		if deps.goarch != "" {
			resolved.goarch = deps.goarch
		}
	}

	var assumeYes bool
	var dryRun bool
	var skipPolicyUpdate bool
	var noBinary bool

	cmd := &cobra.Command{
		Use:   "upgrade [version]",
		Short: "Upgrade Rampart on macOS/Linux, or refresh built-in policies",
		Long: "Upgrade Rampart to the latest or specified release on macOS and Linux.\n" +
			"On Windows, rerun the official install.ps1 installer. Policy-only refreshes\n" +
			"remain available on every platform with --no-binary.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (runErr error) {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			// --no-binary: just refresh built-in policies, skip binary download.
			if noBinary {
				if skipPolicyUpdate {
					return fmt.Errorf("--no-binary and --no-policy-update are mutually exclusive")
				}
				if err := resolved.updatePolicies(cmd.OutOrStdout(), dryRun); err != nil {
					return fmt.Errorf("policy refresh: %w", err)
				}
				return nil
			}
			if resolved.goos == "windows" {
				return fmt.Errorf("upgrade: self-upgrade is not supported on Windows; rerun the official installer: irm https://rampart.sh/install.ps1 | iex")
			}

			current, err := resolved.currentVersion(ctx, resolved.commandRunner, resolved.executablePath)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not determine current version: %v\n", err)
			}

			target := ""
			if len(args) > 0 {
				target, err = normalizeVersion(args[0])
				if err != nil {
					return fmt.Errorf("upgrade: invalid version %q: %w", args[0], err)
				}
			} else {
				target, err = resolved.latestRelease(ctx, resolved.httpClient, upgradeLatestReleaseURL)
				if err != nil {
					return err
				}
			}

			// Current releases reject the removed require_approval policy action.
			// Scan on every upgrade/check against a modern target so users who
			// carried an old custom policy past the original transition still get
			// actionable guidance instead of a surprising policy-load failure.
			if compareSemver(target, "v0.9.9") >= 0 {
				if err := maybeWarnRequireApprovalMigration(cmd.OutOrStdout(), cmd.ErrOrStderr(), cmd.InOrStdin(), assumeYes, resolved.userHomeDir); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "⚠ migration policy scan failed: %v\n", err)
				}
			}

			if current != "" && compareSemver(current, target) >= 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Already on latest (%s)\n", target)
				if !skipPolicyUpdate {
					if err := resolved.updatePolicies(cmd.OutOrStdout(), dryRun); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "⚠ policy update failed: %v\n", err)
					}
				}
				return nil
			}

			assetOS, assetArch, err := upgradePlatform(resolved.goos, resolved.goarch)
			if err != nil {
				return err
			}
			versionNoV := strings.TrimPrefix(target, "v")
			archiveName := fmt.Sprintf("rampart_%s_%s_%s.tar.gz", versionNoV, assetOS, assetArch)
			archiveURL := fmt.Sprintf("%s/%s/%s", upgradeReleaseBaseURL, target, archiveName)
			checksumsURL := fmt.Sprintf("%s/%s/checksums.txt", upgradeReleaseBaseURL, target)

			exePath, err := resolved.executablePath()
			if err != nil {
				return fmt.Errorf("upgrade: locate current executable: %w", err)
			}
			exePath, err = filepath.Abs(exePath)
			if err != nil {
				return fmt.Errorf("upgrade: resolve executable path: %w", err)
			}
			if err := validateSelfUpgradePath(exePath, resolved); err != nil {
				return err
			}

			// A platform service takes priority over PID-file management. Service
			// processes do not write ~/.rampart/serve.pid, and must be restarted
			// explicitly so they load the newly replaced executable. Detect them
			// before reading a fallback PID file so stale fallback state cannot
			// block an otherwise healthy service-managed upgrade.
			activeSvc := ""
			var activeLaunchd []launchdService
			switch resolved.goos {
			case "linux":
				activeSvc = resolved.detectSystemdService(resolved.commandRunner, resolved.userHomeDir, exePath)
			case "darwin":
				activeLaunchd = resolved.detectLaunchdServices(resolved.commandRunner, resolved.userHomeDir, exePath)
			}
			servePID := 0
			serveRunning := activeSvc != "" || len(activeLaunchd) > 0
			if !serveRunning {
				servePID, serveRunning, err = resolved.inspectServePID(resolved.userHomeDir, resolved.readFile)
				if err != nil {
					return err
				}
			}
			pidServeRunning := serveRunning && activeSvc == "" && len(activeLaunchd) == 0

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "Dry run:\n")
				fmt.Fprintf(cmd.OutOrStdout(), "- would upgrade from %s to %s\n", displayVersion(current), target)
				fmt.Fprintf(cmd.OutOrStdout(), "- would download %s\n", archiveURL)
				fmt.Fprintf(cmd.OutOrStdout(), "- would verify SHA256 from %s\n", checksumsURL)
				if pidServeRunning {
					fmt.Fprintf(cmd.OutOrStdout(), "- would stop rampart serve (pid %d)\n", servePID)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "- would atomically replace %s\n", exePath)
				fmt.Fprintf(cmd.OutOrStdout(), "- would scan PATH and warn about other rampart executables without modifying them\n")
				if !skipPolicyUpdate {
					fmt.Fprintf(cmd.OutOrStdout(), "- would refresh managed built-in policies with the new binary\n")
				}
				if activeSvc != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "- would restart systemd service: %s\n", activeSvc)
				} else if len(activeLaunchd) > 0 {
					for _, service := range activeLaunchd {
						fmt.Fprintf(cmd.OutOrStdout(), "- would restart launchd service: %s\n", service.Label)
					}
				} else if pidServeRunning {
					fmt.Fprintf(cmd.OutOrStdout(), "- would restart rampart serve in background\n")
				}
				if serveRunning {
					fmt.Fprintln(cmd.OutOrStdout(), "- would verify a fresh Rampart-owned local runtime at the target version before discarding rollback")
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ dry run complete\n")
				return nil
			}

			if !assumeYes {
				confirmed, err := confirmUpgrade(cmd.InOrStdin(), cmd.OutOrStdout(), current, target)
				if err != nil {
					return err
				}
				if !confirmed {
					fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
					return nil
				}
			}

			dlSpin := newCliSpinner(cmd.OutOrStdout(), fmt.Sprintf("Downloading %s", target))
			archiveBytes, err := resolved.downloadURL(ctx, resolved.httpClient, archiveURL)
			if err != nil {
				dlSpin.Fail("Download failed")
				return err
			}
			checksumsBytes, err := resolved.downloadURL(ctx, resolved.httpClient, checksumsURL)
			if err != nil {
				dlSpin.Fail("Download failed")
				return err
			}
			dlSpin.Stop(fmt.Sprintf("Downloaded %s", target))

			expectedHash, err := lookupSHA256(checksumsBytes, archiveName)
			if err != nil {
				return fmt.Errorf("upgrade: verify checksums.txt: %w", err)
			}

			actualHash := sha256.Sum256(archiveBytes)
			actualHashHex := hex.EncodeToString(actualHash[:])
			if !strings.EqualFold(expectedHash, actualHashHex) {
				return fmt.Errorf("upgrade: checksum mismatch for %s (expected %s, got %s)", archiveName, expectedHash, actualHashHex)
			}

			newBinary, err := extractRampartBinary(archiveBytes)
			if err != nil {
				return err
			}

			candidatePath, err := stageUpgradeCandidate(exePath, newBinary, resolved)
			if err != nil {
				return err
			}
			defer func() { _ = resolved.remove(candidatePath) }()
			if err := resolved.validateCandidate(ctx, candidatePath, target); err != nil {
				return err
			}

			var restartVerifier serveRestartVerifier
			if serveRunning {
				restartVerifier, err = resolved.prepareServeVerifier(resolved.userHomeDir, resolved.readFile)
				if err != nil {
					return fmt.Errorf("upgrade: prepare runtime health verification: %w", err)
				}
			}
			verifyRestartedRuntime := func(expectedVersion string, restartedAt time.Time) error {
				if restartVerifier == nil {
					return fmt.Errorf("upgrade: runtime health verifier is unavailable")
				}
				if err := restartVerifier(ctx, expectedVersion, restartedAt); err != nil {
					return fmt.Errorf("upgrade: restarted runtime did not become healthy: %w", err)
				}
				return nil
			}
			restartPIDRuntime := func(expectedVersion string) error {
				restartedAt := time.Now()
				if err := resolved.restartServe(resolved.commandRunner, exePath, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
					return err
				}
				return verifyRestartedRuntime(expectedVersion, restartedAt)
			}

			pidServeNeedsRestart := false
			defer func() {
				if !pidServeNeedsRestart {
					return
				}
				if restartErr := restartPIDRuntime(current); restartErr != nil {
					restartErr = fmt.Errorf("upgrade: restore previously running rampart serve: %w", restartErr)
					if runErr == nil {
						runErr = restartErr
					} else {
						runErr = errors.Join(runErr, restartErr)
					}
					return
				}
				fmt.Fprintln(cmd.OutOrStdout(), "✓ restored previously running rampart serve")
			}()

			if pidServeRunning {
				if err := resolved.stopServe(servePID); err != nil {
					return err
				}
				// From this point until a successful explicit restart, every error
				// path must restore the previously running background server. In
				// particular, an atomic replacement failure leaves the old binary
				// installed and should not also leave protection offline.
				pidServeNeedsRestart = true
			}

			installSpin := newCliSpinner(cmd.OutOrStdout(), "Installing")
			backupPath, err := activateUpgradeCandidate(exePath, candidatePath, resolved)
			if err != nil {
				installSpin.Fail("Installation failed")
				if isPermissionError(err) {
					return fmt.Errorf("upgrade: %w\n💡 Try this: sudo rampart upgrade", err)
				}
				return err
			}
			if err := resolved.validateCandidate(ctx, exePath, target); err != nil {
				installSpin.Fail("Installation validation failed")
				if rollbackErr := resolved.rename(backupPath, exePath); rollbackErr != nil {
					return errors.Join(err, fmt.Errorf("upgrade: restore previous executable from %s: %w", backupPath, rollbackErr))
				}
				return fmt.Errorf("%w; restored the previous Rampart executable", err)
			}
			installSpin.Stop(fmt.Sprintf("Installed %s", target))

			// Keep the rollback executable until every previously active runtime has
			// loaded the candidate and proved its identity and version over a fresh
			// local health endpoint. Binary replacement and runtime continuity are one
			// transaction: a restart or health-proof failure restores both.
			restartManagedServices := func(expectedVersion string) []error {
				var restartErrs []error
				if activeSvc != "" {
					restartedAt := time.Now()
					if err := resolved.restartSystemdService(resolved.commandRunner, activeSvc, cmd.OutOrStdout()); err != nil {
						restartErrs = append(restartErrs, err)
					} else if err := verifyRestartedRuntime(expectedVersion, restartedAt); err != nil {
						restartErrs = append(restartErrs, fmt.Errorf("verify %s after restart: %w", activeSvc, err))
					}
					return restartErrs
				}
				for _, service := range activeLaunchd {
					restartedAt := time.Now()
					if err := resolved.restartLaunchdService(resolved.commandRunner, service, cmd.OutOrStdout()); err != nil {
						restartErrs = append(restartErrs, err)
						continue
					}
					if err := verifyRestartedRuntime(expectedVersion, restartedAt); err != nil {
						restartErrs = append(restartErrs, fmt.Errorf("verify %s after restart: %w", service.Label, err))
					}
				}
				return restartErrs
			}

			var runtimeRestartErrs []error
			if activeSvc != "" {
				runtimeRestartErrs = restartManagedServices(target)
			} else if len(activeLaunchd) > 0 {
				runtimeRestartErrs = restartManagedServices(target)
			} else if pidServeRunning {
				if err := restartPIDRuntime(target); err != nil {
					runtimeRestartErrs = append(runtimeRestartErrs, err)
				} else {
					pidServeNeedsRestart = false
				}
			}

			if len(runtimeRestartErrs) > 0 {
				restartCause := errors.Join(runtimeRestartErrs...)
				if rollbackErr := resolved.rename(backupPath, exePath); rollbackErr != nil {
					return errors.Join(
						fmt.Errorf("upgrade: candidate runtime activation failed: %w", restartCause),
						fmt.Errorf("upgrade: restore previous executable from %s: %w", backupPath, rollbackErr),
					)
				}
				backupPath = ""

				var recoveryErrs []error
				if activeSvc != "" || len(activeLaunchd) > 0 {
					recoveryErrs = restartManagedServices(current)
				} else if pidServeRunning {
					// Recovery below is the one authoritative retry. Disable the
					// deferred fallback first so a failed recovery is reported once
					// instead of starting an uncontrolled third process attempt.
					pidServeNeedsRestart = false
					if recoveryErr := restartPIDRuntime(current); recoveryErr != nil {
						recoveryErrs = append(recoveryErrs, recoveryErr)
					}
				}
				if len(recoveryErrs) > 0 {
					return errors.Join(
						fmt.Errorf("upgrade: candidate runtime activation failed; restored the previous executable: %w", restartCause),
						fmt.Errorf("upgrade: previous runtime recovery could not be verified: %w", errors.Join(recoveryErrs...)),
					)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "✓ restored the previous Rampart executable and runtime")
				return fmt.Errorf("upgrade: candidate runtime activation failed; restored the previous Rampart executable and runtime: %w", restartCause)
			}

			if err := resolved.remove(backupPath); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(cmd.ErrOrStderr(), "⚠ upgraded runtime is healthy, but prior executable cleanup failed at %s: %v\n", backupPath, err)
			}

			warnAboutPathCopies(cmd.OutOrStdout(), exePath, resolved)
			if !skipPolicyUpdate {
				if err := resolved.refreshPolicies(resolved.commandRunner, exePath, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
					// Non-fatal: the verified binary and any active runtime are healthy,
					// and the user can retry only the managed policy refresh.
					fmt.Fprintf(cmd.ErrOrStderr(), "⚠ policy update failed (binary upgrade succeeded): %v\n", err)
					fmt.Fprintf(cmd.ErrOrStderr(), "  run %s upgrade --no-binary to retry\n", shellQuoteCodexHookArg(exePath))
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ rampart binary upgraded to %s\n", target)
			fmt.Fprintln(cmd.OutOrStdout(), "Next: run 'rampart protect' once to refresh managed agent integrations and verify detected boundaries.")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would happen without changing anything")
	cmd.Flags().BoolVar(&skipPolicyUpdate, "no-policy-update", false, "Skip refreshing built-in policy profiles after upgrade")
	cmd.Flags().BoolVar(&noBinary, "no-binary", false, "Refresh built-in policies only (skip binary upgrade)")

	return cmd
}

func displayVersion(v string) string {
	if v == "" {
		return "(unknown)"
	}
	return v
}

func currentVersion(ctx context.Context, runner commandRunner, executablePath func() (string, error)) (string, error) {
	_ = ctx
	if v, err := normalizeVersion(build.Version); err == nil && strings.TrimPrefix(v, "v") != "dev" {
		return v, nil
	}

	exe, err := executablePath()
	if err != nil {
		return "", err
	}

	cmd := runner(exe, "version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`(?m)^rampart\s+(\S+)`)
	match := re.FindStringSubmatch(string(out))
	if len(match) < 2 {
		return "", fmt.Errorf("parse --version output")
	}
	v, err := normalizeVersion(match[1])
	if err != nil {
		return "", err
	}
	if strings.TrimPrefix(v, "v") == "dev" {
		return "", nil
	}
	return v, nil
}

func normalizeVersion(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errors.New("empty version")
	}
	if strings.EqualFold(v, "dev") {
		return "vdev", nil
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}

	base := strings.TrimPrefix(v, "v")
	if strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("invalid version")
	}
	if _, ok := parseStrictSemver(v); !ok {
		return "", fmt.Errorf("must be a valid semantic version")
	}
	return v, nil
}

func compareSemver(a, b string) int {
	if comparison, ok := compareStrictSemver(a, b); ok {
		return comparison
	}
	ac := strings.TrimPrefix(a, "v")
	bc := strings.TrimPrefix(b, "v")
	switch {
	case ac > bc:
		return 1
	case ac < bc:
		return -1
	default:
		return 0
	}
}

type strictSemver struct {
	core       [3]string
	prerelease []string
}

func compareStrictSemver(a, b string) (int, bool) {
	av, aok := parseStrictSemver(a)
	bv, bok := parseStrictSemver(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range av.core {
		if comparison := compareNumericIdentifiers(av.core[i], bv.core[i]); comparison != 0 {
			return comparison, true
		}
	}
	return compareStrictPrerelease(av.prerelease, bv.prerelease), true
}

func parseStrictSemver(v string) (strictSemver, bool) {
	var out strictSemver
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || strings.Contains(v, " ") {
		return out, false
	}

	main, buildMetadata, hasBuild := strings.Cut(v, "+")
	if hasBuild {
		if buildMetadata == "" || strings.Contains(buildMetadata, "+") || !validSemverIdentifiers(buildMetadata, false) {
			return out, false
		}
	}
	core, prerelease, hasPrerelease := strings.Cut(main, "-")
	parts := strings.Split(core, ".")
	if len(parts) != len(out.core) {
		return out, false
	}
	for i, part := range parts {
		if !isASCIIDigits(part) || (len(part) > 1 && part[0] == '0') {
			return out, false
		}
		out.core[i] = part
	}
	if hasPrerelease {
		if prerelease == "" || !validSemverIdentifiers(prerelease, true) {
			return out, false
		}
		out.prerelease = strings.Split(prerelease, ".")
	}
	return out, true
}

func validSemverIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		allNumeric := true
		for _, r := range identifier {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
			if r < '0' || r > '9' {
				allNumeric = false
			}
		}
		if rejectNumericLeadingZero && allNumeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func isASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func compareNumericIdentifiers(a, b string) int {
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareStrictPrerelease(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		aNumeric := isASCIIDigits(a[i])
		bNumeric := isASCIIDigits(b[i])
		var comparison int
		switch {
		case aNumeric && bNumeric:
			comparison = compareNumericIdentifiers(a[i], b[i])
		case aNumeric:
			comparison = -1
		case bNumeric:
			comparison = 1
		case a[i] < b[i]:
			comparison = -1
		case a[i] > b[i]:
			comparison = 1
		}
		if comparison != 0 {
			return comparison
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func fetchLatestRelease(ctx context.Context, client *http.Client, latestReleaseURL string) (string, error) {
	data, err := downloadURL(ctx, client, latestReleaseURL)
	if err != nil {
		return "", err
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return "", fmt.Errorf("upgrade: parse latest release metadata: %w", err)
	}
	if strings.TrimSpace(release.TagName) == "" {
		return "", fmt.Errorf("upgrade: latest release metadata missing tag_name")
	}

	v, err := normalizeVersion(release.TagName)
	if err != nil {
		return "", fmt.Errorf("upgrade: invalid latest release tag %q: %w", release.TagName, err)
	}
	return v, nil
}

func downloadURL(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("upgrade: create request %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		if isNetworkError(err) {
			return nil, fmt.Errorf("upgrade: network error while fetching %s: %w", url, err)
		}
		return nil, fmt.Errorf("upgrade: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upgrade: fetch %s: unexpected status %s", url, resp.Status)
	}
	if resp.ContentLength > maxUpgradeDownloadBytes {
		return nil, fmt.Errorf("upgrade: fetch %s: response exceeds %d bytes", url, maxUpgradeDownloadBytes)
	}

	body, err := readAllBounded(resp.Body, maxUpgradeDownloadBytes)
	if err != nil {
		return nil, fmt.Errorf("upgrade: read %s: %w", url, err)
	}
	return body, nil
}

func readAllBounded(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("invalid size limit %d", limit)
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("payload exceeds %d bytes", limit)
	}
	return data, nil
}

func isNetworkError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr)
}

func lookupSHA256(checksums []byte, filename string) (string, error) {
	s := bufio.NewScanner(bytes.NewReader(checksums))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := strings.TrimSpace(fields[0])
		name := strings.TrimPrefix(strings.TrimSpace(fields[len(fields)-1]), "*")
		if name == filename {
			if len(hash) != 64 {
				return "", fmt.Errorf("invalid SHA256 entry for %s", filename)
			}
			return strings.ToLower(hash), nil
		}
	}
	if err := s.Err(); err != nil {
		return "", fmt.Errorf("scan checksums: %w", err)
	}
	return "", fmt.Errorf("checksum for %s not found", filename)
}

func extractRampartBinary(archive []byte) ([]byte, error) {
	return extractRampartBinaryWithLimits(archive, maxUpgradeBinaryBytes, maxUpgradeExpandedBytes)
}

func extractRampartBinaryWithLimits(archive []byte, maxBinaryBytes, maxExpandedBytes int64) ([]byte, error) {
	if maxBinaryBytes < 0 || maxExpandedBytes < 0 {
		return nil, fmt.Errorf("upgrade: invalid archive size limits")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("upgrade: open archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var (
		count         int
		expandedBytes int64
		payload       []byte
		found         bool
	)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("upgrade: read archive: %w", err)
		}
		count++
		if count > maxUpgradeArchiveFiles {
			return nil, fmt.Errorf("upgrade: archive contains more than %d entries", maxUpgradeArchiveFiles)
		}
		if hdr.Size < 0 || hdr.Size > maxExpandedBytes-expandedBytes {
			return nil, fmt.Errorf("upgrade: expanded archive exceeds %d bytes", maxExpandedBytes)
		}
		expandedBytes += hdr.Size
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(hdr.Name) != "rampart" {
			continue
		}
		if found {
			return nil, fmt.Errorf("upgrade: archive contains multiple rampart binaries")
		}
		if hdr.Size > maxBinaryBytes {
			return nil, fmt.Errorf("upgrade: rampart binary exceeds %d bytes", maxBinaryBytes)
		}
		bin, err := readAllBounded(tr, maxBinaryBytes)
		if err != nil {
			return nil, fmt.Errorf("upgrade: read archive payload: %w", err)
		}
		payload = bin
		found = true
	}

	if !found || len(payload) == 0 {
		return nil, fmt.Errorf("upgrade: rampart binary not found in archive (archive had %d entries)", count)
	}
	return payload, nil
}

func inspectServePID(userHomeDir func() (string, error), readFile func(string) ([]byte, error)) (int, bool, error) {
	home, err := userHomeDir()
	if err != nil {
		return 0, false, fmt.Errorf("upgrade: resolve home directory: %w", err)
	}
	pidPath := filepath.Join(home, ".rampart", "serve.pid")
	data, err := readFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("upgrade: read serve pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false, nil
	}
	owned, _, err := isRampartServeProcess(pid)
	if err != nil {
		return 0, false, fmt.Errorf("upgrade: verify serve pid %d: %w", pid, err)
	}
	if !owned {
		return pid, false, nil
	}
	return pid, true, nil
}

func stopServeProcess(pid int) error {
	owned, identity, err := isRampartServeProcess(pid)
	if err != nil {
		return fmt.Errorf("upgrade: verify serve pid %d before signaling: %w", pid, err)
	}
	if !owned {
		if identity == "" {
			identity = "process is no longer running"
		}
		return fmt.Errorf("upgrade: refusing to signal stale serve pid %d (%s)", pid, identity)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if err := terminateRampartServeProcess(proc); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return fmt.Errorf("upgrade: stop rampart serve (pid %d): %w", pid, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		err := proc.Signal(syscall.Signal(0))
		if err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("upgrade: rampart serve (pid %d) did not stop within 5s", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func restartServe(runner commandRunner, binary string, stdout, stderr io.Writer) error {
	cmd := runner(binary, "serve", "--background")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("upgrade: restart rampart serve: %w", err)
	}
	return nil
}

// serveRestartVerifier proves that a restart created a fresh, Rampart-owned
// local runtime and that the runtime loaded the expected binary version.
// Implementations must be bounded by ctx; upgrade keeps its rollback binary
// until this proof succeeds.
type serveRestartVerifier func(ctx context.Context, expectedVersion string, restartedAt time.Time) error

type serveRestartVerifierDeps struct {
	processIdentity func(int) (bool, string, error)
	now             func() time.Time
	timeout         time.Duration
	pollInterval    time.Duration
	requestTimeout  time.Duration
}

func defaultServeRestartVerifierDeps() serveRestartVerifierDeps {
	return serveRestartVerifierDeps{
		processIdentity: isRampartServeProcess,
		now:             time.Now,
		timeout:         10 * time.Second,
		pollInterval:    100 * time.Millisecond,
		requestTimeout:  time.Second,
	}
}

func prepareServeRestartVerifier(
	userHomeDir func() (string, error),
	readFile func(string) ([]byte, error),
) (serveRestartVerifier, error) {
	return prepareServeRestartVerifierWithDeps(userHomeDir, readFile, defaultServeRestartVerifierDeps())
}

func prepareServeRestartVerifierWithDeps(
	userHomeDir func() (string, error),
	readFile func(string) ([]byte, error),
	deps serveRestartVerifierDeps,
) (serveRestartVerifier, error) {
	home, err := userHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	if strings.TrimSpace(home) == "" {
		return nil, fmt.Errorf("resolve home directory: empty path")
	}
	statePath := filepath.Join(home, ".rampart", serveStateFile)
	previousState, err := readFile(statePath)
	previousExists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read existing %s: %w", statePath, err)
	}
	previousState = append([]byte(nil), previousState...)

	return func(ctx context.Context, expectedVersion string, restartedAt time.Time) error {
		verifiedState, err := verifyRestartedServe(
			ctx,
			home,
			readFile,
			expectedVersion,
			previousState,
			previousExists,
			restartedAt,
			deps,
		)
		if err != nil {
			return err
		}
		// Each managed runtime must produce its own fresh state. Advancing the
		// baseline prevents a second launchd service from reusing the first
		// service's successful proof.
		previousState = append(previousState[:0], verifiedState...)
		previousExists = true
		return nil
	}, nil
}

func verifyRestartedServe(
	ctx context.Context,
	home string,
	readFile func(string) ([]byte, error),
	expectedVersion string,
	previousState []byte,
	previousExists bool,
	restartedAt time.Time,
	deps serveRestartVerifierDeps,
) ([]byte, error) {
	if deps.processIdentity == nil {
		return nil, fmt.Errorf("process identity verifier is unavailable")
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.timeout <= 0 {
		deps.timeout = 10 * time.Second
	}
	if deps.pollInterval <= 0 {
		deps.pollInterval = 100 * time.Millisecond
	}
	if deps.requestTimeout <= 0 {
		deps.requestTimeout = time.Second
	}

	verifyCtx, cancel := context.WithTimeout(ctx, deps.timeout)
	defer cancel()

	statePath := filepath.Join(home, ".rampart", serveStateFile)
	var lastErr error
	for {
		stateData, err := readFile(statePath)
		if err != nil {
			lastErr = fmt.Errorf("read fresh %s: %w", statePath, err)
		} else {
			verified, verifyErr := verifyRestartedServeState(
				verifyCtx,
				home,
				readFile,
				stateData,
				expectedVersion,
				previousState,
				previousExists,
				restartedAt,
				deps,
			)
			if verifyErr == nil {
				return verified, nil
			}
			// Preserve the last substantive identity/version/state failure. A
			// request racing the outer deadline should not replace actionable
			// diagnostics with a generic context deadline error.
			if lastErr == nil || (!errors.Is(verifyErr, context.DeadlineExceeded) && !errors.Is(verifyErr, context.Canceled)) {
				lastErr = verifyErr
			}
		}

		timer := time.NewTimer(deps.pollInterval)
		select {
		case <-verifyCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if lastErr == nil {
				lastErr = verifyCtx.Err()
			}
			return nil, fmt.Errorf("no healthy restarted Rampart runtime within %s: %w", deps.timeout, lastErr)
		case <-timer.C:
		}
	}
}

func verifyRestartedServeState(
	ctx context.Context,
	home string,
	readFile func(string) ([]byte, error),
	stateData []byte,
	expectedVersion string,
	previousState []byte,
	previousExists bool,
	restartedAt time.Time,
	deps serveRestartVerifierDeps,
) ([]byte, error) {
	if previousExists && bytes.Equal(stateData, previousState) {
		return nil, fmt.Errorf("serve.state is stale (unchanged since before restart)")
	}

	var state serveState
	if err := json.Unmarshal(stateData, &state); err != nil {
		return nil, fmt.Errorf("decode fresh serve.state: %w", err)
	}
	if state.PID <= 0 {
		return nil, fmt.Errorf("fresh serve.state has invalid pid %d", state.PID)
	}
	started, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(state.Started))
	if err != nil {
		return nil, fmt.Errorf("fresh serve.state has invalid started time %q", state.Started)
	}
	// writeServeState uses RFC3339 second precision. Truncating the restart
	// boundary avoids rejecting a daemon that starts later in the same second.
	if started.Before(restartedAt.UTC().Truncate(time.Second)) {
		return nil, fmt.Errorf("serve.state predates this restart (%s)", started.UTC().Format(time.RFC3339Nano))
	}
	if started.After(deps.now().UTC().Add(5 * time.Second)) {
		return nil, fmt.Errorf("serve.state started time is implausibly in the future (%s)", started.UTC().Format(time.RFC3339Nano))
	}

	serveURL, err := validateLocalServeStateURL(state)
	if err != nil {
		return nil, err
	}
	owned, identity, err := deps.processIdentity(state.PID)
	if err != nil {
		return nil, fmt.Errorf("verify serve.state pid %d: %w", state.PID, err)
	}
	if !owned {
		if strings.TrimSpace(identity) == "" {
			identity = "not a Rampart serve process"
		}
		return nil, fmt.Errorf("serve.state pid %d is not Rampart-owned (%s)", state.PID, identity)
	}

	client, closeClient, err := localServeHealthClient(serveURL, home, readFile, deps.requestTimeout)
	if err != nil {
		return nil, err
	}
	defer closeClient()

	healthURL := *serveURL
	healthURL.Path = "/healthz"
	healthURL.RawPath = ""
	health, err := fetchRampartHealth(ctx, client, healthURL.String())
	if err != nil {
		return nil, fmt.Errorf("probe fresh local Rampart health: %w", err)
	}
	if !validUpgradeHealthService(health.Service, expectedVersion) {
		return nil, fmt.Errorf("unexpected health service identity %q", health.Service)
	}
	if expectedVersion != "" {
		expected, expectedErr := normalizeVersion(expectedVersion)
		actual, actualErr := normalizeVersion(health.Version)
		if expectedErr != nil {
			return nil, fmt.Errorf("invalid expected runtime version %q: %w", expectedVersion, expectedErr)
		}
		if actualErr != nil || actual != expected {
			return nil, fmt.Errorf("restarted runtime version mismatch: expected %s, got %q", expected, health.Version)
		}
	}
	return append([]byte(nil), stateData...), nil
}

// v1.4.0 and older health responses predate the explicit service identity
// field. During rollback, the executable version, fresh state, loopback-only
// endpoint, and Rampart-owned process identity still provide a bounded proof
// that the previous runtime recovered. Newer versions must provide the marker.
func validUpgradeHealthService(service, expectedVersion string) bool {
	if service == "rampart" {
		return true
	}
	if service != "" {
		return false
	}
	cmp, ok := compareReleaseVersions(expectedVersion, "v1.4.0")
	return ok && cmp <= 0
}

func validateLocalServeStateURL(state serveState) (*url.URL, error) {
	rawURL := strings.TrimSpace(state.URL)
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fresh serve.state has invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("refusing serve.state URL %q: scheme must be http or https", rawURL)
	}
	if u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil {
		return nil, fmt.Errorf("refusing serve.state URL %q: absolute URL without credentials is required", rawURL)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("refusing serve.state URL %q: paths, queries, and fragments are not allowed", rawURL)
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if !loopback {
		return nil, fmt.Errorf("refusing non-loopback serve.state URL %q", rawURL)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 || state.Port != port {
		return nil, fmt.Errorf("fresh serve.state URL port does not match state port %d", state.Port)
	}
	return u, nil
}

func localServeHealthClient(
	serveURL *url.URL,
	home string,
	readFile func(string) ([]byte, error),
	requestTimeout time.Duration,
) (*http.Client, func(), error) {
	dialer := &net.Dialer{Timeout: requestTimeout}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   requestTimeout,
		ResponseHeaderTimeout: requestTimeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("verify local health address: %w", err)
			}
			if strings.EqualFold(host, "localhost") {
				// Resolve the generated localhost state without consulting DNS or a
				// proxy, while supporting both Rampart's default IPv4 listener and an
				// explicit --addr ::1 listener.
				var dialErrs []error
				for _, loopbackHost := range []string{"127.0.0.1", "::1"} {
					conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(loopbackHost, port))
					if dialErr == nil {
						return conn, nil
					}
					dialErrs = append(dialErrs, dialErr)
				}
				return nil, fmt.Errorf("connect to localhost loopback: %w", errors.Join(dialErrs...))
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("refusing health connection to non-loopback address %q", address)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
	}
	if serveURL.Scheme == "https" {
		// serve.state intentionally contains no arbitrary trust path. Self-upgrade
		// therefore supports HTTPS only for Rampart's tls-auto certificate. A
		// custom --tls-cert service needs an explicit future fingerprint/source
		// design; falling back to system roots or InsecureSkipVerify here would
		// weaken the proof that the restarted local process is the managed one.
		certPath := filepath.Join(home, ".rampart", "tls", "cert.pem")
		certPEM, err := readFile(certPath)
		if err != nil {
			return nil, func() {}, fmt.Errorf("verify HTTPS runtime: read managed tls-auto certificate %s: %w (custom --tls-cert runtimes require a manual upgrade and restart)", certPath, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certPEM) {
			return nil, func() {}, fmt.Errorf("verify HTTPS runtime: managed tls-auto certificate %s is not valid PEM (custom --tls-cert runtimes require a manual upgrade and restart)", certPath)
		}
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, transport.CloseIdleConnections, nil
}

// detectActiveSystemdService returns an active Rampart-owned systemd user
// service only when its ExecStart resolves to the executable being upgraded.
// This prevents a second installation from being mistaken for the managed
// process whose lifecycle must be refreshed.
func detectActiveSystemdService(runner commandRunner, userHomeDir func() (string, error), executable string) string {
	home, err := userHomeDir()
	if err != nil {
		return ""
	}
	serviceDir := filepath.Join(home, ".config", "systemd", "user")
	for _, svc := range []string{"rampart-proxy.service", "rampart-serve.service"} {
		data, exists, err := readRegularServiceFile(filepath.Join(serviceDir, svc))
		if err != nil || !exists {
			continue
		}
		binary, args, ok := systemdServiceCommand(data)
		if !ok || !isRampartServeArguments(append([]string{binary}, args...)) || !sameExecutable(binary, executable) {
			continue
		}
		cmd := runner("systemctl", "--user", "is-active", "--quiet", svc)
		if err := cmd.Run(); err == nil {
			return svc
		}
	}
	return ""
}

// restartSystemdUserService restarts a named systemd user service so it picks
// up the newly installed binary without manual intervention.
func restartSystemdUserService(runner commandRunner, svc string, out io.Writer) error {
	cmd := runner("systemctl", "--user", "restart", svc)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart %s: %w\n%s", svc, err, strings.TrimSpace(string(output)))
	}
	fmt.Fprintf(out, "✓ restarted %s\n", svc)
	return nil
}

type launchdService struct {
	Label     string
	PlistPath string
}

// detectActiveLaunchdServices returns Rampart LaunchAgents that launchctl
// reports as loaded. This includes the current general/proxy labels and the
// legacy com.rampart.serve label so upgrades restart older installations too.
func detectActiveLaunchdServices(runner commandRunner, userHomeDir func() (string, error), executable string) []launchdService {
	home, err := userHomeDir()
	if err != nil {
		return nil
	}
	candidates := rampartLaunchdServices(home)

	active := make([]launchdService, 0, len(candidates))
	for _, service := range candidates {
		data, exists, err := readRegularServiceFile(service.PlistPath)
		if err != nil || !exists {
			continue
		}
		label, args, err := launchdServiceIdentity(data)
		if err != nil || label != service.Label || !isRampartServeArguments(args) || !sameExecutable(args[0], executable) {
			continue
		}
		if err := runner("launchctl", "list", service.Label).Run(); err == nil {
			active = append(active, service)
		}
	}
	return active
}

func systemdServiceCommand(data []byte) (string, []string, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= len("ExecStart=") && strings.EqualFold(line[:len("ExecStart=")], "ExecStart=") {
			return splitServiceCommand(strings.TrimSpace(line[len("ExecStart="):]))
		}
	}
	return "", nil, false
}

func sameExecutable(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(strings.TrimSpace(left))
	rightAbs, rightErr := filepath.Abs(strings.TrimSpace(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftInfo, leftStatErr := os.Stat(leftAbs)
	rightInfo, rightStatErr := os.Stat(rightAbs)
	if leftStatErr == nil && rightStatErr == nil {
		return os.SameFile(leftInfo, rightInfo)
	}
	return samePath(leftAbs, rightAbs)
}

func rampartLaunchdServices(home string) []launchdService {
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	return []launchdService{
		{
			Label:     plistLabel,
			PlistPath: filepath.Join(agentDir, plistLabel+".plist"),
		},
		{
			Label:     "com.rampart.proxy",
			PlistPath: filepath.Join(agentDir, "com.rampart.proxy.plist"),
		},
		{
			Label:     "com.rampart.serve",
			PlistPath: filepath.Join(agentDir, "com.rampart.serve.plist"),
		},
	}
}

// restartLaunchdUserService unloads the running job and reloads its existing
// plist. This is the same lifecycle used by `rampart serve install --force`
// and ensures launchd starts the newly installed Rampart executable.
func restartLaunchdUserService(runner commandRunner, service launchdService, out io.Writer) error {
	if output, err := runner("launchctl", "unload", service.PlistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("restart %s (unload): %w\n%s", service.Label, err, strings.TrimSpace(string(output)))
	}
	if output, err := runner("launchctl", "load", service.PlistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("restart %s (load): %w\n%s", service.Label, err, strings.TrimSpace(string(output)))
	}
	fmt.Fprintf(out, "✓ restarted %s\n", service.Label)
	return nil
}

func refreshPoliciesWithInstalledBinary(runner commandRunner, binary string, stdout, stderr io.Writer) error {
	cmd := runner(binary, "upgrade", "--no-binary")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run newly installed binary for policy refresh: %w", err)
	}
	return nil
}

func validateSelfUpgradePath(path string, deps upgradeDeps) error {
	info, err := deps.lstat(path)
	if err != nil {
		return fmt.Errorf("upgrade: inspect current executable %s: %w", path, err)
	}

	resolved := path
	if info.Mode()&os.ModeSymlink != 0 {
		if target, resolveErr := deps.evalSymlinks(path); resolveErr == nil {
			resolved = target
		}
		if isHomebrewManagedPath(path) || isHomebrewManagedPath(resolved) {
			return fmt.Errorf("upgrade: %s is managed by Homebrew; run `brew upgrade peg/tap/rampart` instead", path)
		}
		return fmt.Errorf("upgrade: refusing to replace symlinked executable %s; upgrade Rampart through the installer or package manager that owns this link", path)
	}
	if isHomebrewManagedPath(path) || isHomebrewManagedPath(resolved) {
		return fmt.Errorf("upgrade: %s is managed by Homebrew; run `brew upgrade peg/tap/rampart` instead", path)
	}
	return nil
}

func isHomebrewManagedPath(path string) bool {
	path = strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	return strings.HasPrefix(path, "/opt/homebrew/") ||
		strings.Contains(path, "/usr/local/cellar/") ||
		strings.Contains(path, "/homebrew/cellar/") ||
		strings.Contains(path, "/.linuxbrew/cellar/")
}

func validateUpgradeCandidate(ctx context.Context, path, target string) error {
	validationCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(validationCtx, path, "version").CombinedOutput()
	if errors.Is(validationCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("upgrade: candidate version check timed out")
	}
	if err != nil {
		return fmt.Errorf("upgrade: candidate could not execute its version command: %w", err)
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "rampart" {
		return fmt.Errorf("upgrade: candidate identity check failed: expected rampart %s, got %q", strings.TrimPrefix(target, "v"), line)
	}
	reported, err := normalizeVersion(fields[1])
	if err != nil || reported != target {
		return fmt.Errorf("upgrade: candidate version check failed: expected %s, got %q", target, fields[1])
	}
	return nil
}

func stageUpgradeCandidate(path string, payload []byte, deps upgradeDeps) (string, error) {
	dir := filepath.Dir(path)
	tmp, err := deps.createTemp(dir, ".rampart-upgrade-*")
	if err != nil {
		return "", fmt.Errorf("upgrade: create candidate file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = deps.remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("upgrade: write candidate binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("upgrade: sync candidate binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("upgrade: finalize candidate binary: %w", err)
	}
	if err := deps.chmod(tmpPath, 0o755); err != nil {
		return "", fmt.Errorf("upgrade: chmod candidate binary: %w", err)
	}
	cleanup = false
	return tmpPath, nil
}

// activateUpgradeCandidate atomically installs a previously validated staged
// candidate while retaining a same-directory copy of the old executable for
// post-activation validation and rollback.
func activateUpgradeCandidate(path, candidatePath string, deps upgradeDeps) (string, error) {
	info, err := deps.lstat(path)
	if err != nil {
		return "", fmt.Errorf("upgrade: inspect current executable before replacement: %w", err)
	}
	oldBinary, err := deps.readFile(path)
	if err != nil {
		return "", fmt.Errorf("upgrade: read current executable for rollback: %w", err)
	}

	backup, err := deps.createTemp(filepath.Dir(path), ".rampart-upgrade-backup-*")
	if err != nil {
		return "", fmt.Errorf("upgrade: create rollback executable: %w", err)
	}
	backupPath := backup.Name()
	cleanupBackup := true
	defer func() {
		if cleanupBackup {
			_ = deps.remove(backupPath)
		}
	}()
	if _, err := backup.Write(oldBinary); err != nil {
		_ = backup.Close()
		return "", fmt.Errorf("upgrade: write rollback executable: %w", err)
	}
	if err := backup.Sync(); err != nil {
		_ = backup.Close()
		return "", fmt.Errorf("upgrade: sync rollback executable: %w", err)
	}
	if err := backup.Close(); err != nil {
		return "", fmt.Errorf("upgrade: finalize rollback executable: %w", err)
	}
	if err := deps.chmod(backupPath, info.Mode().Perm()); err != nil {
		return "", fmt.Errorf("upgrade: preserve rollback executable mode: %w", err)
	}

	if err := deps.rename(candidatePath, path); err != nil {
		return "", fmt.Errorf("upgrade: replace binary at %s: %w", path, err)
	}
	cleanupBackup = false
	return backupPath, nil
}

func isPermissionError(err error) bool {
	return os.IsPermission(err) || errors.Is(err, os.ErrPermission)
}

// warnAboutPathCopies reports PATH shadowing without rewriting executables.
// A filename and executable bit do not prove that Rampart owns a file: it may
// be package-managed, installed by another user workflow, or be an unrelated
// program with the same name. Upgrade therefore leaves every unproven copy
// untouched and gives the operator an explicit path to inspect.
func warnAboutPathCopies(out io.Writer, installedBinary string, deps upgradeDeps) {
	installedResolved := installedBinary
	if resolved, err := deps.evalSymlinks(installedBinary); err == nil {
		installedResolved = resolved
	}

	seen := map[string]struct{}{}
	for _, dir := range filepath.SplitList(deps.pathEnv()) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}

		candidate := filepath.Join(dir, "rampart")
		if samePath(candidate, installedBinary) || samePath(candidate, installedResolved) {
			continue
		}
		lfi, err := deps.lstat(candidate)
		if err != nil {
			continue
		}
		if !lfi.Mode().IsRegular() && lfi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		candidateResolved := candidate
		if lfi.Mode()&os.ModeSymlink != 0 {
			if resolved, err := deps.evalSymlinks(candidate); err == nil {
				candidateResolved = resolved
				if samePath(resolved, installedResolved) {
					continue
				}
			}
		}
		if isHomebrewManagedPath(candidate) || isHomebrewManagedPath(candidateResolved) {
			fmt.Fprintf(out, "⚠ left package-managed rampart unchanged at %s; use brew upgrade instead\n", candidate)
			continue
		}
		fmt.Fprintf(out, "⚠ another rampart executable may shadow this upgrade at %s; left unchanged because ownership is unproven\n", candidate)
	}
}

func upgradePlatform(goos, goarch string) (string, string, error) {
	var assetOS string
	switch goos {
	case "darwin", "linux":
		assetOS = goos
	default:
		return "", "", fmt.Errorf("upgrade: unsupported OS %q", goos)
	}

	var assetArch string
	switch goarch {
	case "amd64", "arm64":
		assetArch = goarch
	default:
		return "", "", fmt.Errorf("upgrade: unsupported architecture %q", goarch)
	}
	return assetOS, assetArch, nil
}

func confirmUpgrade(in io.Reader, out io.Writer, current, target string) (bool, error) {
	fmt.Fprintf(out, "Upgrade rampart from %s to %s? [Y/n]: ", displayVersion(current), target)
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("upgrade: read confirmation: %w", err)
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	if ans == "" || ans == "y" || ans == "yes" {
		return true, nil
	}
	return false, nil
}

type requireApprovalUsage struct {
	FilePath   string
	PolicyName string
}

func maybeWarnRequireApprovalMigration(out io.Writer, errOut io.Writer, in io.Reader, assumeYes bool, userHomeDir func() (string, error)) error {
	usages, err := findRequireApprovalUsages(userHomeDir)
	if err != nil {
		return err
	}
	if len(usages) == 0 {
		return nil
	}

	fmt.Fprintln(out, "⚠️  Policy migration required:")
	fmt.Fprintln(out, "   Found policies using `action: require_approval`:")
	for _, u := range usages {
		fmt.Fprintf(out, "     - %s (policy: %q)\n", u.FilePath, u.PolicyName)
	}
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "   `require_approval` was removed in v0.9.9 and prevents these policies from loading.")
	fmt.Fprintln(out, "   Replace it with `action: ask`. For service-backed/headless approvals, use:")
	fmt.Fprintln(out, "   action: ask + ask.headless_only: true")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "   See https://docs.rampart.sh/migration/v0.6.6/ for full migration steps.")
	fmt.Fprintln(out, "")

	inFile, inIsFile := in.(*os.File)
	if !assumeYes && inIsFile && isTerminal(inFile) {
		fmt.Fprintln(out, "   Press Enter to continue with upgrade, or Ctrl+C to cancel.")
		reader := bufio.NewReader(in)
		if _, readErr := reader.ReadString('\n'); readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("upgrade: read migration confirmation: %w", readErr)
		}
		return nil
	}

	if errOut != nil {
		fmt.Fprintln(errOut, "   Non-interactive mode detected (or --yes set); continuing automatically.")
	}
	return nil
}

func findRequireApprovalUsages(userHomeDir func() (string, error)) ([]requireApprovalUsage, error) {
	home, err := userHomeDir()
	if err != nil {
		return nil, fmt.Errorf("upgrade: resolve home directory: %w", err)
	}
	policyDir := filepath.Join(home, ".rampart", "policies")
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("upgrade: read policy dir: %w", err)
	}

	var findings []requireApprovalUsage
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(policyDir, e.Name())
		// Use raw YAML struct to avoid engine validation rejecting require_approval.
		// The scanner must still detect it even though the engine now rejects it.
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var raw struct {
			Policies []struct {
				Name  string `yaml:"name"`
				Rules []struct {
					Action string `yaml:"action"`
				} `yaml:"rules"`
			} `yaml:"policies"`
		}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			continue
		}
		for _, p := range raw.Policies {
			for _, r := range p.Rules {
				if strings.EqualFold(strings.TrimSpace(r.Action), "require_approval") {
					findings = append(findings, requireApprovalUsage{
						FilePath:   "~" + filepath.ToSlash(strings.TrimPrefix(path, home)),
						PolicyName: p.Name,
					})
					break
				}
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].FilePath != findings[j].FilePath {
			return findings[i].FilePath < findings[j].FilePath
		}
		return findings[i].PolicyName < findings[j].PolicyName
	})
	return findings, nil
}

// upgradeStandardPolicies refreshes built-in profile files in ~/.rampart/policies/.
// Only files whose names exactly match a known built-in profile are updated.
// Custom user files (custom.yaml, org.yaml, etc.) are never touched.
func upgradeStandardPolicies(out io.Writer, dryRun bool) error {
	return upgradeStandardPoliciesForVersion(out, dryRun, build.Version)
}

func upgradeStandardPoliciesForVersion(out io.Writer, dryRun bool, currentVersion string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("locate home dir: %w", err)
	}
	policyDir := filepath.Join(home, ".rampart", "policies")

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no policy dir — nothing to do
		}
		return fmt.Errorf("read policy dir: %w", err)
	}

	updated := 0
	seenBuiltIn := 0
	preserved := make([]string, 0)
	backedUp := make([]string, 0)
	updatedNames := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !builtInProfiles[e.Name()] {
			continue
		}
		seenBuiltIn++
		info, err := e.Info()
		if err != nil {
			fmt.Fprintf(out, "  ⚠ skip %s: inspect policy path: %v\n", e.Name(), err)
			continue
		}
		if !info.Mode().IsRegular() {
			fmt.Fprintf(out, "  preserved non-regular policy path: %s\n", filepath.Join(policyDir, e.Name()))
			preserved = append(preserved, e.Name())
			continue
		}
		profileName := strings.TrimSuffix(e.Name(), ".yaml")
		content, err := policies.Profile(profileName)
		if err != nil {
			fmt.Fprintf(out, "  ⚠ skip %s: %v\n", e.Name(), err)
			continue
		}
		destPath := filepath.Join(policyDir, e.Name())
		state, err := builtInPolicyStateForVersion(destPath, currentVersion)
		if err != nil {
			fmt.Fprintf(out, "  ⚠ skip %s: %v\n", e.Name(), err)
			continue
		}
		if state.VersionNewer {
			fmt.Fprintf(out, "  preserved newer policy: %s\n", destPath)
			preserved = append(preserved, e.Name())
			continue
		}

		// A matching content hash proves that Rampart wrote the installed payload.
		// Without a hash, only migrate an old version-stamped policy after preserving
		// the original, because legacy stamps cannot distinguish stock from edited files.
		managedByHash := state.HasContentHash && state.ContentHashMatches
		legacyStale := state.HasVersionStamp && !state.HasContentHash && state.VersionOlder
		if state.HasContentHash && !state.ContentHashMatches {
			fmt.Fprintf(out, "  preserved modified policy: %s\n", destPath)
			preserved = append(preserved, e.Name())
			continue
		}
		if !managedByHash && !legacyStale && !state.MatchesCurrent {
			fmt.Fprintf(out, "  preserved modified policy: %s\n", destPath)
			preserved = append(preserved, e.Name())
			continue
		}
		if managedByHash && state.MatchesCurrent && state.VersionCurrent {
			continue
		}

		var backupPath string
		if legacyStale {
			backupPath = legacyPolicyBackupBase(destPath, state.VersionStamp)
		}
		if dryRun {
			if backupPath != "" {
				fmt.Fprintf(out, "  would back up legacy stamped policy: %s -> %s\n", destPath, backupPath)
				backedUp = append(backedUp, e.Name())
			}
			fmt.Fprintf(out, "  would update policy: %s\n", destPath)
			updated++
			updatedNames = append(updatedNames, e.Name())
			continue
		}
		currentInstalled, err := os.ReadFile(destPath)
		if err != nil {
			return fmt.Errorf("re-read %s before replacement: %w", e.Name(), err)
		}
		if !bytes.Equal(currentInstalled, state.Installed) {
			return fmt.Errorf("policy %s changed while upgrade was running; retry to avoid overwriting concurrent edits", e.Name())
		}
		if backupPath != "" {
			backupPath, err = backupLegacyManagedPolicy(destPath, state.VersionStamp, state.Installed)
			if err != nil {
				return fmt.Errorf("back up legacy policy %s: %w", e.Name(), err)
			}
			fmt.Fprintf(out, "✓ legacy policy backup: %s\n", backupPath)
			backedUp = append(backedUp, e.Name())
		}
		if err := writeManagedPolicyAtomically(policyDir, destPath, versionStampedPolicyContentForVersion(content, currentVersion)); err != nil {
			return fmt.Errorf("replace %s: %w", e.Name(), err)
		}
		fmt.Fprintf(out, "✓ policy updated: %s\n", destPath)
		updated++
		updatedNames = append(updatedNames, e.Name())
	}

	if seenBuiltIn == 0 {
		fmt.Fprintf(out, "  (no built-in policy files found in %s — skipped)\n", policyDir)
		return nil
	}
	if updated == 0 && len(preserved) == 0 {
		fmt.Fprintf(out, "  (built-in policy files already current in %s — skipped)\n", policyDir)
		return nil
	}
	sort.Strings(updatedNames)
	sort.Strings(preserved)
	sort.Strings(backedUp)
	if dryRun {
		if len(updatedNames) > 0 {
			fmt.Fprintf(out, "  Would update: %s\n", strings.Join(updatedNames, ", "))
		}
	} else if len(updatedNames) > 0 {
		fmt.Fprintf(out, "Updated: %s\n", strings.Join(updatedNames, ", "))
	}
	if len(preserved) > 0 {
		fmt.Fprintf(out, "Preserved modified: %s\n", strings.Join(preserved, ", "))
	}
	if len(backedUp) > 0 {
		fmt.Fprintf(out, "Backed up legacy: %s\n", strings.Join(backedUp, ", "))
	}
	return nil
}

func writeManagedPolicyAtomically(policyDir, destPath string, content []byte) error {
	tmp, err := os.CreateTemp(policyDir, ".rampart-policy-upgrade-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("write temp policy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp policy: %w", err)
	}
	if err := filetxn.Replace(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func legacyPolicyBackupBase(path, version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		version = "unknown"
	}
	var safe strings.Builder
	for _, r := range version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			safe.WriteRune(r)
		} else {
			safe.WriteByte('_')
		}
	}
	return path + ".rampart-backup-" + safe.String()
}

func backupLegacyManagedPolicy(path, version string, content []byte) (string, error) {
	base := legacyPolicyBackupBase(path, version)
	for attempt := 0; attempt < 1000; attempt++ {
		candidate := base
		if attempt > 0 {
			candidate = fmt.Sprintf("%s.%d", base, attempt)
		}
		if info, err := os.Lstat(candidate); err == nil {
			if info.Mode().IsRegular() {
				existing, readErr := os.ReadFile(candidate)
				if readErr != nil {
					return "", readErr
				}
				if bytes.Equal(existing, content) {
					return candidate, nil
				}
			}
			continue
		} else if !os.IsNotExist(err) {
			return "", err
		}

		backup, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := backup.Write(content); err != nil {
			_ = backup.Close()
			_ = os.Remove(candidate)
			return "", err
		}
		if err := backup.Sync(); err != nil {
			_ = backup.Close()
			_ = os.Remove(candidate)
			return "", err
		}
		if err := backup.Close(); err != nil {
			_ = os.Remove(candidate)
			return "", err
		}
		return candidate, nil
	}
	return "", fmt.Errorf("could not allocate a unique backup path for %s", path)
}
