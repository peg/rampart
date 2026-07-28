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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	writeFile             func(string, []byte, os.FileMode) error
	chmod                 func(string, os.FileMode) error
	rename                func(string, string) error
	createTemp            func(string, string) (*os.File, error)
	remove                func(string) error
	commandRunner         commandRunner
	currentVersion        func(context.Context, commandRunner, func() (string, error)) (string, error)
	latestRelease         func(context.Context, *http.Client, string) (string, error)
	downloadURL           func(context.Context, *http.Client, string) ([]byte, error)
	inspectServePID       func(func() (string, error), func(string) ([]byte, error)) (int, bool, error)
	stopServe             func(int) error
	restartServe          func(commandRunner, string, io.Writer, io.Writer) error
	detectSystemdService  func(commandRunner) string
	restartSystemdService func(commandRunner, string, io.Writer) error
	detectLaunchdServices func(commandRunner, func() (string, error)) []launchdService
	restartLaunchdService func(commandRunner, launchdService, io.Writer) error
	sleep                 func(time.Duration)
	pathEnv               func() string
	stat                  func(string) (os.FileInfo, error)
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
		writeFile:             os.WriteFile,
		chmod:                 os.Chmod,
		rename:                os.Rename,
		createTemp:            os.CreateTemp,
		remove:                os.Remove,
		commandRunner:         exec.Command,
		currentVersion:        currentVersion,
		latestRelease:         fetchLatestRelease,
		downloadURL:           downloadURL,
		inspectServePID:       inspectServePID,
		stopServe:             stopServeProcess,
		restartServe:          restartServe,
		detectSystemdService:  detectActiveSystemdService,
		restartSystemdService: restartSystemdUserService,
		detectLaunchdServices: detectActiveLaunchdServices,
		restartLaunchdService: restartLaunchdUserService,
		sleep:                 time.Sleep,
		pathEnv: func() string {
			return os.Getenv("PATH")
		},
		stat:            os.Stat,
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
		if deps.writeFile != nil {
			resolved.writeFile = deps.writeFile
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
		if deps.sleep != nil {
			resolved.sleep = deps.sleep
		}
		if deps.pathEnv != nil {
			resolved.pathEnv = deps.pathEnv
		}
		if deps.stat != nil {
			resolved.stat = deps.stat
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
		RunE: func(cmd *cobra.Command, args []string) error {
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

			servePID, serveRunning, err := resolved.inspectServePID(resolved.userHomeDir, resolved.readFile)
			if err != nil {
				return err
			}

			// A platform service takes priority over PID-file management. Service
			// processes do not write ~/.rampart/serve.pid, and must be restarted
			// explicitly so they load the newly replaced executable.
			activeSvc := ""
			var activeLaunchd []launchdService
			switch resolved.goos {
			case "linux":
				activeSvc = resolved.detectSystemdService(resolved.commandRunner)
			case "darwin":
				activeLaunchd = resolved.detectLaunchdServices(resolved.commandRunner, resolved.userHomeDir)
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
				fmt.Fprintf(cmd.OutOrStdout(), "- would scan PATH and auto-fix stale rampart copies (symlink to new binary)\n")
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

			if pidServeRunning {
				if err := resolved.stopServe(servePID); err != nil {
					return err
				}
			}

			installSpin := newCliSpinner(cmd.OutOrStdout(), "Installing")
			if err := replaceExecutableAtomically(exePath, newBinary, resolved); err != nil {
				installSpin.Fail("Installation failed")
				if isPermissionError(err) {
					return fmt.Errorf("upgrade: %w\n💡 Try this: sudo rampart upgrade", err)
				}
				return err
			}
			installSpin.Stop(fmt.Sprintf("Installed %s", target))

			fixStalePathCopies(cmd.OutOrStdout(), exePath, resolved)
			if !skipPolicyUpdate {
				if err := resolved.refreshPolicies(resolved.commandRunner, exePath, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
					// Non-fatal: the verified binary is installed, and the user can retry
					// the policy-only migration with that binary.
					fmt.Fprintf(cmd.ErrOrStderr(), "⚠ policy update failed (binary upgrade succeeded): %v\n", err)
					fmt.Fprintf(cmd.ErrOrStderr(), "  run '%s upgrade --no-binary' to retry\n", exePath)
				}
			}

			serveRestarted := false
			if activeSvc != "" {
				if err := resolved.restartSystemdService(resolved.commandRunner, activeSvc, cmd.OutOrStdout()); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "⚠ %v\n  run manually: systemctl --user restart %s\n", err, activeSvc)
				} else {
					serveRestarted = true
				}
			} else if len(activeLaunchd) > 0 {
				serveRestarted = true
				for _, service := range activeLaunchd {
					if err := resolved.restartLaunchdService(resolved.commandRunner, service, cmd.OutOrStdout()); err != nil {
						serveRestarted = false
						fmt.Fprintf(cmd.ErrOrStderr(), "⚠ %v\n  reload manually: launchctl unload %q && launchctl load %q\n", err, service.PlistPath, service.PlistPath)
					}
				}
			} else if pidServeRunning {
				if err := resolved.restartServe(resolved.commandRunner, exePath, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
					return err
				}
				serveRestarted = true
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ rampart upgraded to %s\n", target)
			if !serveRestarted && serveRunning {
				fmt.Fprintln(cmd.OutOrStdout(), "Reminder: restart rampart serve to ensure it uses the new binary.")
			}

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
	proc, err := os.FindProcess(pid)
	if err != nil {
		return 0, false, nil
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return pid, false, nil
	}
	return pid, true, nil
}

func stopServeProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
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

// detectActiveSystemdService returns the name of an active rampart systemd user
// service (rampart-proxy.service or rampart-serve.service), or "" if none are active.
// systemd user services are the standard install path for openclaw and claude-code setups.
func detectActiveSystemdService(runner commandRunner) string {
	for _, svc := range []string{"rampart-proxy.service", "rampart-serve.service"} {
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
func detectActiveLaunchdServices(runner commandRunner, userHomeDir func() (string, error)) []launchdService {
	home, err := userHomeDir()
	if err != nil {
		return nil
	}
	candidates := rampartLaunchdServices(home)

	active := make([]launchdService, 0, len(candidates))
	for _, service := range candidates {
		if _, err := os.Stat(service.PlistPath); err != nil {
			continue
		}
		if err := runner("launchctl", "list", service.Label).Run(); err == nil {
			active = append(active, service)
		}
	}
	return active
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

func replaceExecutableAtomically(path string, payload []byte, deps upgradeDeps) error {
	dir := filepath.Dir(path)
	tmp, err := deps.createTemp(dir, ".rampart-upgrade-*")
	if err != nil {
		return fmt.Errorf("upgrade: create temporary file: %w", err)
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
		return fmt.Errorf("upgrade: write temporary binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("upgrade: sync temporary binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("upgrade: finalize temporary binary: %w", err)
	}
	if err := deps.chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("upgrade: chmod temporary binary: %w", err)
	}

	if err := deps.rename(tmpPath, path); err != nil {
		return fmt.Errorf("upgrade: replace binary at %s: %w", path, err)
	}
	cleanup = false
	return nil
}

func isPermissionError(err error) bool {
	return os.IsPermission(err) || errors.Is(err, os.ErrPermission)
}

func fixStalePathCopies(out io.Writer, installedBinary string, deps upgradeDeps) {
	installedInfo, err := deps.stat(installedBinary)
	if err != nil {
		return
	}
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
		cfi, err := deps.stat(candidate)
		if err != nil {
			continue
		}
		if os.SameFile(installedInfo, cfi) {
			continue
		}
		// Auto-fix: replace stale copy with a symlink to the installed binary.
		// This prevents PATH shadowing after upgrades (e.g. ~/go/bin/rampart
		// installed via `go install` hiding the newer /usr/local/bin/rampart).
		tmp := candidate + ".old"
		if err := os.Rename(candidate, tmp); err == nil {
			if err := os.Symlink(installedBinary, candidate); err == nil {
				_ = os.Remove(tmp)
				fmt.Fprintf(out, "✓ fixed stale rampart at %s → symlinked to %s\n", candidate, installedBinary)
			} else {
				// Symlink failed — restore original and warn
				_ = os.Rename(tmp, candidate)
				fmt.Fprintf(out, "⚠ stale rampart at %s — could not symlink (%v), remove manually\n", candidate, err)
			}
		} else {
			fmt.Fprintf(out, "⚠ stale rampart at %s — could not replace (%v), remove manually\n", candidate, err)
		}
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
	fmt.Fprintln(out, "   See https://rampart.sh/docs/migration/v0.6.6 for full migration steps.")
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
