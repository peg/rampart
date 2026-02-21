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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

const (
	upgradeLatestReleaseURL = "https://api.github.com/repos/peg/rampart/releases/latest"
	upgradeReleaseBaseURL   = "https://github.com/peg/rampart/releases/download"
)

type upgradeDeps struct {
	httpClient      *http.Client
	executablePath  func() (string, error)
	userHomeDir     func() (string, error)
	readFile        func(string) ([]byte, error)
	writeFile       func(string, []byte, os.FileMode) error
	chmod           func(string, os.FileMode) error
	rename          func(string, string) error
	createTemp      func(string, string) (*os.File, error)
	remove          func(string) error
	commandRunner   commandRunner
	currentVersion  func(context.Context, commandRunner, func() (string, error)) (string, error)
	latestRelease   func(context.Context, *http.Client, string) (string, error)
	downloadURL     func(context.Context, *http.Client, string) ([]byte, error)
	inspectServePID func(func() (string, error), func(string) ([]byte, error)) (int, bool, error)
	stopServe       func(int) error
	restartServe    func(commandRunner, string, io.Writer, io.Writer) error
	sleep           func(time.Duration)
	pathEnv         func() string
	stat            func(string) (os.FileInfo, error)
	lstat           func(string) (os.FileInfo, error)
	evalSymlinks    func(string) (string, error)
}

func defaultUpgradeDeps() upgradeDeps {
	return upgradeDeps{
		httpClient:      &http.Client{Timeout: 20 * time.Second},
		executablePath:  os.Executable,
		userHomeDir:     os.UserHomeDir,
		readFile:        os.ReadFile,
		writeFile:       os.WriteFile,
		chmod:           os.Chmod,
		rename:          os.Rename,
		createTemp:      os.CreateTemp,
		remove:          os.Remove,
		commandRunner:   exec.Command,
		currentVersion:  currentVersion,
		latestRelease:   fetchLatestRelease,
		downloadURL:     downloadURL,
		inspectServePID: inspectServePID,
		stopServe:       stopServeProcess,
		restartServe:    restartServe,
		sleep:           time.Sleep,
		pathEnv: func() string {
			return os.Getenv("PATH")
		},
		stat:         os.Stat,
		lstat:        os.Lstat,
		evalSymlinks: filepath.EvalSymlinks,
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
	}

	var assumeYes bool
	var dryRun bool
	var skipPolicyUpdate bool

	cmd := &cobra.Command{
		Use:   "upgrade [version]",
		Short: "Upgrade rampart to the latest or specified release",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
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

			if current != "" && compareSemver(current, target) >= 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Already on latest (%s)\n", target)
				return nil
			}

			assetOS, assetArch, err := upgradePlatform(runtime.GOOS, runtime.GOARCH)
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

			servePID, serveRunning, err := resolved.inspectServePID(resolved.userHomeDir, resolved.readFile)
			if err != nil {
				return err
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "Dry run:\n")
				fmt.Fprintf(cmd.OutOrStdout(), "- would upgrade from %s to %s\n", displayVersion(current), target)
				fmt.Fprintf(cmd.OutOrStdout(), "- would download %s\n", archiveURL)
				fmt.Fprintf(cmd.OutOrStdout(), "- would verify SHA256 from %s\n", checksumsURL)
				if serveRunning {
					fmt.Fprintf(cmd.OutOrStdout(), "- would stop rampart serve (pid %d)\n", servePID)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "- would atomically replace %s\n", exePath)
				fmt.Fprintf(cmd.OutOrStdout(), "- would scan PATH and auto-fix stale rampart copies (symlink to new binary)\n")
				if serveRunning {
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

			archiveBytes, err := resolved.downloadURL(ctx, resolved.httpClient, archiveURL)
			if err != nil {
				return err
			}
			checksumsBytes, err := resolved.downloadURL(ctx, resolved.httpClient, checksumsURL)
			if err != nil {
				return err
			}

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

			if serveRunning {
				if err := resolved.stopServe(servePID); err != nil {
					return err
				}
			}

			if err := replaceExecutableAtomically(exePath, newBinary, resolved); err != nil {
				if isPermissionError(err) {
					return fmt.Errorf("upgrade: %w\ntry: sudo rampart upgrade", err)
				}
				return err
			}

			fixStalePathCopies(cmd.OutOrStdout(), exePath, resolved)

			if serveRunning {
				if err := resolved.restartServe(resolved.commandRunner, exePath, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
					return err
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ rampart upgraded to %s\n", target)

			// Refresh standard.yaml so security fixes reach existing users.
			// Only updates the named profile files (standard.yaml, paranoid.yaml, yolo.yaml).
			// Custom user policies (custom.yaml, anything else) are never touched.
			if !skipPolicyUpdate {
				if err := upgradeStandardPolicies(cmd.OutOrStdout(), dryRun); err != nil {
					// Non-fatal — binary is already upgraded.
					fmt.Fprintf(cmd.ErrOrStderr(), "⚠ policy update failed (binary upgrade succeeded): %v\n", err)
					fmt.Fprintf(cmd.ErrOrStderr(), "  run 'rampart init --profile standard --force' to update manually\n")
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would happen without changing anything")
	cmd.Flags().BoolVar(&skipPolicyUpdate, "no-policy-update", false, "Skip refreshing built-in policy profiles after upgrade")

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
	return v, nil
}

func compareSemver(a, b string) int {
	ap, aok := parseSemver(a)
	bp, bok := parseSemver(b)
	if !aok || !bok {
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
	for i := 0; i < 3; i++ {
		if ap[i] > bp[i] {
			return 1
		}
		if ap[i] < bp[i] {
			return -1
		}
	}
	return 0
}

func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	base := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if base == "" {
		return out, false
	}
	base = strings.SplitN(base, "+", 2)[0]
	base = strings.SplitN(base, "-", 2)[0]
	parts := strings.Split(base, ".")
	if len(parts) < 3 {
		return out, false
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("upgrade: read %s: %w", url, err)
	}
	return body, nil
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
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("upgrade: open archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var (
		count   int
		payload []byte
	)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("upgrade: read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		count++
		if filepath.Base(hdr.Name) != "rampart" {
			continue
		}
		bin, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("upgrade: read archive payload: %w", err)
		}
		payload = bin
	}

	if len(payload) == 0 {
		return nil, fmt.Errorf("upgrade: rampart binary not found in archive")
	}
	if count > 1 {
		// Keep strict behavior expected by release layout.
		return nil, fmt.Errorf("upgrade: archive contains %d files; expected a single binary", count)
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
		if lfi.Mode()&os.ModeSymlink != 0 {
			if resolved, err := deps.evalSymlinks(candidate); err == nil && samePath(resolved, installedResolved) {
				continue
			}
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

// upgradeStandardPolicies refreshes built-in profile files in ~/.rampart/policies/.
// Only files whose names exactly match a known built-in profile are updated.
// Custom user files (custom.yaml, org.yaml, etc.) are never touched.
func upgradeStandardPolicies(out io.Writer, dryRun bool) error {
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

	// Built-in profile names — only these are ever auto-updated.
	builtIn := map[string]bool{
		"standard.yaml": true,
		"paranoid.yaml": true,
		"yolo.yaml":     true,
	}

	updated := 0
	for _, e := range entries {
		if e.IsDir() || !builtIn[e.Name()] {
			continue
		}
		profileName := strings.TrimSuffix(e.Name(), ".yaml")
		content, err := policies.Profile(profileName)
		if err != nil {
			fmt.Fprintf(out, "  ⚠ skip %s: %v\n", e.Name(), err)
			continue
		}
		destPath := filepath.Join(policyDir, e.Name())
		if dryRun {
			fmt.Fprintf(out, "  would update policy: %s\n", destPath)
			updated++
			continue
		}
		// Atomic write: temp file + rename.
		tmp, err := os.CreateTemp(policyDir, ".rampart-policy-upgrade-*.yaml.tmp")
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmp.Name()
		if _, err := tmp.Write(content); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("write temp policy: %w", err)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("close temp policy: %w", err)
		}
		if err := os.Rename(tmpPath, destPath); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("replace %s: %w", e.Name(), err)
		}
		fmt.Fprintf(out, "✓ policy updated: %s\n", destPath)
		updated++
	}

	if updated == 0 {
		// No standard policy files found — user may be using a custom config path.
		fmt.Fprintf(out, "  (no built-in policy files found in %s — skipped)\n", policyDir)
	}
	return nil
}
