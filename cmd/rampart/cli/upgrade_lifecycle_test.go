// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/proxy"
)

func TestUpgradeRestartsBackgroundServeWhenInstallFails(t *testing.T) {
	skipOnWindows(t, "binary self-upgrade intentionally uses the Windows installer")
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	archive := makeArchive(t, "rampart", []byte("new-binary"))
	sum := sha256.Sum256(archive)
	archiveName := "rampart_1.1.0_linux_" + runtime.GOARCH + ".tar.gz"
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + archiveName + "\n")
	stopped := 0
	restarted := 0
	deps := &upgradeDeps{
		goos:   "linux",
		goarch: runtime.GOARCH,
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.0.0", nil
		},
		executablePath: func() (string, error) { return exe, nil },
		inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
			return 4242, true, nil
		},
		stopServe: func(pid int) error {
			if pid != 4242 {
				t.Fatalf("stop pid=%d", pid)
			}
			stopped++
			return nil
		},
		prepareServeRestart: preparedRestartForTest(func(_ commandRunner, binary string, _, _ io.Writer) error {
			restarted++
			got, err := os.ReadFile(binary)
			if err != nil {
				return err
			}
			if string(got) != "old-binary" {
				t.Fatalf("rollback restart observed %q, want old binary", got)
			}
			return nil
		}),
		detectSystemdService: func(commandRunner, func() (string, error), string) string { return "" },
		validateCandidate:    acceptUpgradeCandidate,
		prepareServeVerifier: acceptServeRestartVerification,
		downloadURL: func(_ context.Context, _ *http.Client, url string) ([]byte, error) {
			if strings.HasSuffix(url, "checksums.txt") {
				return checksums, nil
			}
			return archive, nil
		},
		rename:  func(_, _ string) error { return errors.New("simulated replace failure") },
		pathEnv: func() string { return "" },
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes", "--no-policy-update"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "simulated replace failure") {
		t.Fatalf("expected install failure, got %v", err)
	}
	if stopped != 1 || restarted != 1 {
		t.Fatalf("stopped=%d restarted=%d, want one stop and rollback restart", stopped, restarted)
	}
	if !strings.Contains(out.String(), "restored previously running rampart serve") {
		t.Fatalf("missing rollback confirmation: %q", out.String())
	}
}

func TestUpgradeCleansOnlyCapturedFailedCandidateBeforeRollback(t *testing.T) {
	skipOnWindows(t, "binary self-upgrade intentionally uses the Windows installer")
	for _, scenario := range []string{"owned", "state replaced", "launch changed", "unowned replacement", "pid reused", "birth changes during check", "capture unavailable", "stop fails"} {
		t.Run(scenario, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".rampart")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			exe := filepath.Join(home, "rampart")
			if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
				t.Fatal(err)
			}
			archive := makeArchive(t, "rampart", []byte("new-binary"))
			sum := sha256.Sum256(archive)
			checksums := []byte(hex.EncodeToString(sum[:]) + "  rampart_2.0.1_linux_" + runtime.GOARCH + ".tar.gz\n")
			const oldPID, candidatePID = 4242, 4243
			candidate := serveState{
				RuntimeIdentity: proxy.RuntimeIdentity{InstanceID: "candidate-instance-1", Version: "2.0.1", Commit: "candidate", Mode: "monitor"},
				URL:             "http://localhost:19090", Port: 19090, PID: candidatePID, Executable: exe,
				Launch: &serveLaunchSettings{WorkingDir: home, ConfigPath: "custom.yaml", AuditDir: "custom-audit", Mode: "monitor", Addr: "127.0.0.1", Port: 19090},
			}
			writeState := func() {
				t.Helper()
				data, err := json.Marshal(candidate)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, serveStateFile), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			birth, owned, candidateAlive := "process-birth-1", true, false
			restarts, proofs, oldStops, candidateStops := 0, 0, 0, 0
			activationErr := errors.New("synthetic activation rejection")
			deps := &upgradeDeps{
				goos: "linux", goarch: runtime.GOARCH,
				userHomeDir:    func() (string, error) { return home, nil },
				executablePath: func() (string, error) { return exe, nil },
				currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
					return "v2.0.0", nil
				},
				inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
					return oldPID, true, nil
				},
				stopServe: func(pid int) error {
					if pid != oldPID {
						t.Fatalf("initial stop pid = %d", pid)
					}
					oldStops++
					return nil
				},
				captureServeCandidate: func(homeDir func() (string, error), binary string, previousPID int, restartedAt time.Time) (func() error, error) {
					if scenario == "capture unavailable" {
						owned = false
					}
					return captureServeCandidateCleanupWithDeps(homeDir, binary, previousPID, restartedAt, serveCandidateCleanupDeps{
						processStart: func(int) (string, error) { return birth, nil },
						processIdentity: func(int) (bool, string, error) {
							if proofs == 1 && scenario == "birth changes during check" {
								birth = "process-birth-2"
							}
							return owned, "", nil
						},
						stop: func(pid int) error {
							candidateStops++
							got, err := os.ReadFile(exe)
							if err != nil || string(got) != "new-binary" || pid != candidatePID || !candidateAlive {
								t.Fatalf("cleanup must stop live captured candidate before binary rollback: pid=%d binary=%q err=%v", pid, got, err)
							}
							if scenario == "stop fails" {
								return errors.New("synthetic stop failure")
							}
							candidateAlive = false
							return nil
						},
					})
				},
				prepareServeRestart: preparedRestartForTest(func(_ commandRunner, binary string, _, _ io.Writer) error {
					restarts++
					got, err := os.ReadFile(binary)
					if err != nil {
						return err
					}
					if restarts == 1 {
						if string(got) != "new-binary" {
							t.Fatalf("candidate binary = %q", got)
						}
						candidateAlive = true
						candidate.Started = time.Now().UTC().Format(time.RFC3339Nano)
						writeState()
					} else if candidateAlive || string(got) != "old-binary" {
						t.Fatalf("recovery must follow candidate cleanup and binary rollback: alive=%v binary=%q", candidateAlive, got)
					}
					return nil
				}),
				prepareServeVerifier: func(func() (string, error), func(string) ([]byte, error)) (serveRestartVerifier, error) {
					return func(_ context.Context, expected string, _ time.Time) error {
						proofs++
						if proofs > 1 {
							if expected != "v2.0.0" || candidateAlive {
								t.Fatalf("recovery proof version=%q candidateAlive=%v", expected, candidateAlive)
							}
							return nil
						}
						if expected != "v2.0.1" || !candidateAlive {
							t.Fatalf("candidate proof version=%q candidateAlive=%v", expected, candidateAlive)
						}
						switch scenario {
						case "state replaced":
							candidate.InstanceID = "replacement-instance"
							writeState()
						case "launch changed":
							candidate.Launch.ConfigPath = "replacement.yaml"
							writeState()
						case "unowned replacement":
							owned = false
						case "pid reused":
							birth = "process-birth-2"
						}
						return activationErr
					}, nil
				},
				detectSystemdService: func(commandRunner, func() (string, error), string) string { return "" },
				validateCandidate:    acceptUpgradeCandidate,
				downloadURL: func(_ context.Context, _ *http.Client, url string) ([]byte, error) {
					if strings.HasSuffix(url, "checksums.txt") {
						return checksums, nil
					}
					return archive, nil
				},
				pathEnv: func() string { return "" },
			}
			var out bytes.Buffer
			cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
			cmd.SetOut(&out)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"v2.0.1", "--yes", "--no-policy-update"})
			err := cmd.Execute()
			if !errors.Is(err, activationErr) || oldStops != 1 {
				t.Fatalf("must preserve original activation failure after one old stop: err=%v stops=%d", err, oldStops)
			}
			got, readErr := os.ReadFile(exe)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if scenario == "owned" {
				if candidateStops != 1 || restarts != 2 || proofs != 2 || string(got) != "old-binary" || !strings.Contains(err.Error(), "restored the previous Rampart executable and runtime") {
					t.Fatalf("verified recovery missing: stops=%d restarts=%d proofs=%d binary=%q err=%v", candidateStops, restarts, proofs, got, err)
				}
			} else {
				wantStops := 0
				if scenario == "stop fails" {
					wantStops = 1
				}
				if candidateStops != wantStops || !candidateAlive || restarts != 1 || proofs != 1 || string(got) != "new-binary" || !strings.Contains(err.Error(), "recovery incomplete") {
					t.Fatalf("unsafe or misleading recovery: stops=%d alive=%v restarts=%d proofs=%d binary=%q err=%v", candidateStops, candidateAlive, restarts, proofs, got, err)
				}
				backups, globErr := filepath.Glob(filepath.Join(home, ".rampart-upgrade-backup-*"))
				if globErr != nil || len(backups) != 1 {
					t.Fatalf("previous executable backup not retained: %v, %v", backups, globErr)
				}
				if backup, err := os.ReadFile(backups[0]); err != nil || string(backup) != "old-binary" {
					t.Fatalf("retained backup=%q err=%v", backup, err)
				}
			}
			if strings.Contains(out.String(), "rampart binary upgraded") {
				t.Fatalf("failed activation claimed upgrade success: %q", out.String())
			}
		})
	}
}

func TestUpgradeRollsBackWhenSystemdRuntimeCannotProveCandidateHealth(t *testing.T) {
	skipOnWindows(t, "binary self-upgrade intentionally uses the Windows installer")
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	archive := makeArchive(t, "rampart", []byte("new-binary"))
	sum := sha256.Sum256(archive)
	archiveName := "rampart_1.1.0_linux_" + runtime.GOARCH + ".tar.gz"
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + archiveName + "\n")
	restarts := 0
	proofs := 0
	policyRefreshes := 0
	deps := &upgradeDeps{
		goos:   "linux",
		goarch: runtime.GOARCH,
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.0.0", nil
		},
		executablePath:       func() (string, error) { return exe, nil },
		detectSystemdService: func(commandRunner, func() (string, error), string) string { return "rampart-serve.service" },
		validateCandidate:    acceptUpgradeCandidate,
		prepareServeVerifier: func(func() (string, error), func(string) ([]byte, error)) (serveRestartVerifier, error) {
			return func(_ context.Context, expectedVersion string, _ time.Time) error {
				proofs++
				if proofs == 1 {
					if expectedVersion != "v1.1.0" {
						t.Fatalf("candidate proof version = %q", expectedVersion)
					}
					return errors.New("simulated candidate health/version mismatch")
				}
				if expectedVersion != "v1.0.0" {
					t.Fatalf("rollback proof version = %q", expectedVersion)
				}
				return nil
			}, nil
		},
		restartSystemdService: func(commandRunner, string, io.Writer) error {
			restarts++
			got, err := os.ReadFile(exe)
			if err != nil {
				return err
			}
			if restarts == 1 {
				if string(got) != "new-binary" {
					t.Fatalf("candidate restart observed %q, want new binary", got)
				}
				return nil
			}
			if string(got) != "old-binary" {
				t.Fatalf("recovery restart observed %q, want old binary", got)
			}
			return nil
		},
		downloadURL: func(_ context.Context, _ *http.Client, url string) ([]byte, error) {
			if strings.HasSuffix(url, "checksums.txt") {
				return checksums, nil
			}
			return archive, nil
		},
		pathEnv: func() string { return "" },
		refreshPolicies: func(commandRunner, string, io.Writer, io.Writer) error {
			policyRefreshes++
			return nil
		},
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "restored the previous Rampart executable and runtime") {
		t.Fatalf("restart failure must make upgrade incomplete, got %v", err)
	}
	if got, readErr := os.ReadFile(exe); readErr != nil || string(got) != "old-binary" {
		t.Fatalf("rollback binary = %q, %v", got, readErr)
	}
	if restarts != 2 {
		t.Fatalf("restart attempts = %d, want candidate plus rollback recovery", restarts)
	}
	if proofs != 2 {
		t.Fatalf("runtime health proofs = %d, want candidate plus rollback recovery", proofs)
	}
	if policyRefreshes != 0 {
		t.Fatalf("policy refreshes = %d, want none after failed runtime activation", policyRefreshes)
	}
	if !strings.Contains(out.String(), "restored the previous Rampart executable and runtime") {
		t.Fatalf("missing rollback confirmation: %q", out.String())
	}
	if strings.Contains(out.String(), "rampart binary upgraded") {
		t.Fatalf("failed activation claimed upgrade success: %q", out.String())
	}
}

func TestUpgradeRollsBackWhenBackgroundServeCannotLoadCandidate(t *testing.T) {
	skipOnWindows(t, "binary self-upgrade intentionally uses the Windows installer")
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	archive := makeArchive(t, "rampart", []byte("new-binary"))
	sum := sha256.Sum256(archive)
	archiveName := "rampart_1.1.0_linux_" + runtime.GOARCH + ".tar.gz"
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + archiveName + "\n")
	restarts := 0
	policyRefreshes := 0
	deps := &upgradeDeps{
		goos:   "linux",
		goarch: runtime.GOARCH,
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.0.0", nil
		},
		executablePath: func() (string, error) { return exe, nil },
		inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
			return 4242, true, nil
		},
		stopServe: func(pid int) error {
			if pid != 4242 {
				t.Fatalf("stop pid=%d", pid)
			}
			return nil
		},
		prepareServeRestart: preparedRestartForTest(func(_ commandRunner, binary string, _, _ io.Writer) error {
			restarts++
			got, err := os.ReadFile(binary)
			if err != nil {
				return err
			}
			if restarts == 1 {
				if string(got) != "new-binary" {
					t.Fatalf("candidate restart observed %q, want new binary", got)
				}
				return errors.New("simulated background restart failure")
			}
			if string(got) != "old-binary" {
				t.Fatalf("recovery restart observed %q, want old binary", got)
			}
			return nil
		}),
		detectSystemdService: func(commandRunner, func() (string, error), string) string { return "" },
		validateCandidate:    acceptUpgradeCandidate,
		prepareServeVerifier: acceptServeRestartVerification,
		downloadURL: func(_ context.Context, _ *http.Client, url string) ([]byte, error) {
			if strings.HasSuffix(url, "checksums.txt") {
				return checksums, nil
			}
			return archive, nil
		},
		pathEnv: func() string { return "" },
		refreshPolicies: func(commandRunner, string, io.Writer, io.Writer) error {
			policyRefreshes++
			return nil
		},
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "restored the previous Rampart executable and runtime") {
		t.Fatalf("restart failure must roll back the upgrade, got %v", err)
	}
	if got, readErr := os.ReadFile(exe); readErr != nil || string(got) != "old-binary" {
		t.Fatalf("rollback binary = %q, %v", got, readErr)
	}
	if restarts != 2 {
		t.Fatalf("restart attempts = %d, want candidate plus rollback recovery", restarts)
	}
	if policyRefreshes != 0 {
		t.Fatalf("policy refreshes = %d, want none after failed runtime activation", policyRefreshes)
	}
	if strings.Contains(out.String(), "rampart binary upgraded") {
		t.Fatalf("failed activation claimed upgrade success: %q", out.String())
	}
}
