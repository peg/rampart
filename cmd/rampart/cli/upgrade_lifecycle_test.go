// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
		restartServe: func(_ commandRunner, binary string, _, _ io.Writer) error {
			restarted++
			got, err := os.ReadFile(binary)
			if err != nil {
				return err
			}
			if string(got) != "old-binary" {
				t.Fatalf("rollback restart observed %q, want old binary", got)
			}
			return nil
		},
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
		restartServe: func(_ commandRunner, binary string, _, _ io.Writer) error {
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
		},
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
