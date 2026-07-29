// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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
)

func TestValidateUpgradeCandidateRequiresExactIdentityAndVersion(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		target  string
		wantErr bool
	}{
		{name: "exact", output: "rampart 1.4.0", target: "v1.4.0"},
		{name: "wrong version", output: "rampart 1.3.0", target: "v1.4.0", wantErr: true},
		{name: "wrong identity", output: "not-rampart 1.4.0", target: "v1.4.0", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidate")
			script := "#!/bin/sh\nprintf '%s\\n' " + shellQuoteCodexHookArg(tc.output) + "\n"
			if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			err := validateUpgradeCandidate(context.Background(), path, tc.target)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateUpgradeCandidate error = %v, wantErr=%t", err, tc.wantErr)
			}
		})
	}
}

func TestUpgradeRejectsInvalidCandidateBeforeStoppingServe(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := makeArchive(t, "rampart", []byte("not-an-executable"))
	sum := sha256.Sum256(archive)
	archiveName := "rampart_1.1.0_linux_" + runtime.GOARCH + ".tar.gz"
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + archiveName + "\n")
	stopped := false

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
		stopServe: func(int) error {
			stopped = true
			return nil
		},
		detectSystemdService: func(commandRunner, func() (string, error), string) string { return "" },
		downloadURL: func(_ context.Context, _ *http.Client, url string) ([]byte, error) {
			if strings.HasSuffix(url, "checksums.txt") {
				return checksums, nil
			}
			return archive, nil
		},
		pathEnv: func() string { return "" },
	}

	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes", "--no-policy-update"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "candidate could not execute") {
		t.Fatalf("expected candidate execution failure, got %v", err)
	}
	if stopped {
		t.Fatal("serve was stopped before candidate validation")
	}
	got, err := os.ReadFile(exe)
	if err != nil || string(got) != "old-binary" {
		t.Fatalf("installed binary = %q, %v", got, err)
	}
}

func TestUpgradeRestoresPreviousBinaryWhenFinalValidationFails(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := makeArchive(t, "rampart", []byte("new-binary"))
	sum := sha256.Sum256(archive)
	archiveName := "rampart_1.1.0_linux_" + runtime.GOARCH + ".tar.gz"
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + archiveName + "\n")
	validations := 0
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
		stopServe: func(int) error { return nil },
		restartServe: func(_ commandRunner, binary string, _, _ io.Writer) error {
			restarted++
			got, err := os.ReadFile(binary)
			if err != nil {
				return err
			}
			if string(got) != "old-binary" {
				return errors.New("restart did not observe restored binary")
			}
			return nil
		},
		detectSystemdService: func(commandRunner, func() (string, error), string) string { return "" },
		prepareServeVerifier: acceptServeRestartVerification,
		validateCandidate: func(context.Context, string, string) error {
			validations++
			if validations == 2 {
				return errors.New("simulated final-path validation failure")
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
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes", "--no-policy-update"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "restored the previous Rampart executable") {
		t.Fatalf("expected final validation rollback, got %v", err)
	}
	got, readErr := os.ReadFile(exe)
	if readErr != nil || string(got) != "old-binary" {
		t.Fatalf("restored binary = %q, %v", got, readErr)
	}
	if restarted != 1 {
		t.Fatalf("restart count = %d, want 1", restarted)
	}
}
