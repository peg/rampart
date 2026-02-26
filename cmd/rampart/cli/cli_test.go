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
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/policies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestVersionCommand(t *testing.T) {
	stdout, _, err := runCLI(t, "version")
	require.NoError(t, err)
	assert.Contains(t, stdout, "rampart "+build.Version)
}

func TestVersionFlag(t *testing.T) {
	stdout, _, err := runCLI(t, "--version")
	require.NoError(t, err)
	assert.Contains(t, stdout, "rampart "+build.Version)
}

func TestInitCreatesFile(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	configPath := filepath.Join(dir, "rampart.yaml")

	_, _, err := runCLI(t, "--config", configPath, "init")
	require.NoError(t, err)

	data, readErr := os.ReadFile(configPath)
	require.NoError(t, readErr)

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(data, &parsed))
	assert.Equal(t, "1", parsed["version"])
}

func TestInitRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	configPath := filepath.Join(dir, "rampart.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("existing: true\n"), 0o644))

	_, _, err := runCLI(t, "--config", configPath, "init")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestInitForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	configPath := filepath.Join(dir, "rampart.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("existing: true\n"), 0o644))

	_, _, err := runCLI(t, "--config", configPath, "init", "--force")
	require.NoError(t, err)

	data, readErr := os.ReadFile(configPath)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "version: \"1\"")
}

func TestInitProfileYolo(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	configPath := filepath.Join(dir, "rampart.yaml")

	_, _, err := runCLI(t, "--config", configPath, "init", "--profile", "yolo")
	require.NoError(t, err)

	data, readErr := os.ReadFile(configPath)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "name: log-everything")
}

func TestPolicyCheckValid(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "rampart.yaml")
	content, err := policies.FS.ReadFile("standard.yaml")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, content, 0o644))

	stdout, _, err := runCLI(t, "--config", configPath, "policy", "check")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Policy valid")
}

func TestPolicyCheckInvalid(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "rampart.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("version: \"1\"\npolicies: [\n"), 0o644))

	_, _, err := runCLI(t, "--config", configPath, "policy", "check")
	require.Error(t, err)
}

func TestPolicyExplain(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "rampart.yaml")
	content, err := policies.FS.ReadFile("standard.yaml")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, content, 0o644))

	stdout, _, err := runCLI(t, "--config", configPath, "policy", "explain", "rm -rf /")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Final decision: DENY")
	assert.Contains(t, stdout, "Destructive command blocked")
}

func TestServeGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	configPath := filepath.Join(dir, "rampart.yaml")
	content, err := policies.FS.ReadFile("standard.yaml")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, content, 0o644))

	signalCh := make(chan os.Signal, 1)
	deps := &serveDeps{
		notifyContext: func(parent context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			go func() {
				select {
				case <-ctx.Done():
				case <-signalCh:
					cancel()
				}
			}()
			return ctx, cancel
		},
	}

	cmd := newServeCmd(&rootOptions{configPath: configPath}, deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"--port", "0"})

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	time.Sleep(100 * time.Millisecond)
	signalCh <- os.Interrupt

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("serve command did not shut down in time")
	}

	auditDir := filepath.Join(".", "audit")
	_, statErr := os.Stat(auditDir)
	if statErr == nil {
		t.Cleanup(func() { _ = os.RemoveAll(auditDir) })
	}
}

func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd(context.Background(), stdout, stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()

	return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err
}

func TestServeReadsAndPersistsToken(t *testing.T) {
	// Regression test: rampart serve was generating a new random token on every
	// start, ignoring ~/.rampart/token and never writing to it. The foreground
	// serve path should read a persisted token and persist it after start.
	dir := t.TempDir()
	testSetHome(t, dir)

	configPath := filepath.Join(dir, "rampart.yaml")
	content, err := policies.FS.ReadFile("standard.yaml")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, content, 0o644))

	// Pre-write a known token to ~/.rampart/token.
	rampartDir := filepath.Join(dir, ".rampart")
	require.NoError(t, os.MkdirAll(rampartDir, 0o700))
	knownToken := "deadbeef00112233deadbeef00112233"
	tokenPath := filepath.Join(rampartDir, "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte(knownToken), 0o600))

	// Find a free port so proxy starts (port>0 gate in serve.go).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	signalCh := make(chan os.Signal, 1)
	deps := &serveDeps{
		notifyContext: func(parent context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			go func() {
				select {
				case <-ctx.Done():
				case <-signalCh:
					cancel()
				}
			}()
			return ctx, cancel
		},
	}

	var stderr bytes.Buffer
	cmd := newServeCmd(&rootOptions{configPath: configPath}, deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"--port", fmt.Sprintf("%d", port)})

	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Execute() }()

	time.Sleep(300 * time.Millisecond)
	signalCh <- os.Interrupt

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("serve command did not shut down in time")
	}

	logs := stderr.String()

	// Serve must log the persisted token, not a fresh random one.
	if !strings.Contains(logs, knownToken) {
		t.Fatalf("serve did not use persisted token from ~/.rampart/token.\nlogs:\n%s", logs)
	}

	// Token file must still contain the same value after serve writes it back.
	written, err := os.ReadFile(tokenPath)
	require.NoError(t, err)
	if strings.TrimSpace(string(written)) != knownToken {
		t.Fatalf("token file changed after serve; want %q got %q", knownToken, strings.TrimSpace(string(written)))
	}

	_ = os.RemoveAll(filepath.Join(".", "audit"))
}
