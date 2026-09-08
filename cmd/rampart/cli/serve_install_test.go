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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestGeneratePlist(t *testing.T) {
	cfg := serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Args:    []string{"--port", "18275", "--mode", "monitor"},
		Token:   "abc123",
		LogPath: "/home/test/.rampart/serve.log",
	}
	out, err := generatePlist(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"sh.rampart.serve",
		"/usr/local/bin/rampart",
		"<string>serve</string>",
		"<string>--port</string>",
		"<string>18275</string>",
		"<string>--mode</string>",
		"<string>monitor</string>",
		"<string>abc123</string>",
		"RunAtLoad",
		"KeepAlive",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plist missing %q\n%s", want, out)
		}
	}
}

func TestGenerateSystemdUnit(t *testing.T) {
	cfg := serviceConfig{
		Binary: "/usr/local/bin/rampart",
		Args:   []string{"--port", "18275"},
		Token:  "tok456",
	}
	out, err := generateSystemdUnit(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ExecStart="/usr/local/bin/rampart" serve "--port" "18275"`,
		`Environment="RAMPART_TOKEN=tok456"`,
		"Restart=on-failure",
		"WantedBy=default.target",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unit missing %q\n%s", want, out)
		}
	}
}

func TestGenerateSystemdUnitQuotesPathsAndDoesNotHTMLEscape(t *testing.T) {
	cfg := serviceConfig{
		Binary: `/home/A & B/rampart`,
		Args:   []string{"--config", "/home/A & B/policy\nname.yaml", `100%\done"`},
		Token:  `token&100%"\value`,
	}
	out, err := generateSystemdUnit(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ExecStart="/home/A & B/rampart" serve "--config" "/home/A & B/policy\nname.yaml" "100%%\\done\""`,
		`Environment="RAMPART_TOKEN=token&100%%\"\\value"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unit missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "&amp;") || strings.Contains(out, "&#") {
		t.Fatalf("systemd unit was HTML-escaped:\n%s", out)
	}
}

func TestResolveToken_FromFlag(t *testing.T) {
	tok, gen, err := resolveServiceToken("myflag")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "myflag" || gen {
		t.Errorf("expected myflag/false, got %s/%v", tok, gen)
	}
}

func TestResolveToken_FromEnv(t *testing.T) {
	t.Setenv("RAMPART_TOKEN", "envtok")
	tok, gen, err := resolveServiceToken("")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "envtok" || gen {
		t.Errorf("expected envtok/false, got %s/%v", tok, gen)
	}
}

func TestResolveToken_Generated(t *testing.T) {
	t.Setenv("RAMPART_TOKEN", "")
	testSetHome(t, t.TempDir()) // prevent reading ~/.rampart/token from real home
	tok, gen, err := resolveServiceToken("")
	if err != nil {
		t.Fatal(err)
	}
	if !gen {
		t.Error("expected generated=true")
	}
	if len(tok) != 32 {
		t.Errorf("expected 32-char hex token, got %d chars: %s", len(tok), tok)
	}
}

func TestPersistAndReadToken(t *testing.T) {
	skipOnWindows(t, "Unix file permissions")
	home := t.TempDir()
	testSetHome(t, home)

	// File doesn't exist yet — readPersistedToken should return an error.
	if _, err := readPersistedToken(); err == nil {
		t.Fatal("expected error reading token from empty home, got nil")
	}

	// Persist a token.
	const want = "abc123deadbeef"
	if err := persistToken(want); err != nil {
		t.Fatalf("persistToken: %v", err)
	}

	// File must be 0o600.
	p, _ := tokenFilePath()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token file permissions: got %04o, want 0600", info.Mode().Perm())
	}

	// Round-trip: read back the token.
	got, err := readPersistedToken()
	if err != nil {
		t.Fatalf("readPersistedToken: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPersistTokenUnchangedDoesNotReplaceFile(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	const token = "stable-token"
	if err := persistToken(token); err != nil {
		t.Fatal(err)
	}
	path, err := tokenFilePath()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistToken(token); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("unchanged token was replaced")
	}
}

func TestReadPersistedTokenRefusesSymlink(t *testing.T) {
	skipOnWindows(t, "Unix symlink semantics")
	home := t.TempDir()
	testSetHome(t, home)
	path, err := tokenFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "external-token")
	if err := os.WriteFile(target, []byte("do-not-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readPersistedToken(); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("readPersistedToken error = %v, want symlink refusal", err)
	}
}

func TestPrintServiceInstallSuccessRedactsTokenForNonInteractiveWriter(t *testing.T) {
	const secret = "service-secret-token"
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&out)

	printSuccess(cmd, secret, true, 9090, "/tmp/rampart.plist")
	if strings.Contains(out.String(), secret) {
		t.Fatalf("non-interactive service output leaked token: %q", out.String())
	}
	if !strings.Contains(out.String(), "saved to ~/.rampart/token") {
		t.Fatalf("non-interactive output omitted token location: %q", out.String())
	}
}

func TestStableServiceBinaryPrefersVerifiedPathSymlink(t *testing.T) {
	skipOnWindows(t, "serve install is not supported on Windows")
	dir := t.TempDir()
	versioned := filepath.Join(dir, "Cellar", "rampart", "1.4.0", "bin", "rampart")
	stable := filepath.Join(dir, "bin", "rampart")
	if err := os.MkdirAll(filepath.Dir(versioned), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(stable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(versioned, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(versioned, stable); err != nil {
		t.Fatal(err)
	}

	originalLookPath := execLookPath
	execLookPath = func(string) (string, error) { return stable, nil }
	t.Cleanup(func() { execLookPath = originalLookPath })

	if got := stableServiceBinary(versioned); got != stable {
		t.Fatalf("stableServiceBinary() = %q, want verified symlink %q", got, stable)
	}
}

func TestStableServiceBinaryRejectsDifferentPathBinary(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current", "rampart")
	candidate := filepath.Join(dir, "bin", "rampart")
	for _, path := range []string{current, candidate} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("same bytes are not the same installed file"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	originalLookPath := execLookPath
	execLookPath = func(string) (string, error) { return candidate, nil }
	t.Cleanup(func() { execLookPath = originalLookPath })

	if got := stableServiceBinary(current); got != current {
		t.Fatalf("stableServiceBinary() = %q, want current executable %q", got, current)
	}
}

func TestPersistToken_FixesPermissions(t *testing.T) {
	skipOnWindows(t, "Unix file permissions")
	home := t.TempDir()
	testSetHome(t, home)

	// Create the token file manually with wrong permissions.
	p, _ := tokenFilePath()
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte("oldtoken"), 0o644)

	// persistToken must fix permissions, not just overwrite content.
	if err := persistToken("newtoken"); err != nil {
		t.Fatalf("persistToken: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions not fixed: got %04o, want 0600", info.Mode().Perm())
	}
}

func TestResolveToken_FromFile(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("RAMPART_TOKEN", "")

	// Write a token to the file.
	const want = "filetokendeadbeef"
	if err := persistToken(want); err != nil {
		t.Fatalf("persistToken: %v", err)
	}

	tok, gen, err := resolveServiceToken("")
	if err != nil {
		t.Fatal(err)
	}
	if gen {
		t.Error("expected generated=false when token comes from file")
	}
	if tok != want {
		t.Errorf("got %q, want %q", tok, want)
	}
}

func TestBuildServiceArgs(t *testing.T) {
	args := buildServiceArgs(8080, "/etc/rampart.yaml", "/etc/policies", "/var/audit", "monitor", "10m")
	want := []string{"--port", "8080", "--config", "/etc/rampart.yaml", "--config-dir", "/etc/policies", "--audit-dir", "/var/audit", "--mode", "monitor", "--approval-timeout", "10m"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", args, want)
	}
}

func TestBuildServiceArgs_Defaults(t *testing.T) {
	args := buildServiceArgs(0, "rampart.yaml", "", "", "enforce", "5m")
	if len(args) != 0 {
		t.Errorf("expected no args for defaults, got %v", args)
	}
}

// mockRunner returns a runner that records calls but doesn't execute anything.
func mockRunner(calls *[]string) commandRunner {
	return func(name string, args ...string) *exec.Cmd {
		*calls = append(*calls, name+" "+strings.Join(args, " "))
		return exec.Command("true")
	}
}

func managedSystemdFixture(t *testing.T, token string) string {
	t.Helper()
	content, err := generateSystemdUnit(serviceConfig{
		Binary: "/usr/local/bin/rampart",
		Token:  token,
	})
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func managedLaunchdFixture(t *testing.T, token string) string {
	t.Helper()
	content, err := generatePlist(serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Token:   token,
		LogPath: filepath.Join(t.TempDir(), "serve.log"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestInstallLinuxRotatesTokenBetweenStopAndStart(t *testing.T) {
	skipOnWindows(t, "Unix service runner")
	home := t.TempDir()
	testSetHome(t, home)
	if err := persistToken("old-token"); err != nil {
		t.Fatal(err)
	}
	unitPath, err := systemdUnitPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(managedSystemdFixture(t, "old-token")), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	runner := tokenObservingRunner(t, &calls)
	cfg := serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Token:   "new-token",
		LogPath: filepath.Join(home, ".rampart", "serve.log"),
	}
	cmd := &cobra.Command{}
	if err := installLinux(cmd, cfg, true, false, defaultServePort, runner); err != nil {
		t.Fatalf("installLinux: %v", err)
	}

	want := []string{
		"systemctl --user is-active rampart-serve.service|old-token",
		"systemctl --user is-enabled rampart-serve.service|old-token",
		"systemctl --user stop rampart-serve.service|old-token",
		"systemctl --user daemon-reload|old-token",
		"systemctl --user enable rampart-serve.service|new-token",
		"systemctl --user start rampart-serve.service|new-token",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("service/token ordering:\n got: %q\nwant: %q", calls, want)
	}
}

func TestInstallLinuxRestoresDefinitionTokenAndServiceOnStartFailure(t *testing.T) {
	skipOnWindows(t, "Unix service runner")
	home := t.TempDir()
	testSetHome(t, home)
	if err := persistToken("old-token"); err != nil {
		t.Fatal(err)
	}
	unitPath, err := systemdUnitPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	oldUnit := managedSystemdFixture(t, "old-token")
	if err := os.WriteFile(unitPath, []byte(oldUnit), 0o600); err != nil {
		t.Fatal(err)
	}

	startCalls := 0
	runner := func(name string, args ...string) *exec.Cmd {
		if name == "systemctl" && len(args) >= 2 && args[1] == "is-active" {
			return exec.Command("sh", "-c", "printf active")
		}
		if name == "systemctl" && len(args) >= 2 && args[1] == "is-enabled" {
			return exec.Command("sh", "-c", "printf enabled")
		}
		if name == "systemctl" && len(args) >= 2 && args[1] == "start" {
			startCalls++
			if startCalls == 1 {
				return exec.Command("sh", "-c", "exit 1")
			}
		}
		return exec.Command("true")
	}
	cfg := serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Token:   "new-token",
		LogPath: filepath.Join(home, ".rampart", "serve.log"),
	}
	err = installLinux(&cobra.Command{}, cfg, true, false, defaultServePort, runner)
	if err == nil || !strings.Contains(err.Error(), "systemctl start") {
		t.Fatalf("installLinux error = %v, want start failure", err)
	}
	gotUnit, readErr := os.ReadFile(unitPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(gotUnit) != oldUnit {
		t.Fatalf("unit after rollback = %q, want %q", gotUnit, oldUnit)
	}
	gotToken, readErr := readPersistedToken()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if gotToken != "old-token" {
		t.Fatalf("token after rollback = %q, want old-token", gotToken)
	}
	if startCalls != 2 {
		t.Fatalf("start calls = %d, want failed replacement plus restored service", startCalls)
	}
}

func TestInstallLinuxRollbackPreservesInactiveDisabledState(t *testing.T) {
	skipOnWindows(t, "Unix service runner")
	home := t.TempDir()
	testSetHome(t, home)
	if err := persistToken("old-token"); err != nil {
		t.Fatal(err)
	}
	unitPath, err := systemdUnitPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(managedSystemdFixture(t, "old-token")), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	startCalls := 0
	runner := func(name string, args ...string) *exec.Cmd {
		verb := ""
		if name == "systemctl" && len(args) >= 2 {
			verb = args[1]
			calls = append(calls, verb)
		}
		switch verb {
		case "is-active":
			return exec.Command("sh", "-c", "printf inactive; exit 3")
		case "is-enabled":
			return exec.Command("sh", "-c", "printf disabled; exit 1")
		case "start":
			startCalls++
			if startCalls == 1 {
				return exec.Command("sh", "-c", "exit 1")
			}
		}
		return exec.Command("true")
	}
	err = installLinux(&cobra.Command{}, serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Token:   "new-token",
		LogPath: filepath.Join(home, ".rampart", "serve.log"),
	}, true, false, defaultServePort, runner)
	if err == nil || !strings.Contains(err.Error(), "systemctl start") {
		t.Fatalf("installLinux error = %v, want start failure", err)
	}
	if strings.Count(strings.Join(calls, ","), "stop") != 1 {
		t.Fatalf("calls = %v, want only rollback stop for inactive prior service", calls)
	}
	wantSuffix := []string{"daemon-reload", "disable", "stop"}
	if len(calls) < len(wantSuffix) || strings.Join(calls[len(calls)-len(wantSuffix):], ",") != strings.Join(wantSuffix, ",") {
		t.Fatalf("rollback calls = %v, want suffix %v", calls, wantSuffix)
	}
}

func TestInstallLinuxRefusesSymlinkedServiceDefinition(t *testing.T) {
	skipOnWindows(t, "Unix symlink semantics")
	home := t.TempDir()
	testSetHome(t, home)
	unitPath, err := systemdUnitPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "shared-unit")
	if err := os.WriteFile(target, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, unitPath); err != nil {
		t.Fatal(err)
	}
	err = installLinux(&cobra.Command{}, serviceConfig{
		Binary: "/usr/local/bin/rampart", Token: "new-token",
	}, true, false, defaultServePort, mockRunner(&[]string{}))
	if err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("installLinux error = %v, want symlink refusal", err)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "keep me\n" {
		t.Fatalf("symlink target changed: data=%q err=%v", data, readErr)
	}
}

func TestInstallDarwinRotatesTokenBetweenUnloadAndLoad(t *testing.T) {
	skipOnWindows(t, "Unix service runner")
	home := t.TempDir()
	testSetHome(t, home)
	if err := persistToken("old-token"); err != nil {
		t.Fatal(err)
	}
	path, err := plistPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(managedLaunchdFixture(t, "old-token")), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	runner := tokenObservingRunner(t, &calls)
	cfg := serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Token:   "new-token",
		LogPath: filepath.Join(home, ".rampart", "serve.log"),
	}
	cmd := &cobra.Command{}
	if err := installDarwin(cmd, cfg, true, false, defaultServePort, runner); err != nil {
		t.Fatalf("installDarwin: %v", err)
	}

	want := []string{
		"launchctl list " + plistLabel + "|old-token",
		"launchctl unload " + path + "|old-token",
		"launchctl load " + path + "|new-token",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("service/token ordering:\n got: %q\nwant: %q", calls, want)
	}
}

func TestInstallDarwinReportsLogDirectoryFailure(t *testing.T) {
	skipOnWindows(t, "Unix service runner")
	home := t.TempDir()
	testSetHome(t, home)
	blocker := filepath.Join(home, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	cfg := serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Token:   "token",
		LogPath: filepath.Join(blocker, "serve.log"),
	}
	cmd := &cobra.Command{}
	err := installDarwin(cmd, cfg, true, false, defaultServePort, mockRunner(&calls))
	if err == nil || !strings.Contains(err.Error(), "create service log directory") {
		t.Fatalf("installDarwin error = %v, want log-directory error", err)
	}
	if len(calls) != 0 {
		t.Fatalf("service runner called after filesystem failure: %v", calls)
	}
}

func TestInstallDarwinAllowsExistingUnloadedService(t *testing.T) {
	skipOnWindows(t, "Unix service runner")
	home := t.TempDir()
	testSetHome(t, home)
	if err := persistToken("old-token"); err != nil {
		t.Fatal(err)
	}
	path, err := plistPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(managedLaunchdFixture(t, "old-token")), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	runner := func(name string, args ...string) *exec.Cmd {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "list" {
			return exec.Command("sh", "-c", "exit 113")
		}
		return exec.Command("true")
	}
	cfg := serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Token:   "new-token",
		LogPath: filepath.Join(home, ".rampart", "serve.log"),
	}
	if err := installDarwin(&cobra.Command{}, cfg, true, false, defaultServePort, runner); err != nil {
		t.Fatalf("installDarwin: %v", err)
	}
	want := []string{
		"launchctl list " + plistLabel,
		"launchctl load " + path,
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n got: %q\nwant: %q", calls, want)
	}
	token, err := readPersistedToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "new-token" {
		t.Fatalf("persisted token = %q, want new-token", token)
	}
}

func TestInstallDarwinRefusesTokenRotationOnUnknownListFailure(t *testing.T) {
	skipOnWindows(t, "Unix service runner")
	home := t.TempDir()
	testSetHome(t, home)
	if err := persistToken("old-token"); err != nil {
		t.Fatal(err)
	}
	path, err := plistPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(managedLaunchdFixture(t, "old-token")), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	runner := func(name string, args ...string) *exec.Cmd {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return exec.Command("false")
	}
	cfg := serviceConfig{
		Binary:  "/usr/local/bin/rampart",
		Token:   "new-token",
		LogPath: filepath.Join(home, ".rampart", "serve.log"),
	}
	err = installDarwin(&cobra.Command{}, cfg, true, false, defaultServePort, runner)
	if err == nil || !strings.Contains(err.Error(), "launchctl list") {
		t.Fatalf("installDarwin error = %v, want launchctl list failure", err)
	}
	if len(calls) != 1 || calls[0] != "launchctl list "+plistLabel {
		t.Fatalf("calls after ambiguous list failure = %q", calls)
	}
	token, err := readPersistedToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "old-token" {
		t.Fatalf("persisted token = %q, want old-token", token)
	}
}

func TestServeLifecycleRefusesUnownedDefinition(t *testing.T) {
	skipOnWindows(t, "Unix service file semantics")
	cases := []struct {
		name      string
		path      func() (string, error)
		content   string
		wantError string
		install   func(*cobra.Command, serviceConfig, bool, bool, int, commandRunner) error
		uninstall func(*cobra.Command, commandRunner) error
	}{
		{
			name:      "systemd",
			path:      systemdUnitPath,
			content:   "[Service]\nExecStart=/usr/bin/unrelated serve\n",
			wantError: "unrecognized systemd service",
			install:   installLinux,
			uninstall: uninstallLinux,
		},
		{
			name: "launchd",
			path: plistPath,
			content: `<?xml version="1.0"?><plist><dict>
<key>Label</key><string>sh.rampart.serve</string>
<key>ProgramArguments</key><array><string>/usr/bin/unrelated</string><string>serve</string></array>
			</dict></plist>`,
			wantError: "unrecognized LaunchAgent",
			install:   installDarwin,
			uninstall: uninstallDarwin,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			testSetHome(t, home)
			path, err := tc.path()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			beforeInfo, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}

			var calls []string
			runner := mockRunner(&calls)
			cfg := serviceConfig{Binary: "/usr/local/bin/rampart", Token: "replacement-token", LogPath: filepath.Join(home, ".rampart", "serve.log")}
			if err := tc.install(&cobra.Command{}, cfg, true, false, defaultServePort, runner); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("install error = %v, want ownership refusal", err)
			}
			if err := tc.uninstall(&cobra.Command{}, runner); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("uninstall error = %v, want ownership refusal", err)
			}
			if len(calls) != 0 {
				t.Fatalf("unowned service triggered lifecycle commands: %v", calls)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != tc.content {
				t.Fatalf("unowned service changed: data=%q err=%v", data, err)
			}
			afterInfo, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() {
				t.Fatalf("unowned service mode changed: before=%v after=%v", beforeInfo.Mode().Perm(), afterInfo.Mode().Perm())
			}
		})
	}
}

func TestInstallRepairsManagedServiceAndTokenPermissionsBeforeEarlyReturn(t *testing.T) {
	skipOnWindows(t, "Unix service file permissions")
	cases := []struct {
		name    string
		path    func() (string, error)
		content func(*testing.T, string) string
		install func(*cobra.Command, serviceConfig, bool, bool, int, commandRunner) error
	}{
		{name: "systemd", path: systemdUnitPath, content: managedSystemdFixture, install: installLinux},
		{name: "launchd", path: plistPath, content: managedLaunchdFixture, install: installDarwin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			testSetHome(t, home)
			servicePath, err := tc.path()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(servicePath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(servicePath, []byte(tc.content(t, "old-token")), 0o644); err != nil {
				t.Fatal(err)
			}
			tokenPath, err := tokenFilePath()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tokenPath, []byte("old-token"), 0o644); err != nil {
				t.Fatal(err)
			}

			var calls []string
			cfg := serviceConfig{Binary: "/usr/local/bin/rampart", Token: "replacement-token", LogPath: filepath.Join(home, ".rampart", "serve.log")}
			if err := tc.install(&cobra.Command{}, cfg, false, false, defaultServePort, mockRunner(&calls)); err != nil {
				t.Fatal(err)
			}
			if len(calls) != 0 {
				t.Fatalf("existing managed service triggered lifecycle commands: %v", calls)
			}
			for _, path := range []string{servicePath, tokenPath} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("%s permissions = %04o, want 0600", path, info.Mode().Perm())
				}
			}
		})
	}
}

func TestInstallExistingManagedServiceRejectsSymlinkedToken(t *testing.T) {
	skipOnWindows(t, "Unix symlink semantics")
	home := t.TempDir()
	testSetHome(t, home)
	servicePath, err := systemdUnitPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(servicePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(servicePath, []byte(managedSystemdFixture(t, "old-token")), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath, err := tokenFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "shared-token")
	if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, tokenPath); err != nil {
		t.Fatal(err)
	}

	err = installLinux(&cobra.Command{}, serviceConfig{}, false, false, defaultServePort, mockRunner(&[]string{}))
	if err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("installLinux error = %v, want token symlink refusal", err)
	}
	if data, readErr := os.ReadFile(target); readErr != nil || string(data) != "keep me" {
		t.Fatalf("token target changed: data=%q err=%v", data, readErr)
	}
}

func TestRequireUnchangedServiceFileRejectsCreatedOrModifiedDefinition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rampart-serve.service")
	if err := os.WriteFile(path, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireUnchangedServiceFile(path, false, nil); err == nil {
		t.Fatal("service created after an absent snapshot was accepted")
	}
	if err := requireUnchangedServiceFile(path, true, []byte("original")); err == nil {
		t.Fatal("service modified after snapshot was accepted")
	}
	if err := requireUnchangedServiceFile(path, true, []byte("created")); err != nil {
		t.Fatalf("unchanged service rejected: %v", err)
	}
}

func tokenObservingRunner(t *testing.T, calls *[]string) commandRunner {
	t.Helper()
	return func(name string, args ...string) *exec.Cmd {
		token, err := readPersistedToken()
		if err != nil {
			t.Fatalf("read token while invoking %s: %v", name, err)
		}
		*calls = append(*calls, name+" "+strings.Join(args, " ")+"|"+token)
		if name == "systemctl" && len(args) >= 2 && args[1] == "is-active" {
			return exec.Command("sh", "-c", "printf active")
		}
		if name == "systemctl" && len(args) >= 2 && args[1] == "is-enabled" {
			return exec.Command("sh", "-c", "printf enabled")
		}
		return exec.Command("true")
	}
}

func TestServeInstallCmd_Force(t *testing.T) {
	// Just ensure the flag exists and parses.
	opts := &rootOptions{configPath: "rampart.yaml"}
	var calls []string
	cmd := newServeInstallCmd(opts, mockRunner(&calls))
	cmd.SetArgs([]string{"--force", "--token", "test123"})
	// Don't actually run — just check parse.
	if err := cmd.ParseFlags([]string{"--force", "--token", "test123"}); err != nil {
		t.Fatal(err)
	}
}

func TestServeInstallCmdReconcilesLegacyLaunchdLogRouting(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("launchd command generation")
	}
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("RAMPART_TOKEN", "")
	const token = "synthetic-existing-service-token"
	if err := persistToken(token); err != nil {
		t.Fatal(err)
	}
	path, err := plistPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(managedLaunchdFixture(t, token)), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(home, "operator-config.json")
	if err := os.WriteFile(unrelated, []byte("{\"keep\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath(), []byte("existing diagnostics\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	cmd := newServeInstallCmd(&rootOptions{configPath: "rampart.yaml"}, mockRunner(&calls))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--force", "--port", "18275", "--mode", "monitor", "--approval-timeout", "90s"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	label, args, err := launchdServiceIdentity(data)
	if err != nil || label != plistLabel {
		t.Fatalf("service identity changed: %q (%v)", label, err)
	}
	want := []string{"serve", "--port", "18275", "--audit-dir", filepath.Join(home, ".rampart", "audit"), "--mode", "monitor", "--approval-timeout", "90s", "--log-file", logPath()}
	if len(args) < 1 || !slices.Equal(args[1:], want) {
		t.Fatalf("service arguments = %q, want executable followed by %q", args, want)
	}
	for name, want := range map[string]string{unrelated: "{\"keep\":true}\n", logPath(): "existing diagnostics\n"} {
		data, err := os.ReadFile(name)
		if err != nil || string(data) != want {
			t.Fatalf("reinstall changed unrelated state: %q (%v)", data, err)
		}
	}
	if got, err := readPersistedToken(); err != nil || got != token {
		t.Fatal("reinstall changed the existing service token")
	}
	if !slices.Equal(calls, []string{"launchctl list " + plistLabel, "launchctl unload " + path, "launchctl load " + path}) {
		t.Fatalf("unexpected service transitions: %q", calls)
	}
}

func TestServeUninstallCmd_Exists(t *testing.T) {
	var calls []string
	cmd := newServeUninstallCmd(mockRunner(&calls))
	// Just verify it builds.
	if cmd.Use != "uninstall" {
		t.Error("unexpected Use")
	}
}
