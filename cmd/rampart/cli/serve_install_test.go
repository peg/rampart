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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
		"ExecStart=/usr/local/bin/rampart serve --port 18275",
		"Environment=RAMPART_TOKEN=tok456",
		"Restart=on-failure",
		"WantedBy=default.target",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unit missing %q\n%s", want, out)
		}
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
	t.Setenv("HOME", t.TempDir()) // prevent reading ~/.rampart/token from real home
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
	home := t.TempDir()
	t.Setenv("HOME", home)

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

func TestPersistToken_FixesPermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

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
	t.Setenv("HOME", home)
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

func TestServeUninstallCmd_Exists(t *testing.T) {
	var calls []string
	cmd := newServeUninstallCmd(mockRunner(&calls))
	// Just verify it builds.
	if cmd.Use != "uninstall" {
		t.Error("unexpected Use")
	}
}
