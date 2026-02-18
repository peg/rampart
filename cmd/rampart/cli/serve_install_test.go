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
	"os/exec"
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
