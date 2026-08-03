// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
	"github.com/peg/rampart/policies"
)

func TestProtectKeepsExperimentalGeminiExplicit(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	if err := os.MkdirAll(filepath.Join(home, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"protect", "gemini", "--no-restart"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "remains experimental") || !strings.Contains(err.Error(), "rampart setup gemini") {
		t.Fatalf("error = %v, want experimental setup guidance", err)
	}
}

func TestInstallManagedGuardPolicy(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	path, err := installManagedGuardPolicy()
	if err != nil {
		t.Fatalf("installManagedGuardPolicy: %v", err)
	}
	if want := filepath.Join(home, ".rampart", "policies", "guard.yaml"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := policies.Profile("guard")
	if err != nil {
		t.Fatal(err)
	}
	_, _, installedContent := parseManagedPolicyHeaders(installed)
	if string(installedContent) != string(embedded) {
		t.Fatal("installed Guard policy does not match the embedded profile")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil {
			t.Fatal(err)
		} else if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestAtomicWritePrivateFileReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := atomicWritePrivateFile(path, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if err := atomicWritePrivateFile(path, []byte("second\n")); err != nil {
		t.Fatalf("replace existing file: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second\n" {
		t.Fatalf("content = %q, want replacement", data)
	}
}

func TestConfigureOpenClawGuardModeDelegatesIncludeSafePatchToHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell recorder is POSIX-only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "openclaw")
	argsPath := filepath.Join(dir, "args")
	stdinPath := filepath.Join(dir, "stdin")
	t.Setenv("RAMPART_TEST_ARGS", argsPath)
	t.Setenv("RAMPART_TEST_STDIN", stdinPath)
	script := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "set" ]; then
  printf '%s ' "$@" >> "$RAMPART_TEST_ARGS"
  printf '\n' >> "$RAMPART_TEST_ARGS"
  exit 0
fi
printf '%s ' "$@" >> "$RAMPART_TEST_ARGS"
printf '\n' >> "$RAMPART_TEST_ARGS"
cat > "$RAMPART_TEST_STDIN"
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prepareOpenClawGuardTest(t, dir, bin)

	if err := configureOpenClawGuardMode(bin, "http://127.0.0.1:19090", &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"config set plugins.entries.rampart.config.approvalTimeoutMs 120000 --json",
		"config patch --stdin",
	} {
		if !strings.Contains(strings.Join(strings.Fields(string(args)), " "), want) {
			t.Fatalf("OpenClaw commands missing %q: %q", want, args)
		}
	}
	patchData, err := os.ReadFile(stdinPath)
	if err != nil {
		t.Fatal(err)
	}
	var patch map[string]any
	if err := json.Unmarshal(patchData, &patch); err != nil {
		t.Fatal(err)
	}
	entry := patch["plugins"].(map[string]any)["entries"].(map[string]any)["rampart"].(map[string]any)
	pluginConfig := entry["config"].(map[string]any)
	if entry["enabled"] != true || pluginConfig["failOpen"] != false || pluginConfig["failOpenTools"] != nil || pluginConfig["serveUrl"] != "http://127.0.0.1:19090" {
		t.Fatalf("unexpected managed guard patch: %#v", entry)
	}
}

func TestConfigureOpenClawGuardModeFallsBackToValidatedLegacyHostWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell recorder is POSIX-only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "openclaw")
	argsPath := filepath.Join(dir, "args")
	t.Setenv("RAMPART_TEST_ARGS", argsPath)
	script := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "patch" ]; then
  exit 2
fi
printf '%s ' "$@" >> "$RAMPART_TEST_ARGS"
printf '\n' >> "$RAMPART_TEST_ARGS"
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prepareOpenClawGuardTest(t, dir, bin)

	if err := configureOpenClawGuardMode(bin, "http://localhost:9090", &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(lines) != 5 {
		t.Fatalf("fallback command count = %d, want 5: %q", len(lines), args)
	}
	for _, want := range []string{
		"approvalTimeoutMs 120000 --json",
		"failOpenTools [] --json",
		"failOpen false --json",
		`serveUrl "http://localhost:9090" --json`,
		"rampart.enabled true --json",
	} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("legacy host writes missing %q: %s", want, args)
		}
	}
}

func TestConfigureOpenClawGuardModeDoesNotBypassSupportedHostRejection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell recorder is POSIX-only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "openclaw")
	marker := filepath.Join(dir, "fallback-ran")
	t.Setenv("RAMPART_TEST_MARKER", marker)
	script := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "set" ] && [ "$3" = "plugins.entries.rampart.config.approvalTimeoutMs" ]; then
  exit 0
fi
if [ "$1" = "config" ] && [ "$2" = "patch" ] && [ "$3" = "--help" ]; then
  exit 0
fi
if [ "$1" = "config" ] && [ "$2" = "patch" ]; then
  printf '%s\n' 'write rejected by host policy' >&2
  exit 2
fi
touch "$RAMPART_TEST_MARKER"
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prepareOpenClawGuardTest(t, dir, bin)

	err := configureOpenClawGuardMode(bin, "http://localhost:9090", &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "config patch") {
		t.Fatalf("expected supported host rejection, got %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fallback bypassed a supported host rejection: %v", err)
	}
}

func TestNormalizeOpenClawServeURLRequiresLoopbackRoot(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "http://localhost:9090/", want: "http://localhost:9090", ok: true},
		{raw: "https://127.0.0.1:19090", want: "https://127.0.0.1:19090", ok: true},
		{raw: "http://[::1]:9090", want: "http://[::1]:9090", ok: true},
		{raw: "https://rampart.example.com", ok: false},
		{raw: "http://localhost:9090/path", ok: false},
		{raw: "http://user:secret@localhost:9090", ok: false},
	} {
		t.Run(test.raw, func(t *testing.T) {
			got, err := normalizeOpenClawServeURL(test.raw)
			if test.ok {
				if err != nil || got != test.want {
					t.Fatalf("normalizeOpenClawServeURL(%q) = %q, %v; want %q", test.raw, got, err, test.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("normalizeOpenClawServeURL(%q) unexpectedly returned %q", test.raw, got)
			}
		})
	}
}

func TestEnsureServeRunningHonorsReachableExplicitEndpoint(t *testing.T) {
	uptime := 1.0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service": "rampart", "status": "ok", "mode": "enforce",
			"version": "test", "uptime_seconds": uptime,
		})
	}))
	defer srv.Close()

	var out bytes.Buffer
	if err := ensureServeRunningForURL(&out, &bytes.Buffer{}, srv.URL); err != nil {
		t.Fatalf("ensureServeRunningForURL: %v", err)
	}
	if !strings.Contains(out.String(), srv.URL) {
		t.Fatalf("output does not identify explicit endpoint: %q", out.String())
	}
}

func TestEnsureServeRunningDoesNotReplaceUnreachableExplicitEndpoint(t *testing.T) {
	err := ensureServeRunningForURL(&bytes.Buffer{}, &bytes.Buffer{}, "http://127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "configured Rampart policy service") {
		t.Fatalf("error = %v, want explicit-endpoint failure", err)
	}
}

func prepareOpenClawGuardTest(t *testing.T, root, bin string) {
	t.Helper()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, openclawPluginDir), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	config := []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}},"tools":{"exec":{"ask":"on-miss"}}}`)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)
}

func TestOpenClawPluginCurrentDetectsSameVersionDrift(t *testing.T) {
	dir := t.TempDir()
	if err := ocplugin.Extract(dir); err != nil {
		t.Fatal(err)
	}
	state := openClawPluginState{
		Installed: true, Allowed: true, Enabled: true, StartupExplicit: true,
		ManifestVersion: ocplugin.Version(), RuntimeVersion: ocplugin.Version(), Dir: dir,
	}
	if !openClawPluginCurrent(state) {
		t.Fatal("exact bundled plugin should be current")
	}
	bundled, err := ocplugin.PluginFS.ReadFile("index.js")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), append(bundled, []byte("\n// drift")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if openClawPluginCurrent(state) {
		t.Fatal("same-version runtime drift should force a managed reinstall")
	}
}
