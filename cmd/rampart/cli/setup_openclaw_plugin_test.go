package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractOpenClawPluginRuntimeVersion(t *testing.T) {
	got := extractOpenClawPluginRuntimeVersion(`export const id = "rampart";
export const version = "1.0.0";
`)
	if got != "1.0.0" {
		t.Fatalf("runtime version = %q, want 1.0.0", got)
	}
}

func TestRemoveOpenClawNativePluginPreservesUnrelatedStateAndIsIdempotent(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"id":"rampart","name":"Rampart","author":"peg","repository":"https://github.com/peg/rampart"}`
	if err := os.WriteFile(filepath.Join(pluginDir, "openclaw.plugin.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "index.js"), []byte("/** Rampart OpenClaw Plugin */\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherPlugin := filepath.Join(stateDir, "extensions", "other", "state.json")
	if err := os.MkdirAll(filepath.Dir(otherPlugin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPlugin, []byte(`{"memory":"keep"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	config := `{
  "identity": {"name": "keep-me"},
  "plugins": {
    "allow": ["other", "rampart"],
    "entries": {"other": {"enabled": true}, "rampart": {"enabled": true}},
    "installs": {"other": {"source": "npm"}, "rampart": {"source": "path"}}
  },
  "tools": {"exec": {"ask": "off", "security": "allowlist"}}
}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := removeOpenClawNativePluginAt(stateDir, configPath)
	if err != nil || !removed {
		t.Fatalf("removeOpenClawNativePluginAt() = (%v, %v), want (true, nil)", removed, err)
	}
	if _, err := os.Stat(pluginDir); !os.IsNotExist(err) {
		t.Fatalf("Rampart plugin directory still exists: %v", err)
	}
	if data, err := os.ReadFile(otherPlugin); err != nil || string(data) != `{"memory":"keep"}` {
		t.Fatalf("unrelated plugin state changed: data=%q err=%v", data, err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	plugins := got["plugins"].(map[string]any)
	for _, key := range []string{"entries", "installs"} {
		records := plugins[key].(map[string]any)
		if _, exists := records["rampart"]; exists {
			t.Fatalf("plugins.%s.rampart was not removed: %#v", key, records)
		}
		if _, exists := records["other"]; !exists {
			t.Fatalf("plugins.%s.other was removed: %#v", key, records)
		}
	}
	allow := plugins["allow"].([]any)
	if len(allow) != 1 || allow[0] != "other" {
		t.Fatalf("plugins.allow = %#v, want [other]", allow)
	}
	execConfig := got["tools"].(map[string]any)["exec"].(map[string]any)
	if execConfig["ask"] != "on-miss" || execConfig["security"] != "allowlist" {
		t.Fatalf("tools.exec was not safely restored: %#v", execConfig)
	}
	if got["identity"].(map[string]any)["name"] != "keep-me" {
		t.Fatalf("unrelated config changed: %#v", got)
	}

	afterFirst, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	removed, err = removeOpenClawNativePluginAt(stateDir, configPath)
	if err != nil || removed {
		t.Fatalf("second remove = (%v, %v), want (false, nil)", removed, err)
	}
	afterSecond, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterFirst, afterSecond) {
		t.Fatal("idempotent removal rewrote OpenClaw config")
	}
}

func TestRemoveOpenClawNativePluginRefusesUnmanagedDirectory(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "openclaw.plugin.json"), []byte(`{"id":"rampart","name":"Personal plugin"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "index.js"), []byte("user code"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	before := []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}},"tools":{"exec":{"ask":"off"}}}`)
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := removeOpenClawNativePluginAt(stateDir, configPath); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected ownership refusal, got %v", err)
	}
	if _, err := os.Stat(pluginDir); err != nil {
		t.Fatalf("unmanaged directory was removed: %v", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("config changed after refusal: data=%q err=%v", after, err)
	}
}

func TestFindOpenClawBinaryHonorsOverride(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "custom-openclaw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)

	got, err := findOpenClawBinary()
	if err != nil {
		t.Fatalf("findOpenClawBinary returned error: %v", err)
	}
	if got != bin {
		t.Fatalf("findOpenClawBinary = %q, want %q", got, bin)
	}
}

func TestFindOpenClawBinaryRejectsBadOverride(t *testing.T) {
	skipOnWindows(t, "POSIX executable bits are not meaningful on Windows")

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "not-executable")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)

	_, err := findOpenClawBinary()
	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("expected not executable error, got %v", err)
	}
}

func TestResolveOpenClawStateDirHonorsStateEnv(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPENCLAW_STATE_DIR", tmp)

	stateDir, configPath, err := resolveOpenClawStateDir("/missing/openclaw")
	if err != nil {
		t.Fatalf("resolveOpenClawStateDir returned error: %v", err)
	}
	if stateDir != tmp {
		t.Fatalf("stateDir = %q, want %q", stateDir, tmp)
	}
	if configPath != filepath.Join(tmp, "openclaw.json") {
		t.Fatalf("configPath = %q", configPath)
	}
}

func TestResolveOpenClawStateDirHonorsConfigEnv(t *testing.T) {
	tmp := t.TempDir()
	cfg := filepath.Join(tmp, "custom.json")
	t.Setenv("OPENCLAW_CONFIG_PATH", cfg)

	stateDir, configPath, err := resolveOpenClawStateDir("/missing/openclaw")
	if err != nil {
		t.Fatalf("resolveOpenClawStateDir returned error: %v", err)
	}
	if stateDir != tmp || configPath != cfg {
		t.Fatalf("stateDir/configPath = %q/%q, want %q/%q", stateDir, configPath, tmp, cfg)
	}
}

func TestResolveOpenClawStateDirIgnoresMigrationNotice(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	bin := filepath.Join(t.TempDir(), "openclaw")
	shim := "#!/bin/sh\n" +
		"printf '%s\\n' '[state-migrations] Legacy state migration notes:'\n" +
		"printf '%s\\n' '- Left plugin install index in place because shared SQLite state has conflicting plugin install metadata for: rampart'\n" +
		"printf '%s\\n' '" + configPath + "'\n"
	if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCLAW_STATE_DIR", "")
	t.Setenv("OPENCLAW_CONFIG_PATH", "")

	gotStateDir, gotConfigPath, err := resolveOpenClawStateDir(bin)
	if err != nil {
		t.Fatalf("resolveOpenClawStateDir returned error: %v", err)
	}
	if gotStateDir != stateDir || gotConfigPath != configPath {
		t.Fatalf("stateDir/configPath = %q/%q, want %q/%q", gotStateDir, gotConfigPath, stateDir, configPath)
	}
}

func TestGetOpenClawPluginStateWithMigrationNotice(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "openclaw.plugin.json"), []byte(`{"version":"1.4.0","activation":{"onStartup":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "openclaw.json"), []byte(`{"plugins":{"allow":["rampart"],"entries":{"rampart":{"enabled":true}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	bin := filepath.Join(t.TempDir(), "openclaw")
	shim := "#!/bin/sh\n" +
		"printf '%s\\n' '[state-migrations] Legacy state migration notes:'\n" +
		"printf '%s\\n' '- Left plugin install index in place because shared SQLite state has conflicting plugin install metadata for: rampart'\n" +
		"printf '%s\\n' '" + configPath + "'\n"
	if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCLAW_STATE_DIR", "")
	t.Setenv("OPENCLAW_CONFIG_PATH", "")
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)

	state := getOpenClawPluginState()
	if !state.Installed || !state.Allowed || !state.Enabled {
		t.Fatalf("expected installed, allowed, enabled plugin; got %#v", state)
	}
}

func TestEnsureOpenClawApprovalHardeningRefusesLegacyPatchOnModernOpenClaw(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	home := t.TempDir()
	testSetHome(t, home)
	stateDir := filepath.Join(home, ".openclaw")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "openclaw.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	shim := `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' '2026.7.1-2'
  exit 0
fi
printf '%s\n' "$OPENCLAW_CONFIG_PATH"
`
	if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	t.Setenv("OPENCLAW_CONFIG_PATH", filepath.Join(stateDir, "openclaw.json"))

	var stdout, stderr bytes.Buffer
	err := ensureOpenClawApprovalHardening(&stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "refusing legacy approval bundle patching") {
		t.Fatalf("expected modern OpenClaw legacy-patch refusal, got %v", err)
	}
}

func TestAddToOpenClawPluginsAllowPreservesAbsentAllowlist(t *testing.T) {
	skipOnWindows(t, "PATH shim binaries in this test are Unix-only")
	configPath := setupOpenClawConfigTest(t, `{"plugins":{"entries":{"rampart":{"enabled":true}}}}`)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	added, existing, err := addToOpenClawPluginsAllow("rampart")
	if err != nil {
		t.Fatalf("addToOpenClawPluginsAllow returned error: %v", err)
	}
	if added || existing != nil {
		t.Fatalf("expected no change with nil existing allowlist, got added=%v existing=%v", added, existing)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("config changed when plugins.allow was absent:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestAddToOpenClawPluginsAllowAppendsExistingAllowlist(t *testing.T) {
	skipOnWindows(t, "PATH shim binaries in this test are Unix-only")
	configPath := setupOpenClawConfigTest(t, `{"plugins":{"allow":["codex"]}}`)

	added, existing, err := addToOpenClawPluginsAllow("rampart")
	if err != nil {
		t.Fatalf("addToOpenClawPluginsAllow returned error: %v", err)
	}
	if !added || len(existing) != 1 || existing[0] != "codex" {
		t.Fatalf("expected append after existing codex allowlist, got added=%v existing=%v", added, existing)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"codex"`, `"rampart"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("updated config missing %s: %s", want, data)
		}
	}
}

func setupOpenClawConfigTest(t *testing.T, config string) string {
	t.Helper()
	stateDir := t.TempDir()
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "openclaw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}
