package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
)

func removeOpenClawNativePluginAt(stateDir, configPath string) (bool, error) {
	return removeOpenClawNativePluginWithHostAt(stateDir, configPath, nil)
}

func installCurrentOpenClawTestPlugin(stateDir, configPath string) error {
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		return err
	}
	cfg := map[string]any{}
	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	plugins, _ := cfg["plugins"].(map[string]any)
	if plugins == nil {
		plugins = map[string]any{}
		cfg["plugins"] = plugins
	}
	entries, _ := plugins["entries"].(map[string]any)
	if entries == nil {
		entries = map[string]any{}
		plugins["entries"] = entries
	}
	entries["rampart"] = map[string]any{"enabled": true}
	installs, _ := plugins["installs"].(map[string]any)
	if installs == nil {
		installs = map[string]any{}
		plugins["installs"] = installs
	}
	installs["rampart"] = map[string]any{"source": "path", "installPath": pluginDir}
	allow, _ := plugins["allow"].([]any)
	plugins["allow"] = append(allow, "rampart")
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, append(out, '\n'), 0o600)
}

func currentOpenClawTestPlugin(dir string) bool {
	state := openClawPluginState{Installed: true, Allowed: true, Enabled: true, Dir: dir}
	state.readInstalledPluginMetadata()
	return openClawPluginManaged(dir) && openClawPluginCurrent(state)
}

func noopOpenClawRuntimeValidation() error { return nil }

func TestOpenClawMigrationInstallFailureLeavesLegacyProtectionUntouched(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "read.js")
	backup := target + ".rampart-backup"
	configPath := filepath.Join(dir, "openclaw.json")
	patched := []byte("before\n/* RAMPART_READ_CHECK */ try {}\nafter\n")
	original := []byte("before\nafter\n")
	config := []byte(`{"rampart":{"url":"http://127.0.0.1:9090"},"ask":"on-miss"}` + "\n")
	for path, data := range map[string][]byte{
		target:     patched,
		backup:     original,
		configPath: config,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	patchDirsCalled := false
	cleanCalled := false
	err := runSetupOpenClawMigrateWith(
		io.Discard,
		io.Discard,
		func(io.Writer, io.Writer) error { return errors.New("native runtime validation failed") },
		func() []string {
			patchDirsCalled = true
			return []string{dir}
		},
		func(io.Writer, io.Writer) error {
			cleanCalled = true
			return os.WriteFile(configPath, []byte("mutated"), 0o600)
		},
	)
	if err == nil || !strings.Contains(err.Error(), "legacy protection was left unchanged") {
		t.Fatalf("migration error = %v, want preserved-legacy failure", err)
	}
	if patchDirsCalled || cleanCalled {
		t.Fatalf("legacy retirement ran after native failure: patch_dirs=%t clean=%t", patchDirsCalled, cleanCalled)
	}
	for path, want := range map[string][]byte{
		target:     patched,
		backup:     original,
		configPath: config,
	} {
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s changed after native install failure: got %q, want %q", path, got, want)
		}
	}
}

func TestOpenClawMigrationRestoresOnlyPositivelyOwnedLegacyPatches(t *testing.T) {
	dir := t.TempDir()
	ownedTarget := filepath.Join(dir, "read.js")
	ownedBackup := ownedTarget + ".rampart-backup"
	unownedTarget := filepath.Join(dir, "other.js")
	unownedBackup := unownedTarget + ".rampart-backup"
	ownedOriginal := []byte("export const read = true;\n")
	unownedCurrent := []byte("export const keep = true;\n")
	unownedOriginal := []byte("export const planted = true;\n")
	for path, data := range map[string][]byte{
		ownedTarget:   []byte("/* RAMPART_DIST_CHECK_READ */ try {}\n"),
		ownedBackup:   ownedOriginal,
		unownedTarget: unownedCurrent,
		unownedBackup: unownedOriginal,
	} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cleanCalled := false
	if err := runSetupOpenClawMigrateWith(
		io.Discard,
		io.Discard,
		func(io.Writer, io.Writer) error { return nil },
		func() []string { return []string{dir} },
		func(io.Writer, io.Writer) error {
			cleanCalled = true
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if !cleanCalled {
		t.Fatal("legacy config cleanup did not run after native validation")
	}
	gotOwned, err := os.ReadFile(ownedTarget)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotOwned, ownedOriginal) {
		t.Fatalf("owned target = %q, want restored %q", gotOwned, ownedOriginal)
	}
	if _, err := os.Stat(ownedBackup); !os.IsNotExist(err) {
		t.Fatalf("owned backup still exists after restore: %v", err)
	}
	gotUnowned, err := os.ReadFile(unownedTarget)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotUnowned, unownedCurrent) {
		t.Fatalf("unowned target was overwritten: got %q, want %q", gotUnowned, unownedCurrent)
	}
	gotUnownedBackup, err := os.ReadFile(unownedBackup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotUnownedBackup, unownedOriginal) {
		t.Fatalf("unowned backup changed: got %q, want %q", gotUnownedBackup, unownedOriginal)
	}
}

func TestExtractOpenClawPluginRuntimeVersion(t *testing.T) {
	got := extractOpenClawPluginRuntimeVersion(`export const id = "rampart";
export const version = "1.0.0";
`)
	if got != "1.0.0" {
		t.Fatalf("runtime version = %q, want 1.0.0", got)
	}
}

func TestNormalizeOpenClawExecModeConfigRemovesOnlyRetiredFields(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "openclaw.json")
	before := `{
  "identity": {"name": "keep-me", "largeId": 9007199254740993},
  "tools": {"exec": {"mode": "full", "ask": "off", "security": "full", "timeout": 30}}
}`
	if err := os.WriteFile(configPath, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}

	changed, err := normalizeOpenClawExecModeConfigAt(configPath)
	if err != nil || !changed {
		t.Fatalf("normalize = (%v, %v), want (true, nil)", changed, err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["identity"].(map[string]any)["name"] != "keep-me" {
		t.Fatalf("unrelated config changed: %#v", cfg)
	}
	if !bytes.Contains(data, []byte(`"largeId": 9007199254740993`)) {
		t.Fatalf("large unrelated numeric ID changed: %s", data)
	}
	execCfg := cfg["tools"].(map[string]any)["exec"].(map[string]any)
	if execCfg["mode"] != "full" || execCfg["timeout"] != float64(30) {
		t.Fatalf("canonical exec config changed: %#v", execCfg)
	}
	if _, exists := execCfg["ask"]; exists {
		t.Fatalf("retired ask field remains: %#v", execCfg)
	}
	if _, exists := execCfg["security"]; exists {
		t.Fatalf("retired security field remains: %#v", execCfg)
	}

	afterFirst := append([]byte(nil), data...)
	changed, err = normalizeOpenClawExecModeConfigAt(configPath)
	if err != nil || changed {
		t.Fatalf("second normalize = (%v, %v), want (false, nil)", changed, err)
	}
	afterSecond, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterFirst, afterSecond) {
		t.Fatal("idempotent mode normalization rewrote OpenClaw config")
	}
}

func TestSetOpenClawExecAskPreservesCanonicalMode(t *testing.T) {
	for _, tt := range []struct {
		mode     string
		security string
		ask      string
	}{
		{mode: "deny", security: "deny", ask: "off"},
		{mode: "allowlist", security: "allowlist", ask: "off"},
		{mode: "ask", security: "allowlist", ask: "on-miss"},
		{mode: "auto", security: "allowlist", ask: "on-miss"},
		{mode: "full", security: "full", ask: "off"},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			stateDir := t.TempDir()
			configPath := filepath.Join(stateDir, "openclaw.json")
			config := fmt.Sprintf(`{"tools":{"exec":{"mode":%q,"ask":%q,"security":%q}},"keep":true}`, tt.mode, tt.ask, tt.security)
			if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			execCfg := cfg["tools"].(map[string]any)["exec"].(map[string]any)
			if execCfg["mode"] != tt.mode || cfg["keep"] != true {
				t.Fatalf("canonical or unrelated config changed: %#v", cfg)
			}
			if _, exists := execCfg["ask"]; exists {
				t.Fatalf("set reintroduced retired ask field: %#v", execCfg)
			}
			if _, exists := execCfg["security"]; exists {
				t.Fatalf("set retained retired security field: %#v", execCfg)
			}
			if _, err := os.Lstat(openClawExecAskReceiptPath(stateDir)); !os.IsNotExist(err) {
				t.Fatalf("canonical mode unexpectedly created a legacy receipt: %v", err)
			}
		})
	}
}

func TestNormalizeOpenClawExecModeConfigRefusesConflictingLegacyPolicy(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config string
	}{
		{name: "stricter ask", config: `{"tools":{"exec":{"mode":"full","ask":"always"}}}`},
		{name: "stricter security", config: `{"tools":{"exec":{"mode":"full","security":"deny"}}}`},
		{name: "weaker security", config: `{"tools":{"exec":{"mode":"deny","security":"full"}}}`},
		{name: "malformed ask", config: `{"tools":{"exec":{"mode":"auto","ask":true}}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "openclaw.json")
			before := []byte(tt.config)
			if err := os.WriteFile(configPath, before, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeOpenClawExecModeConfigAt(configPath); err == nil || !strings.Contains(err.Error(), "conflicts with canonical") {
				t.Fatalf("normalize error = %v, want canonical policy conflict", err)
			}
			after, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("conflicting config changed")
			}
		})
	}
}

func TestOpenClawExecModeMigrationRollsBackFailedHostInstall(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	before := []byte("{\n  \"plugins\": {\"entries\": {\"rampart\": {\"enabled\": true}}},\n  \"tools\": {\"exec\": {\"mode\": \"full\", \"ask\": \"off\"}}\n}\n")
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	hostErr := errors.New("host install failed")
	err := installOpenClawPluginSafely(stateDir, configPath, func() error {
		return runWithOpenClawExecModeMigration(stateDir, configPath, func() error { return hostErr }, io.Discard)
	}, noopOpenClawRuntimeValidation, io.Discard)
	if !errors.Is(err, hostErr) {
		t.Fatalf("install error = %v, want %v", err, hostErr)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("failed install did not restore exact config bytes:\n%s", after)
	}
}

func TestOpenClawExecModeMigrationRollbackPreservesConcurrentChange(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"tools":{"exec":{"mode":"full","ask":"off"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	migration, err := migrateOpenClawExecModeConfigAt(configPath)
	if err != nil || !migration.changed() {
		t.Fatalf("migration = (%v, %v), want changed", migration, err)
	}
	operatorChange := []byte(`{"tools":{"exec":{"mode":"deny"}},"operator":true}`)
	if err := os.WriteFile(configPath, operatorChange, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migration.rollbackIfUnchanged(); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("rollback error = %v, want concurrent-change refusal", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, operatorChange) {
		t.Fatal("rollback overwrote concurrent operator change")
	}
}

func TestSetOpenClawExecAskDoesNotRewriteValidCanonicalConfig(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	before := []byte("{\n  \"tools\": {\"exec\": {\"mode\": \"auto\"}},\n  \"keep\": true\n}\n")
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("valid canonical config was rewritten")
	}
}

func TestEnsureOpenClawExecApprovalPreservesIncludeBackedCanonicalMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is POSIX-only")
	}
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	includePath := filepath.Join(stateDir, "tools.json")
	outer := []byte(`{"tools":{"$include":"tools.json"},"keep":true}`)
	included := []byte(`{"exec":{"mode":"auto","security":"allowlist","ask":"on-miss"},"keep":true,"largeId":9007199254740993}`)
	if err := os.WriteFile(configPath, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(includePath, included, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	script := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "get" ] && [ "$3" = "tools.exec.mode" ]; then
  printf '%s\n' '"auto"'
  exit 0
fi
exit 1
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureOpenClawExecApprovalConfig(bin, stateDir, configPath); err != nil {
		t.Fatal(err)
	}
	gotOuter, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	gotIncluded, err := os.ReadFile(includePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotOuter, outer) {
		t.Fatal("include-backed root config was rewritten")
	}
	var gotTools map[string]any
	if err := json.Unmarshal(gotIncluded, &gotTools); err != nil {
		t.Fatal(err)
	}
	execCfg := gotTools["exec"].(map[string]any)
	if execCfg["mode"] != "auto" || gotTools["keep"] != true {
		t.Fatalf("include-backed canonical config changed: %#v", gotTools)
	}
	if !bytes.Contains(gotIncluded, []byte(`"largeId": 9007199254740993`)) {
		t.Fatalf("include-backed large numeric ID changed: %s", gotIncluded)
	}
	if _, present := execCfg["ask"]; present {
		t.Fatalf("include-backed retired ask remains: %#v", execCfg)
	}
	if _, present := execCfg["security"]; present {
		t.Fatalf("include-backed retired security remains: %#v", execCfg)
	}
	if _, err := os.Lstat(openClawExecAskReceiptPath(stateDir)); !os.IsNotExist(err) {
		t.Fatalf("canonical include unexpectedly created a legacy receipt: %v", err)
	}
}

func TestEnsureOpenClawExecApprovalAcceptsOperatorOwnedIncludeBackedLegacyOff(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	includePath := filepath.Join(stateDir, "tools.json")
	outer := []byte(`{"tools":{"$include":"tools.json"},"keep":true}`)
	included := []byte(`{"exec":{"security":"full","ask":"off"},"keep":true}`)
	if err := os.WriteFile(configPath, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(includePath, included, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureOpenClawExecApprovalConfig("unused", stateDir, configPath); err != nil {
		t.Fatal(err)
	}
	gotOuter, outerErr := os.ReadFile(configPath)
	gotIncluded, includeErr := os.ReadFile(includePath)
	if outerErr != nil || includeErr != nil {
		t.Fatalf("read configs: outer=%v include=%v", outerErr, includeErr)
	}
	if !bytes.Equal(gotOuter, outer) || !bytes.Equal(gotIncluded, included) {
		t.Fatal("operator-owned include-backed legacy config was rewritten")
	}
	if _, err := os.Lstat(openClawExecAskReceiptPath(stateDir)); !os.IsNotExist(err) {
		t.Fatalf("operator-owned include unexpectedly created a receipt: %v", err)
	}
}

func TestNormalizeOpenClawExecModeConfigRefusesLinkedConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on many Windows hosts")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	configPath := filepath.Join(dir, "openclaw.json")
	before := []byte(`{"tools":{"exec":{"mode":"full","ask":"off"}}}`)
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeOpenClawExecModeConfigAt(configPath); err == nil || !strings.Contains(err.Error(), "linked or non-regular") {
		t.Fatalf("normalize error = %v, want linked config refusal", err)
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("linked config target changed")
	}
}

func TestOpenClawIncludesRefuseEscapingParentSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on many Windows hosts")
	}
	for _, section := range []string{"tools", "plugins"} {
		t.Run(section, func(t *testing.T) {
			stateDir := t.TempDir()
			outsideDir := t.TempDir()
			before := []byte(`{"exec":{"mode":"full","ask":"off"},"entries":{"rampart":{"enabled":true}}}`)
			outsidePath := filepath.Join(outsideDir, "included.json")
			if err := os.WriteFile(outsidePath, before, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideDir, filepath.Join(stateDir, "linked")); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(stateDir, "openclaw.json")
			config := fmt.Sprintf(`{%q:{"$include":"linked/included.json"}}`, section)
			if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			if section == "tools" {
				_, err = normalizeOpenClawExecModeConfigAt(configPath)
			} else {
				_, err = loadOpenClawPluginsConfig(configPath)
			}
			if err == nil || !strings.Contains(err.Error(), "outside the OpenClaw config directory") {
				t.Fatalf("include error = %v, want containment refusal", err)
			}
			after, err := os.ReadFile(outsidePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("outside include target changed")
			}
		})
	}
}

func TestOpenClawIncludeMigrationPinsInRootParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on many Windows hosts")
	}
	stateDir := t.TempDir()
	insideDir := filepath.Join(stateDir, "inside")
	if err := os.Mkdir(insideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	includePath := filepath.Join(insideDir, "tools.json")
	before := []byte(`{"exec":{"mode":"full","ask":"off"}}`)
	if err := os.WriteFile(includePath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(stateDir, "linked")
	if err := os.Symlink(insideDir, linkPath); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"tools":{"$include":"linked/tools.json"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	migration, err := migrateOpenClawExecModeConfigAt(configPath)
	if err != nil || !migration.changed() {
		t.Fatalf("migration = (%v, %v), want changed", migration, err)
	}
	resolvedInside, err := filepath.EvalSymlinks(insideDir)
	if err != nil {
		t.Fatal(err)
	}
	if migration.configPath != filepath.Join(resolvedInside, "tools.json") {
		t.Fatalf("migration retained directory alias: %s", migration.configPath)
	}
	outsideDir := t.TempDir()
	outsidePath := filepath.Join(outsideDir, "tools.json")
	if err := os.WriteFile(outsidePath, migration.after, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(linkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Fatal(err)
	}
	if err := migration.rollbackIfUnchanged(); err != nil {
		t.Fatal(err)
	}
	insideAfter, insideErr := os.ReadFile(includePath)
	outsideAfter, outsideErr := os.ReadFile(outsidePath)
	if insideErr != nil || outsideErr != nil {
		t.Fatalf("read targets: inside=%v outside=%v", insideErr, outsideErr)
	}
	if !bytes.Equal(insideAfter, before) || !bytes.Equal(outsideAfter, migration.after) {
		t.Fatal("rollback did not preserve the resolved include target")
	}
}

func TestOpenClawIncludeMigrationPreservesOtherHardLink(t *testing.T) {
	stateDir := t.TempDir()
	outsidePath := filepath.Join(t.TempDir(), "tools.json")
	before := []byte(`{"exec":{"mode":"full","ask":"off"}}`)
	if err := os.WriteFile(outsidePath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	includePath := filepath.Join(stateDir, "tools.json")
	if err := os.Link(outsidePath, includePath); err != nil {
		t.Skipf("creating a hard link is unavailable: %v", err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"tools":{"$include":"tools.json"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := normalizeOpenClawExecModeConfigAt(configPath)
	if err != nil || !changed {
		t.Fatalf("migration = (%v, %v), want changed", changed, err)
	}
	after, err := os.ReadFile(outsidePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("migration changed the other hard link")
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
  "tools": {"exec": {"ask": "on-miss", "security": "allowlist"}}
}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
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

func TestOpenClawExecModeMigrationRollsBackFailedHostUninstall(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	before := []byte("{\n  \"plugins\": {\"entries\": {\"rampart\": {\"enabled\": true}}},\n  \"tools\": {\"exec\": {\"mode\": \"full\", \"ask\": \"off\"}}\n}\n")
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	hostErr := errors.New("host uninstall failed")
	removed, err := removeOpenClawNativePluginWithHostAt(stateDir, configPath, func() error { return hostErr })
	if removed || !errors.Is(err, hostErr) {
		t.Fatalf("remove = (%v, %v), want (false, %v)", removed, err, hostErr)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("failed uninstall did not restore exact config bytes:\n%s", after)
	}
	if !openClawPluginManaged(pluginDir) {
		t.Fatal("failed host uninstall changed managed plugin path")
	}
}

func TestOpenClawUninstallRefusesAmbiguousModeReceiptBeforeMutation(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}},"tools":{"exec":{"ask":"always"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeUserJSON(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["tools"].(map[string]any)["exec"].(map[string]any)["mode"] = "full"
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPath := openClawExecAskReceiptPath(stateDir)
	receiptBefore, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	configBefore := append([]byte(nil), data...)
	hostCalled := false
	removed, err := removeOpenClawNativePluginWithHostAt(stateDir, configPath, func() error {
		hostCalled = true
		return nil
	})
	if removed || err == nil || !strings.Contains(err.Error(), "prior operator-owned") {
		t.Fatalf("remove = (%v, %v), want preflight refusal", removed, err)
	}
	if hostCalled {
		t.Fatal("host uninstall ran before ambiguous receipt was resolved")
	}
	if !openClawPluginManaged(pluginDir) {
		t.Fatal("plugin changed before ambiguous receipt was resolved")
	}
	configAfter, configErr := os.ReadFile(configPath)
	receiptAfter, receiptErr := os.ReadFile(receiptPath)
	if configErr != nil || receiptErr != nil || !bytes.Equal(configAfter, configBefore) || !bytes.Equal(receiptAfter, receiptBefore) {
		t.Fatalf("ambiguous receipt refusal changed state: configErr=%v receiptErr=%v", configErr, receiptErr)
	}
}

func TestRemoveOpenClawNativePluginFallbackNormalizesEquivalentMixedExecMode(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	config := []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}},"tools":{"exec":{"mode":"full","security":"full","ask":"off"}},"keep":true}`)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := removeOpenClawNativePluginAt(stateDir, configPath)
	if err != nil || !removed {
		t.Fatalf("remove = (%v, %v), want (true, nil)", removed, err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	execCfg := cfg["tools"].(map[string]any)["exec"].(map[string]any)
	if execCfg["mode"] != "full" || cfg["keep"] != true {
		t.Fatalf("canonical or unrelated config changed: %#v", cfg)
	}
	if _, present := execCfg["security"]; present {
		t.Fatalf("retired security remains: %#v", execCfg)
	}
	if _, present := execCfg["ask"]; present {
		t.Fatalf("retired ask remains: %#v", execCfg)
	}
}

func TestRemoveOpenClawNativePluginWithoutReceiptPreservesOperatorAsk(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}},"tools":{"exec":{"ask":"off"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if removed, err := removeOpenClawNativePluginAt(stateDir, configPath); err != nil || !removed {
		t.Fatalf("remove = (%v, %v), want (true, nil)", removed, err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg["tools"].(map[string]any)["exec"].(map[string]any)["ask"]; got != "off" {
		t.Fatalf("operator-owned tools.exec.ask = %#v, want off", got)
	}
}

func TestRemoveOpenClawNativePluginDoesNotOverwriteAskChangedAfterReceipt(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}},"tools":{"exec":{"ask":"always"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["tools"].(map[string]any)["exec"].(map[string]any)["ask"] = "on-miss"
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if removed, err := removeOpenClawNativePluginAt(stateDir, configPath); err != nil || !removed {
		t.Fatalf("remove = (%v, %v), want (true, nil)", removed, err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg["tools"].(map[string]any)["exec"].(map[string]any)["ask"]; got != "on-miss" {
		t.Fatalf("operator-changed tools.exec.ask = %#v, want on-miss", got)
	}
	if _, err := os.Lstat(openClawExecAskReceiptPath(stateDir)); !os.IsNotExist(err) {
		t.Fatalf("ownership receipt remains after operator-preserving removal: %v", err)
	}
}

func TestSetOpenClawExecAskRefreshesStaleReceiptAfterOperatorChange(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"tools":{"exec":{"ask":"always"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
		t.Fatal(err)
	}

	var cfg map[string]any
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["tools"].(map[string]any)["exec"].(map[string]any)["ask"] = "on-miss"
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
		t.Fatal(err)
	}
	changed, err := restoreOpenClawExecAskFromReceipt(stateDir, configPath)
	if err != nil || !changed {
		t.Fatalf("restore = (%v, %v), want (true, nil)", changed, err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg["tools"].(map[string]any)["exec"].(map[string]any)["ask"]; got != "on-miss" {
		t.Fatalf("restored ask = %#v, want latest operator value on-miss", got)
	}
}

func TestRestoreOpenClawExecAskRefusesAmbiguousPriorValueNextToMode(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"tools":{"exec":{"ask":"always"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setOpenClawExecAskAt(stateDir, configPath, "off"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	execCfg := cfg["tools"].(map[string]any)["exec"].(map[string]any)
	execCfg["mode"] = "full"
	delete(execCfg, "ask")
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	changed, err := restoreOpenClawExecAskFromReceipt(stateDir, configPath)
	if changed || err == nil || !strings.Contains(err.Error(), "prior operator-owned") {
		t.Fatalf("restore = (%v, %v), want ambiguity refusal", changed, err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &cfg); err != nil {
		t.Fatal(err)
	}
	execCfg = cfg["tools"].(map[string]any)["exec"].(map[string]any)
	if execCfg["mode"] != "full" {
		t.Fatalf("canonical mode changed: %#v", execCfg)
	}
	if _, exists := execCfg["ask"]; exists {
		t.Fatalf("legacy ask was reintroduced: %#v", execCfg)
	}
	if _, err := os.Lstat(openClawExecAskReceiptPath(stateDir)); err != nil {
		t.Fatalf("ambiguity receipt was removed: %v", err)
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

func TestRemoveOpenClawNativePluginRefusesConfigOnlyIdentity(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	before := []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}},"tools":{"exec":{"ask":"off"}}}`)
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := removeOpenClawNativePluginAt(stateDir, configPath); err == nil || !strings.Contains(err.Error(), "config-only") {
		t.Fatalf("expected config-only ownership refusal, got %v", err)
	}
	if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("config changed after ownership refusal: data=%q err=%v", after, err)
	}
}

func TestRemoveOpenClawNativePluginUsesHostLifecycleForIncludeBackedConfig(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	rootConfig := []byte(`{"identity":{"keep":true},"plugins":{"$include":"./plugins.json"}}`)
	if err := os.WriteFile(configPath, rootConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	includePath := filepath.Join(stateDir, "plugins.json")
	if err := os.WriteFile(includePath, []byte(`{"entries":{"rampart":{"enabled":true}},"allow":["rampart"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	hostCalled := false
	hostUninstall := func() error {
		hostCalled = true
		if err := os.RemoveAll(pluginDir); err != nil {
			return err
		}
		return os.WriteFile(includePath, []byte(`{"entries":{},"allow":[]}`), 0o600)
	}
	removed, err := removeOpenClawNativePluginWithHostAt(stateDir, configPath, hostUninstall)
	if err != nil || !removed {
		t.Fatalf("remove = (%v, %v), want (true, nil)", removed, err)
	}
	if !hostCalled {
		t.Fatal("host lifecycle uninstall was not called")
	}
	if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(after, rootConfig) {
		t.Fatalf("include-authored root config changed: data=%q err=%v", after, err)
	}
	if after, err := os.ReadFile(includePath); err != nil || bytes.Contains(after, []byte(`"rampart"`)) {
		t.Fatalf("host did not update included plugin config: data=%q err=%v", after, err)
	}
}

func TestRemoveOpenClawNativePluginRefusesUnmanagedPathBeforeHostLifecycle(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("operator-owned")
	if err := os.WriteFile(filepath.Join(pluginDir, "index.js"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err := removeOpenClawNativePluginWithHostAt(stateDir, filepath.Join(stateDir, "openclaw.json"), func() error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "non-Rampart") {
		t.Fatalf("expected unmanaged collision refusal, got %v", err)
	}
	if called {
		t.Fatal("host lifecycle uninstall ran for an unmanaged path")
	}
	if after, readErr := os.ReadFile(filepath.Join(pluginDir, "index.js")); readErr != nil || !bytes.Equal(after, foreign) {
		t.Fatalf("foreign path changed: data=%q err=%v", after, readErr)
	}
}

func TestRemoveOpenClawNativePluginRemovesOwnedLegacyHookWithoutCallingNativeHostUninstall(t *testing.T) {
	stateDir := t.TempDir()
	hookDir := filepath.Join(stateDir, "hooks", "rampart")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, "HOOK.md"), []byte("Rampart AI agent firewall hook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, "index.js"), []byte(`export * from "../../index.js"`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	operatorConfig := []byte(`{"tools":{"exec":{"mode":"full","ask":"always"}},"keep":true}`)
	if err := os.WriteFile(configPath, operatorConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	hostCalled := false
	removed, err := removeOpenClawNativePluginWithHostAt(stateDir, configPath, func() error {
		hostCalled = true
		return errors.New("native plugin is not installed")
	})
	if err != nil || !removed {
		t.Fatalf("remove = (%v, %v), want (true, nil)", removed, err)
	}
	if hostCalled {
		t.Fatal("native host uninstall was called for a legacy-hook-only installation")
	}
	if _, err := os.Lstat(hookDir); !os.IsNotExist(err) {
		t.Fatalf("managed legacy hook remains: %v", err)
	}
	if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(after, operatorConfig) {
		t.Fatalf("hook-only uninstall changed operator exec config: data=%q err=%v", after, err)
	}
}

func TestOpenClawInstallSafetyRefusesUnmanagedCollision(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("operator-owned")
	if err := os.WriteFile(filepath.Join(pluginDir, "index.js"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	config := []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}}}`)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := installOpenClawPluginSafely(stateDir, configPath, func() error {
		called = true
		return nil
	}, noopOpenClawRuntimeValidation, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "non-Rampart") {
		t.Fatalf("expected unmanaged collision refusal, got %v", err)
	}
	if called {
		t.Fatal("host installer ran despite unmanaged collision")
	}
	if data, readErr := os.ReadFile(filepath.Join(pluginDir, "index.js")); readErr != nil || !bytes.Equal(data, foreign) {
		t.Fatalf("foreign plugin changed: data=%q err=%v", data, readErr)
	}
	if data, readErr := os.ReadFile(configPath); readErr != nil || !bytes.Equal(data, config) {
		t.Fatalf("foreign config changed: data=%q err=%v", data, readErr)
	}
}

func TestOpenClawInstallSafetyRefusesSymlinkCollision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlink creation requires privileges on many Windows hosts")
	}
	stateDir := t.TempDir()
	targetDir := filepath.Join(t.TempDir(), "rampart")
	if err := ocplugin.Extract(targetDir); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := os.MkdirAll(filepath.Dir(pluginDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := installOpenClawPluginSafely(stateDir, configPath, func() error { return nil }, noopOpenClawRuntimeValidation, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("expected symlink collision refusal, got %v", err)
	}
	if !currentOpenClawTestPlugin(targetDir) {
		t.Fatal("symlink target changed")
	}
}

func TestOpenClawInstallSafetyRefusesUnmanagedHookCollision(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	hookDir := filepath.Join(stateDir, "hooks", "rampart")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("operator hook")
	if err := os.WriteFile(filepath.Join(hookDir, "HOOK.md"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := installOpenClawPluginSafely(stateDir, configPath, func() error { return nil }, noopOpenClawRuntimeValidation, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "non-Rampart OpenClaw hook") {
		t.Fatalf("expected unmanaged hook refusal, got %v", err)
	}
	if !currentOpenClawTestPlugin(pluginDir) {
		t.Fatal("managed plugin changed while refusing foreign hook")
	}
	if data, readErr := os.ReadFile(filepath.Join(hookDir, "HOOK.md")); readErr != nil || !bytes.Equal(data, foreign) {
		t.Fatalf("foreign hook changed: data=%q err=%v", data, readErr)
	}
}

func TestOpenClawInstallSafetyRefusesConfigOnlyCollision(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	before := []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}},"identity":{"keep":true}}`)
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := installOpenClawPluginSafely(stateDir, configPath, func() error {
		called = true
		return nil
	}, noopOpenClawRuntimeValidation, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "config-only") {
		t.Fatalf("expected config-only ownership refusal, got %v", err)
	}
	if called {
		t.Fatal("host installer ran despite config-only collision")
	}
	if after, readErr := os.ReadFile(configPath); readErr != nil || !bytes.Equal(after, before) {
		t.Fatalf("config-only collision changed: data=%q err=%v", after, readErr)
	}
}

func TestOpenClawInstallSafetyIgnoresUnrelatedRampartTextOutsidePluginConfig(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"identity":{"name":"Rampart operator"},"plugins":{"entries":{"other":{"enabled":true}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installOpenClawPluginSafely(stateDir, configPath, func() error {
		return installCurrentOpenClawTestPlugin(stateDir, configPath)
	}, noopOpenClawRuntimeValidation, &bytes.Buffer{}); err != nil {
		t.Fatalf("unrelated Rampart text blocked a fresh install: %v", err)
	}
}

func TestOpenClawInstallSafetyRefusesIncludeBackedConfigOnlyCollision(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	rootConfig := []byte(`{"plugins":{"$include":"./plugins.json"},"identity":{"keep":true}}`)
	if err := os.WriteFile(configPath, rootConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	includePath := filepath.Join(stateDir, "plugins.json")
	includeConfig := []byte(`{"entries":{"rampart":{"enabled":true}}}`)
	if err := os.WriteFile(includePath, includeConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := installOpenClawPluginSafely(stateDir, configPath, func() error {
		called = true
		return nil
	}, noopOpenClawRuntimeValidation, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "config-only") {
		t.Fatalf("expected include-backed ownership refusal, got %v", err)
	}
	if called {
		t.Fatal("host installer ran despite include-backed config-only collision")
	}
	if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(after, rootConfig) {
		t.Fatalf("root config changed: data=%q err=%v", after, err)
	}
	if after, err := os.ReadFile(includePath); err != nil || !bytes.Equal(after, includeConfig) {
		t.Fatalf("included config changed: data=%q err=%v", after, err)
	}
}

func TestOpenClawInstallSafetyLeavesManagedInstallForHostRollback(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	beforeConfig := []byte(`{"plugins":{"allow":["other","rampart"],"entries":{"other":{"enabled":true},"rampart":{"enabled":true}}},"identity":{"keep":true}}`)
	if err := os.WriteFile(configPath, beforeConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ocplugin.Extract(filepath.Join(stateDir, openclawPluginDir)); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(stateDir, openclawPluginDir, "index.js")
	oldIndex, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	oldIndex = append(oldIndex, []byte("\n// prior managed version\n")...)
	if err := os.WriteFile(indexPath, oldIndex, 0o600); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected host install failure")
	err = installOpenClawPluginSafely(stateDir, configPath, func() error { return injected }, noopOpenClawRuntimeValidation, &bytes.Buffer{})
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected failure, got %v", err)
	}
	if after, readErr := os.ReadFile(indexPath); readErr != nil || !bytes.Equal(after, oldIndex) {
		t.Fatalf("prior plugin was not restored: data length=%d err=%v", len(after), readErr)
	}
	if after, readErr := os.ReadFile(configPath); readErr != nil || !bytes.Equal(after, beforeConfig) {
		t.Fatalf("prior config was not restored byte-for-byte: data=%q err=%v", after, readErr)
	}
}

func TestOpenClawInstallSafetyValidatesHostReplacementAndCleansManagedLegacyHook(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	beforeConfig := []byte(`{"plugins":{"allow":["other","rampart"],"entries":{"other":{"enabled":true},"rampart":{"enabled":true}}},"identity":{"keep":true}}`)
	if err := os.WriteFile(configPath, beforeConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "operator-old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	hookDir := filepath.Join(stateDir, "hooks", "rampart")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, "HOOK.md"), []byte("Rampart AI agent firewall hook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, "index.js"), []byte(`export * from "../../index.js"`), 0o600); err != nil {
		t.Fatal(err)
	}

	validated := false
	if err := installOpenClawPluginSafely(stateDir, configPath, func() error {
		if err := os.RemoveAll(pluginDir); err != nil {
			return err
		}
		return installCurrentOpenClawTestPlugin(stateDir, configPath)
	}, func() error {
		validated = true
		return nil
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !validated {
		t.Fatal("host runtime validation was not called")
	}
	if !currentOpenClawTestPlugin(pluginDir) {
		t.Fatal("current plugin payload was not installed")
	}
	if _, err := os.Stat(filepath.Join(pluginDir, "operator-old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old managed directory was not replaced: %v", err)
	}
	if _, err := os.Lstat(hookDir); !os.IsNotExist(err) {
		t.Fatalf("superseded managed hook remains: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"keep": true`)) || !bytes.Contains(data, []byte(`"other"`)) {
		t.Fatalf("unrelated config was not preserved: %s", data)
	}
}

func TestOpenClawInstallSafetyFreshInstall(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := installOpenClawPluginSafely(stateDir, configPath, func() error {
		return installCurrentOpenClawTestPlugin(stateDir, configPath)
	}, noopOpenClawRuntimeValidation, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !currentOpenClawTestPlugin(filepath.Join(stateDir, openclawPluginDir)) || !openClawConfigHasRampart(configPath) {
		t.Fatal("fresh host-native install did not publish the current managed plugin and config")
	}
}

func TestOpenClawHostLifecycleCommandsUseForceAndRuntimeInspection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell argument recorder is POSIX-only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "openclaw")
	argsPath := filepath.Join(dir, "args")
	t.Setenv("RAMPART_TEST_OPENCLAW_ARGS", argsPath)
	script := `#!/bin/sh
if [ "$3" = "--help" ]; then
  printf '%s\n' '  --force  Skip source confirmation' '  --accept-capabilities  Accept the plugin declared capabilities'
  exit 0
fi
printf '%s\n' "$@" > "$RAMPART_TEST_OPENCLAW_ARGS"
if [ "$2" = "inspect" ]; then
  printf '%s\n' 'OpenClaw migration notice' '{"plugin":{"id":"rampart"},"runtime":{"hooks":["before_tool_call"]}}'
fi
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	readArgs := func() []string {
		data, err := os.ReadFile(argsPath)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Fields(string(data))
	}

	if err := runOpenClawPluginInstall(bin, "/staged/rampart", &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(readArgs(), " "), "plugins install /staged/rampart --force --accept-capabilities"; got != want {
		t.Fatalf("install args = %q, want %q", got, want)
	}
	if err := runOpenClawPluginEnable(bin, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(readArgs(), " "), "plugins enable rampart --accept-capabilities"; got != want {
		t.Fatalf("enable args = %q, want %q", got, want)
	}
	if err := runOpenClawPluginUninstall(bin, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(readArgs(), " "), "plugins uninstall rampart --force"; got != want {
		t.Fatalf("uninstall args = %q, want %q", got, want)
	}
	if err := validateOpenClawPluginRuntime(bin); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(readArgs(), " "), "plugins inspect rampart --runtime --json"; got != want {
		t.Fatalf("runtime inspection args = %q, want %q", got, want)
	}
}

func TestOpenClawPluginEnableUsesOnlySupportedCompatibilityFlags(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell argument recorder is POSIX-only")
	}
	tests := []struct {
		name string
		help string
		want string
	}{
		{
			name: "current host requires capability consent",
			help: "  --accept-capabilities  Accept the plugin declared capabilities",
			want: "plugins enable rampart --accept-capabilities",
		},
		{
			name: "supported floor predates capability consent",
			help: "Usage: openclaw plugins enable [options] <id>",
			want: "plugins enable rampart",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "openclaw")
			argsPath := filepath.Join(dir, "args")
			t.Setenv("RAMPART_TEST_OPENCLAW_ARGS", argsPath)
			t.Setenv("RAMPART_TEST_OPENCLAW_HELP", tt.help)
			script := `#!/bin/sh
if [ "$3" = "--help" ]; then
  printf '%s\n' "$RAMPART_TEST_OPENCLAW_HELP"
  exit 0
fi
printf '%s\n' "$@" > "$RAMPART_TEST_OPENCLAW_ARGS"
`
			if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := runOpenClawPluginEnable(bin, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(argsPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(strings.Fields(string(data)), " "); got != tt.want {
				t.Fatalf("enable args = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOpenClawPluginEnableRefusesWhenOptionsProbeFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is POSIX-only")
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 23\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := runOpenClawPluginEnable(bin, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "inspect OpenClaw plugin enable options") {
		t.Fatalf("probe error = %v, want fail-closed enable options inspection error", err)
	}
}

func TestOpenClawPluginInstallUsesOnlySupportedCompatibilityFlags(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell argument recorder is POSIX-only")
	}
	tests := []struct {
		name string
		help string
		want string
	}{
		{
			name: "force predates capability consent",
			help: "  --force  Skip source confirmation",
			want: "plugins install /staged/rampart --force",
		},
		{
			name: "supported floor predates both flags",
			help: "Usage: openclaw plugins install [options] <path>",
			want: "plugins install /staged/rampart",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "openclaw")
			argsPath := filepath.Join(dir, "args")
			t.Setenv("RAMPART_TEST_OPENCLAW_ARGS", argsPath)
			t.Setenv("RAMPART_TEST_OPENCLAW_HELP", tt.help)
			script := `#!/bin/sh
if [ "$3" = "--help" ]; then
  printf '%s\n' "$RAMPART_TEST_OPENCLAW_HELP"
  exit 0
fi
printf '%s\n' "$@" > "$RAMPART_TEST_OPENCLAW_ARGS"
`
			if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := runOpenClawPluginInstall(bin, "/staged/rampart", &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(argsPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(strings.Fields(string(data)), " "); got != tt.want {
				t.Fatalf("install args = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOpenClawPluginInstallRefusesWhenInstallOptionsProbeFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is POSIX-only")
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 23\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := runOpenClawPluginInstall(bin, "/staged/rampart", &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "inspect OpenClaw plugin install options") {
		t.Fatalf("probe error = %v, want fail-closed install options inspection error", err)
	}
}

func TestValidateOpenClawPluginRuntimeRequiresHookEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is POSIX-only")
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' '{\"plugin\":{\"id\":\"rampart\"},\"runtime\":{\"hooks\":[]}}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateOpenClawPluginRuntime(bin); err == nil || !strings.Contains(err.Error(), "before_tool_call") {
		t.Fatalf("expected missing hook evidence failure, got %v", err)
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

func TestRestartOpenClawGatewayUsesPortableHostCommand(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	bin := filepath.Join(t.TempDir(), "openclaw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)

	err := restartOpenClawGateway()
	if err == nil || !strings.Contains(err.Error(), "openclaw gateway restart") || strings.Contains(err.Error(), "systemctl") {
		t.Fatalf("expected portable host restart failure, got %v", err)
	}
}

func TestGetOpenClawVersionIgnoresMigrationNotices(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	bin := filepath.Join(t.TempDir(), "openclaw")
	script := "#!/bin/sh\nprintf '%s\\n' '[state-migrations] Legacy state migration notes:' 'OpenClaw v2026.7.1-2'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	version, err := getOpenClawVersion(bin)
	if err != nil {
		t.Fatal(err)
	}
	if version != "2026.7.1-2" {
		t.Fatalf("version = %q, want 2026.7.1-2", version)
	}
	if ok, err := openclawVersionAtLeast(version, "2026.3.28"); err != nil || !ok {
		t.Fatalf("openclawVersionAtLeast = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestParseCalVerRejectsTrailingGarbage(t *testing.T) {
	if got := parseCalVer("2026oops.7.1"); got != nil {
		t.Fatalf("parseCalVer accepted malformed version: %v", got)
	}
	if got := parseCalVer("2026.7"); got != nil {
		t.Fatalf("parseCalVer accepted incomplete version: %v", got)
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
	home := t.TempDir()
	configDir := t.TempDir()
	cfg := filepath.Join(configDir, "custom.json")
	t.Setenv("OPENCLAW_HOME", home)
	t.Setenv("OPENCLAW_CONFIG_PATH", cfg)

	stateDir, configPath, err := resolveOpenClawStateDir("/missing/openclaw")
	if err != nil {
		t.Fatalf("resolveOpenClawStateDir returned error: %v", err)
	}
	wantState := filepath.Join(home, ".openclaw")
	if stateDir != wantState || configPath != cfg {
		t.Fatalf("stateDir/configPath = %q/%q, want %q/%q", stateDir, configPath, wantState, cfg)
	}
}

func TestResolveOpenClawStateDirKeepsIndependentOverrides(t *testing.T) {
	stateDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "custom.json")
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	t.Setenv("OPENCLAW_CONFIG_PATH", configPath)

	gotState, gotConfig, err := resolveOpenClawStateDir("/missing/openclaw")
	if err != nil {
		t.Fatal(err)
	}
	if gotState != stateDir || gotConfig != configPath {
		t.Fatalf("stateDir/configPath = %q/%q, want independent overrides %q/%q", gotState, gotConfig, stateDir, configPath)
	}
}

func TestDefaultOpenClawStateDirHonorsHomeAndProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("OPENCLAW_HOME", home)
	t.Setenv("OPENCLAW_PROFILE", "work")
	got, err := defaultOpenClawStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".openclaw-work"); got != want {
		t.Fatalf("defaultOpenClawStateDir = %q, want %q", got, want)
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
	if err := os.WriteFile(filepath.Join(pluginDir, "openclaw.plugin.json"), []byte(`{"version":"1.5.0","activation":{"onStartup":true}}`), 0o600); err != nil {
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

func TestGetOpenClawPluginStateReadsIncludeBackedActivation(t *testing.T) {
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"plugins":{"$include":"plugins.json"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	includePath := filepath.Join(stateDir, "plugins.json")
	if err := os.WriteFile(includePath, []byte(`{"allow":["other"],"entries":{"rampart":{"enabled":false}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	state := getOpenClawPluginStateAt(stateDir, configPath)
	if !state.Installed || state.Allowed || state.Enabled {
		t.Fatalf("included disabled/excluded state was not honored: %#v", state)
	}

	if err := os.WriteFile(includePath, []byte(`{"allow":["rampart"],"entries":{"rampart":{"enabled":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state = getOpenClawPluginStateAt(stateDir, configPath)
	if !state.Installed || !state.Allowed || !state.Enabled {
		t.Fatalf("included enabled state was not honored: %#v", state)
	}
}

func TestGetOpenClawPluginStateFailsClosedOnAmbiguousInclude(t *testing.T) {
	stateDir := t.TempDir()
	if err := ocplugin.Extract(filepath.Join(stateDir, openclawPluginDir)); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"plugins":{"$include":"plugins.json","allow":["rampart"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "plugins.json"), []byte(`{"entries":{"rampart":{"enabled":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	state := getOpenClawPluginStateAt(stateDir, configPath)
	if state.Allowed || state.Enabled {
		t.Fatalf("ambiguous plugins include should fail closed: %#v", state)
	}
}

func TestEnsureOpenClawApprovalHardeningUsesHostConfigWriter(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	home := t.TempDir()
	testSetHome(t, home)
	stateDir := filepath.Join(home, ".openclaw")
	configPath := filepath.Join(stateDir, "openclaw.json")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outerConfig := []byte(`{"plugins":{"$include":"plugins.json"}}` + "\n")
	if err := os.WriteFile(configPath, outerConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "plugins.json"), []byte(`{"entries":{"rampart":{"enabled":true}}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ocplugin.Extract(filepath.Join(stateDir, openclawPluginDir)); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(t.TempDir(), "args.log")
	bin := filepath.Join(t.TempDir(), "openclaw")
	shim := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$RAMPART_TEST_LOG\"\n"
	if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	t.Setenv("OPENCLAW_CONFIG_PATH", configPath)
	t.Setenv("RAMPART_TEST_LOG", logPath)

	var stdout, stderr bytes.Buffer
	if err := ensureOpenClawApprovalHardening(&stdout, &stderr); err != nil {
		t.Fatalf("ensureOpenClawApprovalHardening returned error: %v (stderr=%q)", err, stderr.String())
	}
	gotArgs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := "config set plugins.entries.rampart.config.approvalTimeoutMs 120000 --json\n"
	if string(gotArgs) != wantArgs {
		t.Fatalf("OpenClaw args = %q, want %q", gotArgs, wantArgs)
	}
	gotOuter, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotOuter, outerConfig) {
		t.Fatalf("Rampart rewrote include-backed outer config: got %q, want %q", gotOuter, outerConfig)
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
