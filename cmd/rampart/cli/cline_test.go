package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCreateClineHookScriptsArePlatformNativeAndEnforcing(t *testing.T) {
	posix := createClineHookScript("/opt/Rampart's bin/rampart", "PostToolUse", "darwin")
	for _, want := range []string{"#!/bin/sh", clineManagedHookMarker, "hook --format cline"} {
		if !strings.Contains(posix, want) {
			t.Fatalf("POSIX script missing %q:\n%s", want, posix)
		}
	}
	if strings.Contains(posix, "--mode audit") || strings.Contains(posix, "|| true") {
		t.Fatalf("PostToolUse must preserve response enforcement:\n%s", posix)
	}
	if !strings.Contains(posix, `'"'"'`) {
		t.Fatalf("POSIX binary path was not shell-quoted: %s", posix)
	}

	windows := createClineHookScript(`C:\Program Files\Rampart's\rampart.exe`, "PreToolUse", "windows")
	for _, want := range []string{clineManagedHookMarker, "[Console]::In.ReadToEnd()", "hook --format cline", `Rampart''s`} {
		if !strings.Contains(windows, want) {
			t.Fatalf("PowerShell script missing %q:\n%s", want, windows)
		}
	}
	if strings.Contains(windows, "#!/") {
		t.Fatalf("PowerShell hook must not contain a POSIX shebang:\n%s", windows)
	}
}

func TestInstallClineHooksUsesDirectDiscoveryFiles(t *testing.T) {
	dir := t.TempDir()
	paths, migrated, err := installClineHooks(dir, "/usr/local/bin/rampart", "linux", false)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("fresh install unexpectedly reported migration")
	}
	for index, event := range clineHookEvents {
		if got, want := paths[index], filepath.Join(dir, event); got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		info, err := os.Stat(paths[index])
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s is not an executable regular file: %v", paths[index], info.Mode())
		}
		data, err := os.ReadFile(paths[index])
		if err != nil || !clineHookScriptManaged(data) {
			t.Fatalf("%s is not a managed hook: err=%v", paths[index], err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "PreToolUse", "rampart-policy")); err == nil {
		t.Fatal("legacy directory layout was created")
	}

	windowsDir := t.TempDir()
	windowsPaths, _, err := installClineHooks(windowsDir, `C:\Rampart\rampart.exe`, "windows", false)
	if err != nil {
		t.Fatal(err)
	}
	for index, event := range clineHookEvents {
		if got, want := windowsPaths[index], filepath.Join(windowsDir, event+".ps1"); got != want {
			t.Fatalf("Windows path = %q, want %q", got, want)
		}
	}
}

func TestInstallClineHooksMigratesOnlyOwnedLegacyLayout(t *testing.T) {
	dir := t.TempDir()
	legacy := map[string]string{
		"PreToolUse":  "rampart-policy",
		"PostToolUse": "rampart-audit",
	}
	for event, name := range legacy {
		path := filepath.Join(dir, event, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		content := createLegacyClineHookForTest(event)
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	paths, migrated, err := installClineHooks(dir, "/usr/local/bin/rampart", "linux", false)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("expected legacy layout migration")
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("migrated path %s is not a file: info=%v err=%v", path, info, err)
		}
	}

	conflictDir := t.TempDir()
	conflict := filepath.Join(conflictDir, "PreToolUse")
	if err := os.MkdirAll(conflict, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conflict, "user-hook"), []byte("user"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installClineHooks(conflictDir, "/usr/local/bin/rampart", "linux", true); err == nil || !strings.Contains(err.Error(), "never overwrites") {
		t.Fatalf("force must reject non-Rampart directory, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(conflict, "user-hook")); err != nil {
		t.Fatalf("user hook was modified: %v", err)
	}
}

func TestInstallClineHooksMigratesOwnedLegacyLayoutOnWindows(t *testing.T) {
	dir := t.TempDir()
	for event, name := range map[string]string{"PreToolUse": "rampart-policy", "PostToolUse": "rampart-audit"} {
		path := filepath.Join(dir, event, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(createLegacyClineHookForTest(event)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	paths, migrated, err := installClineHooks(dir, `C:\Rampart\rampart.exe`, "windows", false)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("expected Windows install to clean owned legacy directories")
	}
	for index, event := range clineHookEvents {
		if _, err := os.Stat(paths[index]); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, event)); err == nil {
			t.Fatalf("legacy %s directory still exists", event)
		}
	}
}

func TestInstallAndRemoveClineHooksNeverOverwriteOtherOwners(t *testing.T) {
	dir := t.TempDir()
	pre := filepath.Join(dir, "PreToolUse")
	if err := os.WriteFile(pre, []byte("#!/bin/sh\n# user hook\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installClineHooks(dir, "/usr/local/bin/rampart", "linux", false); err == nil {
		t.Fatal("expected non-Rampart hook conflict")
	}
	if _, _, err := installClineHooks(dir, "/usr/local/bin/rampart", "linux", true); err == nil {
		t.Fatal("--force must not overwrite a non-Rampart hook")
	}
	data, _ := os.ReadFile(pre)
	if !strings.Contains(string(data), "user hook") {
		t.Fatalf("user hook was overwritten: %q", data)
	}

	managed := filepath.Join(dir, "PostToolUse")
	if err := os.WriteFile(managed, []byte(createClineHookScript("rampart", "PostToolUse", "linux")), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := removeClineHooksFromDir(cmd, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pre); err != nil {
		t.Fatalf("non-Rampart hook was removed: %v", err)
	}
	if _, err := os.Stat(managed); !os.IsNotExist(err) {
		t.Fatalf("managed hook still exists: %v", err)
	}
	if !strings.Contains(out.String(), "Skipped non-Rampart hook") {
		t.Fatalf("removal did not report preserved hook:\n%s", out.String())
	}
}

func TestRemoveClineHooksPreservesLegacySymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "owned-looking-target")
	if err := os.WriteFile(target, []byte(createLegacyClineHookForTest("PreToolUse")), 0o755); err != nil {
		t.Fatal(err)
	}
	legacyDir := filepath.Join(dir, "PreToolUse")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(legacyDir, "rampart-policy")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := removeClineHooksFromDir(cmd, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("non-Rampart symlink was removed: %v", err)
	}
	if !strings.Contains(out.String(), "Skipped non-Rampart hook") {
		t.Fatalf("symlink preservation was not reported:\n%s", out.String())
	}
}

func TestClineHookPairConfiguredChecksOwnershipAndExecutableBit(t *testing.T) {
	dir := t.TempDir()
	paths, _, err := installClineHooks(dir, "rampart", "linux", false)
	if err != nil {
		t.Fatal(err)
	}
	if !clineHookPairConfigured(dir, "linux") {
		t.Fatal("expected installed pair to be configured")
	}
	if err := os.Chmod(paths[0], 0o644); err != nil {
		t.Fatal(err)
	}
	if clineHookPairConfigured(dir, "linux") {
		t.Fatal("disabled POSIX hook must not be reported configured")
	}
	if !clineHookPairConfigured(dir, "windows") {
		// No Windows artifacts were installed in this directory.
	} else {
		t.Fatal("POSIX files must not masquerade as Windows .ps1 hooks")
	}
}

func TestResolveClineSetupHookDirAndDataDirIndependence(t *testing.T) {
	home := t.TempDir()
	got, scope, err := resolveClineSetupHookDir(home, false, "")
	if err != nil || got != filepath.Join(home, "Documents", "Cline", "Hooks") || scope != "user-level" {
		t.Fatalf("default = %q, %q, %v", got, scope, err)
	}
	got, scope, err = resolveClineSetupHookDir(home, false, "~/custom-hooks")
	if err != nil || got != filepath.Join(home, "custom-hooks") || scope != "explicit" {
		t.Fatalf("explicit = %q, %q, %v", got, scope, err)
	}
	if _, _, err := resolveClineSetupHookDir(home, false, "~other/hooks"); err == nil {
		t.Fatal("expected another user's tilde path to be rejected")
	}

	t.Setenv("CLINE_DATA_DIR", filepath.Join(home, "isolated-data"))
	if got := clineCLIHooksDir(home); got != filepath.Join(home, ".cline", "hooks") {
		t.Fatalf("CLINE_DATA_DIR incorrectly changed hooks: %q", got)
	}
	t.Setenv("CLINE_DIR", "~/custom-cline")
	if got := clineCLIHooksDir(home); got != filepath.Join(home, "custom-cline", "hooks") {
		t.Fatalf("CLINE_DIR override = %q", got)
	}
}

func TestClineKnownHookDirsMatchReliableDiscoveryPaths(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workspace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	workspace, err = os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// Current upstream advertises --hooks-dir by setting this environment
	// variable, but its file-hook loader does not consume it. Do not turn the
	// mere presence of files there into a protected status claim.
	explicit := filepath.Join(t.TempDir(), "advertised-but-not-loaded")
	t.Setenv("CLINE_HOOKS_DIR", explicit)

	dirs := clineKnownHookDirs(home)
	for _, want := range []string{
		clineUserHooksDir(home),
		filepath.Join(home, ".cline", "hooks"),
		filepath.Join(workspace, ".clinerules", "hooks"),
		filepath.Join(workspace, ".cline", "hooks"),
	} {
		if !clinePathInList(dirs, want) {
			t.Fatalf("reliable discovery path %q missing from %v", want, dirs)
		}
	}
	if clinePathInList(dirs, explicit) {
		t.Fatalf("unreliable CLINE_HOOKS_DIR must not imply activation: %v", dirs)
	}
}

func clinePathInList(paths []string, want string) bool {
	want = filepath.Clean(want)
	for _, path := range paths {
		if filepath.Clean(path) == want {
			return true
		}
	}
	return false
}

func TestVerifyClineHooksChecksCurrentContentAndActivation(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hookDir := clineUserHooksDir(home)
	paths, _, err := installClineHooks(hookDir, "rampart", runtime.GOOS, false)
	if err != nil {
		t.Fatal(err)
	}
	if check := verifyClineHooksInstalled(); check.Status != verificationPass || check.Actual != hookDir {
		t.Fatalf("installed check = %#v", check)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(paths[0], 0o644); err != nil {
			t.Fatal(err)
		}
		if check := verifyClineHooksInstalled(); check.Status != verificationFail || !strings.Contains(check.Actual, "not executable") {
			t.Fatalf("disabled check = %#v", check)
		}
	}
}

func TestVerifyClineHooksDoesNotClaimAdvertisedOverrideIsActive(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	explicit := filepath.Join(t.TempDir(), "hooks")
	if _, _, err := installClineHooks(explicit, "rampart", runtime.GOOS, false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLINE_HOOKS_DIR", explicit)

	check := verifyClineHooksInstalled()
	if check.Status != verificationUnverified || check.Actual != explicit {
		t.Fatalf("explicit override check = %#v", check)
	}
	if !strings.Contains(check.Message, "without consuming it reliably") {
		t.Fatalf("explicit override limitation was not reported: %#v", check)
	}
}

func createLegacyClineHookForTest(event string) string {
	return "#!/bin/bash\n# Rampart " + event + " hook for Cline\nexec rampart hook --format cline\n"
}
