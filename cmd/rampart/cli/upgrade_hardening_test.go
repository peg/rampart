// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/policies"
)

func TestCompareSemverPrereleaseOrdering(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"v1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0+build.1", "1.0.0+build.2", 0},
		{"12345678901234567890.0.0", "9999999999999999999.0.0", 1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got, ok := compareStrictSemver(tt.a, tt.b)
			if !ok {
				t.Fatalf("versions should parse: %q, %q", tt.a, tt.b)
			}
			if got != tt.want {
				t.Fatalf("compareStrictSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			if reverse, ok := compareStrictSemver(tt.b, tt.a); !ok || reverse != -tt.want {
				t.Fatalf("reverse comparison = (%d, %t), want (%d, true)", reverse, ok, -tt.want)
			}
		})
	}
}

func TestNormalizeVersionStrictSemver(t *testing.T) {
	valid := map[string]string{
		"1.2.3":                   "v1.2.3",
		"v1.2.3-rc.2+build.17":    "v1.2.3-rc.2+build.17",
		"  10.20.30-alpha.beta  ": "v10.20.30-alpha.beta",
	}
	for input, want := range valid {
		got, err := normalizeVersion(input)
		if err != nil || got != want {
			t.Errorf("normalizeVersion(%q) = (%q, %v), want (%q, nil)", input, got, err, want)
		}
	}

	invalid := []string{
		"1.2", "1.2.3.4", "1.02.3", "1.2.3-01", "1.2.3-", "1.2.3+",
		"1.2.3-alpha..one", "1.2.3-alpha!", "vv1.2.3",
	}
	for _, input := range invalid {
		if got, err := normalizeVersion(input); err == nil {
			t.Errorf("normalizeVersion(%q) = %q, want error", input, got)
		}
	}
}

func TestUpgradePayloadBounds(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		if _, err := readAllBounded(strings.NewReader("12345"), 4); err == nil {
			t.Fatal("expected an oversized stream to be rejected")
		}
	})

	t.Run("tar binary", func(t *testing.T) {
		archive := makeArchive(t, "rampart", []byte("12345"))
		if _, err := extractRampartBinaryWithLimits(archive, 4, 100); err == nil || !strings.Contains(err.Error(), "binary exceeds") {
			t.Fatalf("expected binary size error, got %v", err)
		}
	})

	t.Run("tar expanded", func(t *testing.T) {
		archive := makeMultiFileArchive(t, map[string][]byte{
			"rampart": []byte("1234"),
			"LICENSE": []byte("5678"),
		})
		if _, err := extractRampartBinaryWithLimits(archive, 10, 7); err == nil || !strings.Contains(err.Error(), "expanded archive exceeds") {
			t.Fatalf("expected expanded size error, got %v", err)
		}
	})

	t.Run("tar entries", func(t *testing.T) {
		archive := makeArchiveWithEmptyEntries(t, maxUpgradeArchiveFiles+1)
		if _, err := extractRampartBinary(archive); err == nil || !strings.Contains(err.Error(), "entries") {
			t.Fatalf("expected entry count error, got %v", err)
		}
	})

}

func TestDownloadURLRejectsDeclaredOversize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(maxUpgradeDownloadBytes+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := downloadURL(context.Background(), server.Client(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("expected declared size error, got %v", err)
	}
}

func makeArchiveWithEmptyEntries(t *testing.T, count int) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := 0; i < count; i++ {
		if err := tw.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("entry-%04d", i),
			Mode:     0o644,
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func TestUpgradeWindowsRequiresInstallerBeforeMutation(t *testing.T) {
	versionChecked := false
	policyUpdated := false
	deps := &upgradeDeps{
		goos: "windows",
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			versionChecked = true
			return "v1.0.0", nil
		},
		updatePolicies: func(io.Writer, bool) error {
			policyUpdated = true
			return nil
		},
	}

	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "install.ps1") {
		t.Fatalf("expected Windows installer guidance, got %v", err)
	}
	if versionChecked || policyUpdated {
		t.Fatalf("Windows refusal must happen before version lookup or mutation (version=%t policy=%t)", versionChecked, policyUpdated)
	}

	cmd = newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--no-binary"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("policy-only Windows refresh returned error: %v", err)
	}
	if !policyUpdated {
		t.Fatal("expected --no-binary to remain available on Windows")
	}
}

func TestValidateSelfUpgradePathRejectsManagedAndSymlinkedExecutables(t *testing.T) {
	target := filepath.Join(t.TempDir(), "rampart-real")
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}

	t.Run("Homebrew", func(t *testing.T) {
		deps := defaultUpgradeDeps()
		deps.lstat = func(string) (os.FileInfo, error) { return info, nil }
		for _, path := range []string{
			"/opt/homebrew/bin/rampart",
			"/usr/local/Cellar/rampart/1.4.0/bin/rampart",
			"/home/linuxbrew/.linuxbrew/Cellar/rampart/1.4.0/bin/rampart",
		} {
			err := validateSelfUpgradePath(path, deps)
			if err == nil || !strings.Contains(err.Error(), "brew upgrade") {
				t.Fatalf("expected Homebrew guidance for %s, got %v", path, err)
			}
		}
	})

	t.Run("symlink", func(t *testing.T) {
		skipOnWindows(t, "creating symlinks can require elevated Windows privileges")
		link := filepath.Join(t.TempDir(), "rampart")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		deps := &upgradeDeps{
			currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
				return "v1.0.0", nil
			},
			executablePath: func() (string, error) { return link, nil },
			inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
				t.Fatal("serve inspection must not run for an unsafe executable path")
				return 0, false, nil
			},
			downloadURL: func(context.Context, *http.Client, string) ([]byte, error) {
				t.Fatal("download must not run for an unsafe executable path")
				return nil, nil
			},
		}
		cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"v1.1.0", "--yes"})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "refusing to replace symlinked executable") {
			t.Fatalf("expected symlink refusal, got %v", err)
		}
	})
}

func TestUpgradeRefreshesPoliciesAfterInstallingNewBinary(t *testing.T) {
	skipOnWindows(t, "binary self-upgrade intentionally uses the Windows installer")
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write old executable: %v", err)
	}

	archive := makeArchive(t, "rampart", []byte("new-binary"))
	sum := sha256.Sum256(archive)
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + testArchiveName("1.1.0") + "\n")
	refreshed := false
	deps := &upgradeDeps{
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.0.0", nil
		},
		executablePath: func() (string, error) { return exe, nil },
		inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
			return 0, false, nil
		},
		detectSystemdService: func(commandRunner) string { return "" },
		downloadURL: func(_ context.Context, _ *http.Client, url string) ([]byte, error) {
			if strings.HasSuffix(url, "checksums.txt") {
				return checksums, nil
			}
			return archive, nil
		},
		pathEnv: func() string { return "" },
		updatePolicies: func(io.Writer, bool) error {
			t.Fatal("old-process policy updater must not run after binary replacement")
			return nil
		},
		refreshPolicies: func(_ commandRunner, binary string, _, _ io.Writer) error {
			refreshed = true
			if binary != exe {
				t.Fatalf("policy refresh binary = %q, want %q", binary, exe)
			}
			installed, err := os.ReadFile(binary)
			if err != nil {
				return err
			}
			if string(installed) != "new-binary" {
				t.Fatalf("policy refresh observed %q, want newly installed binary", installed)
			}
			return nil
		},
	}

	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !refreshed {
		t.Fatal("expected policies to be refreshed after installation")
	}
}

func TestFixStalePathCopiesDoesNotReplaceHomebrewBinary(t *testing.T) {
	skipOnWindows(t, "Homebrew path layout is Unix-specific")
	dir := t.TempDir()
	installed := filepath.Join(dir, "rampart")
	if err := os.WriteFile(installed, []byte("current"), 0o755); err != nil {
		t.Fatalf("write installed binary: %v", err)
	}
	installedInfo, err := os.Stat(installed)
	if err != nil {
		t.Fatalf("stat installed binary: %v", err)
	}
	link := filepath.Join(dir, "homebrew-link")
	if err := os.Symlink(installed, link); err != nil {
		t.Fatalf("create test symlink: %v", err)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat test symlink: %v", err)
	}
	candidate := "/usr/local/bin/rampart"
	deps := defaultUpgradeDeps()
	deps.pathEnv = func() string { return "/usr/local/bin" }
	deps.stat = func(path string) (os.FileInfo, error) {
		if path == installed {
			return installedInfo, nil
		}
		t.Fatalf("package-managed candidate reached mutation stat: %s", path)
		return nil, os.ErrNotExist
	}
	deps.lstat = func(path string) (os.FileInfo, error) {
		if path != candidate {
			t.Fatalf("unexpected lstat path: %s", path)
		}
		return linkInfo, nil
	}
	deps.evalSymlinks = func(path string) (string, error) {
		if path == candidate {
			return "/usr/local/Cellar/rampart/1.3.0/bin/rampart", nil
		}
		return path, nil
	}

	var out bytes.Buffer
	fixStalePathCopies(&out, installed, deps)
	if !strings.Contains(out.String(), "left package-managed rampart unchanged") {
		t.Fatalf("missing package-manager preservation notice: %q", out.String())
	}
}

func TestRefreshPoliciesWithInstalledBinaryArguments(t *testing.T) {
	var gotName string
	var gotArgs []string
	runner := func(name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.Command(os.Args[0], "-test.run=^$")
	}
	if err := refreshPoliciesWithInstalledBinary(runner, "/new/rampart", io.Discard, io.Discard); err != nil {
		t.Fatalf("refreshPoliciesWithInstalledBinary returned error: %v", err)
	}
	if gotName != "/new/rampart" || strings.Join(gotArgs, " ") != "upgrade --no-binary" {
		t.Fatalf("runner called with %q %q", gotName, gotArgs)
	}
}

func TestInitBuiltInWritesManagedPolicyProvenance(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	configPath := filepath.Join(dir, "rampart.yaml")

	root := NewRootCmd(context.Background(), io.Discard, io.Discard)
	root.SetArgs([]string{"init", "--config", configPath, "--profile", "standard"})
	if err := root.Execute(); err != nil {
		t.Fatalf("init returned error: %v", err)
	}

	policyPath := filepath.Join(dir, ".rampart", "policies", "standard.yaml")
	state, err := builtInPolicyState(policyPath)
	if err != nil {
		t.Fatalf("builtInPolicyState returned error: %v", err)
	}
	if !state.HasVersionStamp || !state.HasContentHash || !state.ContentHashMatches || !state.MatchesCurrent {
		t.Fatalf("fresh init lacks managed provenance: %+v", state)
	}
}

func TestManagedPolicyHashPreservesEditsAndUpdatesManagedContent(t *testing.T) {
	standard, err := policies.Profile("standard")
	if err != nil {
		t.Fatalf("load standard profile: %v", err)
	}

	t.Run("edited", func(t *testing.T) {
		dir := t.TempDir()
		testSetHome(t, dir)
		policyDir := filepath.Join(dir, ".rampart", "policies")
		if err := os.MkdirAll(policyDir, 0o755); err != nil {
			t.Fatalf("mkdir policy dir: %v", err)
		}
		path := filepath.Join(policyDir, "standard.yaml")
		edited := append(versionStampedPolicyContentForVersion(standard, "v1.0.0"), []byte("\n# local edit\n")...)
		if err := os.WriteFile(path, edited, 0o600); err != nil {
			t.Fatalf("write edited policy: %v", err)
		}

		var out bytes.Buffer
		if err := upgradeStandardPoliciesForVersion(&out, false, "v1.1.0"); err != nil {
			t.Fatalf("upgrade policies: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read policy: %v", err)
		}
		if !bytes.Equal(got, edited) {
			t.Fatal("hash-mismatched local edit was overwritten")
		}
		if !strings.Contains(out.String(), "Preserved modified: standard.yaml") {
			t.Fatalf("missing preservation notice: %q", out.String())
		}
	})

	t.Run("managed stale", func(t *testing.T) {
		dir := t.TempDir()
		testSetHome(t, dir)
		policyDir := filepath.Join(dir, ".rampart", "policies")
		if err := os.MkdirAll(policyDir, 0o755); err != nil {
			t.Fatalf("mkdir policy dir: %v", err)
		}
		path := filepath.Join(policyDir, "standard.yaml")
		if err := os.WriteFile(path, versionStampedPolicyContentForVersion(standard, "v1.0.0"), 0o600); err != nil {
			t.Fatalf("write managed policy: %v", err)
		}
		if err := upgradeStandardPoliciesForVersion(io.Discard, false, "v1.1.0"); err != nil {
			t.Fatalf("upgrade policies: %v", err)
		}
		state, err := builtInPolicyStateForVersion(path, "v1.1.0")
		if err != nil {
			t.Fatalf("read managed state: %v", err)
		}
		if state.VersionStamp != "v1.1.0" || !state.ContentHashMatches || !state.MatchesCurrent {
			t.Fatalf("managed policy not refreshed: %+v", state)
		}
		backups, err := filepath.Glob(path + ".rampart-backup-*")
		if err != nil {
			t.Fatalf("glob backups: %v", err)
		}
		if len(backups) != 0 {
			t.Fatalf("hash-proven managed policy should not need a legacy backup: %v", backups)
		}
	})
}

func TestUpgradePreservesSymlinkedBuiltInPolicy(t *testing.T) {
	skipOnWindows(t, "creating symlinks can require elevated Windows privileges")
	dir := t.TempDir()
	testSetHome(t, dir)
	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir policy dir: %v", err)
	}
	external := filepath.Join(dir, "external-standard.yaml")
	original := []byte("version: \"1\"\npolicies: []\n")
	if err := os.WriteFile(external, original, 0o600); err != nil {
		t.Fatalf("write external policy: %v", err)
	}
	policyPath := filepath.Join(policyDir, "standard.yaml")
	if err := os.Symlink(external, policyPath); err != nil {
		t.Fatalf("symlink policy: %v", err)
	}

	var out bytes.Buffer
	if err := upgradeStandardPoliciesForVersion(&out, false, "v1.1.0"); err != nil {
		t.Fatalf("upgrade policies: %v", err)
	}
	info, err := os.Lstat(policyPath)
	if err != nil {
		t.Fatalf("lstat policy: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlinked policy path was replaced")
	}
	got, err := os.ReadFile(external)
	if err != nil {
		t.Fatalf("read external policy: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("external symlink target was modified")
	}
	if !strings.Contains(out.String(), "preserved non-regular policy path") {
		t.Fatalf("missing symlink preservation notice: %q", out.String())
	}
}
