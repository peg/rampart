// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/policies"
)

func TestUpgradeInstruction(t *testing.T) {
	tests := []struct{ goos, exe, want string }{
		{"darwin", "/opt/homebrew/Cellar/rampart/1.11.1/bin/rampart", "brew upgrade peg/tap/rampart"},
		{"linux", "/home/linuxbrew/.linuxbrew/bin/rampart", "brew upgrade peg/tap/rampart"},
		{"windows", `C:\Users\me\.rampart\bin\rampart.exe`, "irm https://rampart.sh/install.ps1 | iex"},
		{"linux", "/usr/local/bin/rampart", "curl -fsSL https://rampart.sh/install | sh"},
	}
	for _, tt := range tests {
		if got := upgradeInstruction(tt.goos, tt.exe); got != tt.want {
			t.Errorf("upgradeInstruction(%q, %q) = %q, want %q", tt.goos, tt.exe, got, tt.want)
		}
	}
}

func TestUpgradePrintsInstructionWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	var out bytes.Buffer
	cmd := newUpgradeCmd(&rootOptions{})
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(out.String(), "To upgrade Rampart, run:") {
		t.Fatalf("missing upgrade instruction: %q", out.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("upgrade wrote files: %v", entries)
	}
}

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

func TestUpgradeNoBinaryRefreshesStockPolicy(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	standardPath := filepath.Join(policyDir, "standard.yaml")
	standard, err := policies.Profile("standard")
	if err != nil {
		t.Fatalf("embedded standard profile: %v", err)
	}
	if err := os.WriteFile(standardPath, standard, 0o644); err != nil {
		t.Fatalf("write stock policy: %v", err)
	}

	var out bytes.Buffer
	cmd := newUpgradeCmd(&rootOptions{})
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--no-binary"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	got, err := os.ReadFile(standardPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if bytes.Equal(got, standard) {
		t.Fatal("expected stock policy to be rewritten with a version stamp")
	}
	if !bytes.HasPrefix(got, []byte("# rampart-policy-version: ")) {
		snippet := string(got)
		if len(snippet) > 40 {
			snippet = snippet[:40]
		}
		t.Fatalf("expected version stamp after refresh, got %q", snippet)
	}
}

func TestUpgradeNoBinaryPreservesModifiedBuiltInPolicy(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	standardPath := filepath.Join(policyDir, "standard.yaml")
	standard, err := policies.Profile("standard")
	if err != nil {
		t.Fatalf("embedded standard profile: %v", err)
	}
	modified := append([]byte("# rampart-policy-version: "+build.Version+"\n"), standard...)
	modified = append(modified, []byte("\n# local customization\n")...)
	if err := os.WriteFile(standardPath, modified, 0o644); err != nil {
		t.Fatalf("write modified policy: %v", err)
	}

	var out bytes.Buffer
	cmd := newUpgradeCmd(&rootOptions{})
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--no-binary"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	got, err := os.ReadFile(standardPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !bytes.Equal(got, modified) {
		t.Fatal("expected modified built-in policy to be preserved")
	}
	if !strings.Contains(out.String(), "Preserved modified: standard.yaml") {
		t.Fatalf("expected preserved-modified output, got %q", out.String())
	}
}

func TestUpgradeStandardPoliciesMigratesStaleLegacyWithBackup(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	standardPath := filepath.Join(policyDir, "standard.yaml")
	standard, err := policies.Profile("standard")
	if err != nil {
		t.Fatalf("embedded standard profile: %v", err)
	}
	stale := append([]byte("# rampart-policy-version: 0.0.1\n"), standard...)
	if err := os.WriteFile(standardPath, stale, 0o644); err != nil {
		t.Fatalf("write stale policy: %v", err)
	}

	var out bytes.Buffer
	if err := upgradeStandardPoliciesForVersion(&out, false, "v1.2.3"); err != nil {
		t.Fatalf("upgradeStandardPoliciesForVersion returned error: %v", err)
	}

	got, err := os.ReadFile(standardPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	want := versionStampedPolicyContentForVersion(standard, "v1.2.3")
	if !bytes.Equal(got, want) {
		t.Fatal("expected stale built-in policy to be migrated to current managed content")
	}
	backupPath := standardPath + ".rampart-backup-0.0.1"
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read legacy backup: %v", err)
	}
	if !bytes.Equal(backup, stale) {
		t.Fatal("expected backup to preserve the exact legacy policy")
	}
	if !strings.Contains(out.String(), "Backed up legacy: standard.yaml") {
		t.Fatalf("expected legacy backup output, got %q", out.String())
	}
}

func TestUpgradeStandardPoliciesUpdatesBuiltIns(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir policy dir: %v", err)
	}

	standardPath := filepath.Join(policyDir, "standard.yaml")
	blockPath := filepath.Join(policyDir, "block-prompt-injection.yaml")
	stockStandard, err := policies.Profile("standard")
	if err != nil {
		t.Fatalf("load standard profile: %v", err)
	}
	stockBlock, err := policies.Profile("block-prompt-injection")
	if err != nil {
		t.Fatalf("load block-prompt-injection profile: %v", err)
	}
	if err := os.WriteFile(standardPath, stockStandard, 0o644); err != nil {
		t.Fatalf("write standard: %v", err)
	}
	if err := os.WriteFile(blockPath, stockBlock, 0o644); err != nil {
		t.Fatalf("write block-prompt-injection: %v", err)
	}

	var out bytes.Buffer
	if err := upgradeStandardPolicies(&out, false); err != nil {
		t.Fatalf("upgradeStandardPolicies: %v", err)
	}

	standardPayload, err := os.ReadFile(standardPath)
	if err != nil {
		t.Fatalf("read standard: %v", err)
	}
	blockPayload, err := os.ReadFile(blockPath)
	if err != nil {
		t.Fatalf("read block-prompt-injection: %v", err)
	}

	wantStandard, err := policies.Profile("standard")
	if err != nil {
		t.Fatalf("load standard profile: %v", err)
	}
	wantBlock, err := policies.Profile("block-prompt-injection")
	if err != nil {
		t.Fatalf("load block-prompt-injection profile: %v", err)
	}

	// Written files now have a version stamp prepended — check content after the stamp line.
	if !bytes.Contains(standardPayload, wantStandard) {
		t.Fatal("standard.yaml was not updated to the embedded profile")
	}
	if !bytes.Contains(blockPayload, wantBlock) {
		t.Fatal("block-prompt-injection.yaml was not updated to the embedded profile")
	}

	if !strings.Contains(out.String(), "Updated: block-prompt-injection.yaml, standard.yaml") {
		t.Fatalf("missing updated summary line: %q", out.String())
	}
}

func TestUpgradeStandardPoliciesNoBuiltInsFound(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir policy dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "custom.yaml"), []byte("version: \"1\"\n"), 0o644); err != nil {
		t.Fatalf("write custom policy: %v", err)
	}

	var out bytes.Buffer
	if err := upgradeStandardPolicies(&out, false); err != nil {
		t.Fatalf("upgradeStandardPolicies: %v", err)
	}
	if !strings.Contains(out.String(), "no built-in policy files found") {
		t.Fatalf("expected no-built-ins message, got %q", out.String())
	}
}
