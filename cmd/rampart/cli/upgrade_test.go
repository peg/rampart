package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/peg/rampart/policies"
)

// testArchiveName returns the archive filename for the current platform (e.g., rampart_1.1.0_darwin_arm64.tar.gz).
func testArchiveName(version string) string {
	goos, arch, _ := upgradePlatform(runtime.GOOS, runtime.GOARCH)
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("rampart_%s_%s_%s.%s", version, goos, arch, ext)
}

func TestLookupSHA256(t *testing.T) {
	sums := []byte("abc123 def\n" + strings.Repeat("a", 64) + "  rampart_1.2.3_linux_amd64.tar.gz\n")
	got, err := lookupSHA256(sums, "rampart_1.2.3_linux_amd64.tar.gz")
	if err != nil {
		t.Fatalf("lookupSHA256 returned error: %v", err)
	}
	if got != strings.Repeat("a", 64) {
		t.Fatalf("unexpected hash: %s", got)
	}
}

func TestExtractRampartBinary(t *testing.T) {
	archive := makeArchive(t, "rampart", []byte("binary-data"))
	got, err := extractRampartBinary(archive)
	if err != nil {
		t.Fatalf("extractRampartBinary returned error: %v", err)
	}
	if string(got) != "binary-data" {
		t.Fatalf("unexpected payload: %q", string(got))
	}
}

// TestExtractRampartBinary_GoreleaserLayout tests the real goreleaser archive
// format which bundles LICENSE and README.md alongside the binary.
// Regression test for: "archive contains 4 files; expected a single binary"
func TestExtractRampartBinary_GoreleaserLayout(t *testing.T) {
	// Mimic actual goreleaser archive layout (flat, no subdirectory prefix):
	//   rampart        ← the binary
	//   LICENSE
	//   README.md
	//   CHANGELOG.md
	archive := makeMultiFileArchive(t, map[string][]byte{
		"rampart":      []byte("real-binary"),
		"LICENSE":      []byte("Apache 2.0"),
		"README.md":    []byte("# Rampart"),
		"CHANGELOG.md": []byte("## v0.4.4"),
	})
	got, err := extractRampartBinary(archive)
	if err != nil {
		t.Fatalf("extractRampartBinary failed on goreleaser layout: %v", err)
	}
	if string(got) != "real-binary" {
		t.Fatalf("unexpected payload: %q", string(got))
	}
}

func makeMultiFileArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, payload := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(payload)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write(payload); err != nil {
			t.Fatalf("write payload %s: %v", name, err)
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

func TestNewUpgradeCmdAlreadyLatest(t *testing.T) {
	deps := &upgradeDeps{
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.2.3", nil
		},
		latestRelease: func(context.Context, *http.Client, string) (string, error) {
			return "v1.2.3", nil
		},
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(out.String(), "Already on latest (v1.2.3)") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestNewUpgradeCmdAlreadyLatestStillRefreshesStockPolicy(t *testing.T) {
	// Regression test: when already on latest, upgrade should still refresh
	// a stock installed policy so it picks up version stamping and embedded changes.
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

	deps := &upgradeDeps{
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.2.3", nil
		},
		latestRelease: func(context.Context, *http.Client, string) (string, error) {
			return "v1.2.3", nil
		},
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--yes"})
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

func TestNewUpgradeCmdPreservesModifiedBuiltInPolicy(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	standardPath := filepath.Join(policyDir, "standard.yaml")
	modified := []byte("# rampart-policy-version: 0.9.19\nversion: \"1\"\npolicies:\n  - name: local-rule\n")
	if err := os.WriteFile(standardPath, modified, 0o644); err != nil {
		t.Fatalf("write modified policy: %v", err)
	}

	deps := &upgradeDeps{
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.2.3", nil
		},
		latestRelease: func(context.Context, *http.Client, string) (string, error) {
			return "v1.2.3", nil
		},
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--yes"})
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

func TestNewUpgradeCmdDryRun(t *testing.T) {
	skipOnWindows(t, "upgrade not supported on Windows")
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	deps := &upgradeDeps{
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.0.0", nil
		},
		executablePath: func() (string, error) { return exe, nil },
		inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
			return 1234, true, nil
		},
		detectSystemdService: func(commandRunner) string { return "" },
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--dry-run", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "would download") || !strings.Contains(got, "would restart rampart serve") {
		t.Fatalf("dry-run output missing expected lines: %q", got)
	}
}

func TestNewUpgradeCmdDryRunSystemd(t *testing.T) {
	skipOnWindows(t, "upgrade not supported on Windows")
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	deps := &upgradeDeps{
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.0.0", nil
		},
		executablePath: func() (string, error) { return exe, nil },
		inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
			return 0, false, nil
		},
		detectSystemdService: func(commandRunner) string { return "rampart-proxy.service" },
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--dry-run", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "would restart systemd service: rampart-proxy.service") {
		t.Fatalf("dry-run output missing systemd restart line: %q", got)
	}
}

func TestNewUpgradeCmdSuccessNoServe(t *testing.T) {
	skipOnWindows(t, "upgrade not supported on Windows")
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	archive := makeArchive(t, "rampart", []byte("new-binary"))
	sum := sha256.Sum256(archive)
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + testArchiveName("1.1.0") + "\n")

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
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes", "--no-policy-update"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if !strings.Contains(out.String(), "✓ rampart upgraded to v1.1.0") {
		t.Fatalf("missing success line: %q", out.String())
	}
}

func TestNewUpgradeCmdSystemdRestart(t *testing.T) {
	skipOnWindows(t, "upgrade not supported on Windows")
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	archive := makeArchive(t, "rampart", []byte("new-binary"))
	sum := sha256.Sum256(archive)
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + testArchiveName("1.1.0") + "\n")

	var restarted string
	deps := &upgradeDeps{
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.0.0", nil
		},
		executablePath: func() (string, error) { return exe, nil },
		inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
			return 0, false, nil
		},
		detectSystemdService: func(commandRunner) string { return "rampart-proxy.service" },
		restartSystemdService: func(_ commandRunner, svc string, out io.Writer) error {
			restarted = svc
			fmt.Fprintf(out, "✓ restarted %s\n", svc)
			return nil
		},
		downloadURL: func(_ context.Context, _ *http.Client, url string) ([]byte, error) {
			if strings.HasSuffix(url, "checksums.txt") {
				return checksums, nil
			}
			return archive, nil
		},
		pathEnv: func() string { return "" },
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes", "--no-policy-update"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "✓ rampart upgraded to v1.1.0") {
		t.Fatalf("missing success line: %q", got)
	}
	if restarted != "rampart-proxy.service" {
		t.Fatalf("expected systemd restart of rampart-proxy.service, got %q", restarted)
	}
	if !strings.Contains(got, "✓ restarted rampart-proxy.service") {
		t.Fatalf("missing restarted confirmation: %q", got)
	}
}

func TestNewUpgradeCmdSystemdTakesPriorityOverPID(t *testing.T) {
	skipOnWindows(t, "upgrade not supported on Windows")
	// If both a PID file AND a systemd service exist, systemd wins.
	dir := t.TempDir()
	exe := filepath.Join(dir, "rampart")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	archive := makeArchive(t, "rampart", []byte("new-binary"))
	sum := sha256.Sum256(archive)
	checksums := []byte(hex.EncodeToString(sum[:]) + "  " + testArchiveName("1.1.0") + "\n")

	pidStopped := false
	var restarted string
	deps := &upgradeDeps{
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) {
			return "v1.0.0", nil
		},
		executablePath: func() (string, error) { return exe, nil },
		inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
			return 9999, true, nil // PID file exists
		},
		stopServe: func(int) error {
			pidStopped = true
			return nil
		},
		detectSystemdService: func(commandRunner) string { return "rampart-serve.service" },
		restartSystemdService: func(_ commandRunner, svc string, out io.Writer) error {
			restarted = svc
			return nil
		},
		downloadURL: func(_ context.Context, _ *http.Client, url string) ([]byte, error) {
			if strings.HasSuffix(url, "checksums.txt") {
				return checksums, nil
			}
			return archive, nil
		},
		pathEnv: func() string { return "" },
	}

	var out bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, deps)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v1.1.0", "--yes", "--no-policy-update"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if pidStopped {
		t.Fatal("expected PID-based stop to be skipped when systemd service is active")
	}
	if restarted != "rampart-serve.service" {
		t.Fatalf("expected systemd restart, got %q", restarted)
	}
}

func makeArchive(t *testing.T, name string, payload []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(payload))}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
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

func TestFindRequireApprovalUsages(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir policy dir: %v", err)
	}
	customPath := filepath.Join(policyDir, "custom.yaml")
	if err := os.WriteFile(customPath, []byte(`
version: "1"
default_action: deny
policies:
  - name: approve-deploys
    match:
      tool: exec
    rules:
      - action: require_approval
        when:
          command_matches: ["kubectl apply **"]
        message: "approve deploys"
`), 0o644); err != nil {
		t.Fatalf("write custom policy: %v", err)
	}

	usages, err := findRequireApprovalUsages(os.UserHomeDir)
	if err != nil {
		t.Fatalf("findRequireApprovalUsages: %v", err)
	}
	if len(usages) != 1 {
		t.Fatalf("expected 1 usage, got %d: %#v", len(usages), usages)
	}
	if usages[0].FilePath != "~/.rampart/policies/custom.yaml" {
		t.Fatalf("unexpected file path: %q", usages[0].FilePath)
	}
	if usages[0].PolicyName != "approve-deploys" {
		t.Fatalf("unexpected policy name: %q", usages[0].PolicyName)
	}
}

func TestMaybeWarnRequireApprovalMigration(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	policyDir := filepath.Join(dir, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir policy dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "custom.yaml"), []byte(`
version: "1"
default_action: deny
policies:
  - name: approve-deploys
    match:
      tool: exec
    rules:
      - action: require_approval
        when:
          command_matches: ["kubectl apply **"]
        message: "approve deploys"
`), 0o644); err != nil {
		t.Fatalf("write custom policy: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if err := maybeWarnRequireApprovalMigration(&out, &errOut, strings.NewReader(""), true, os.UserHomeDir); err != nil {
		t.Fatalf("maybeWarnRequireApprovalMigration: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "⚠️  Migration notice for v0.6.6:") {
		t.Fatalf("missing migration header: %q", got)
	}
	if !strings.Contains(got, "~/.rampart/policies/custom.yaml (policy: \"approve-deploys\")") {
		t.Fatalf("missing policy usage line: %q", got)
	}
	if !strings.Contains(got, "action: ask + ask.headless_only: true") {
		t.Fatalf("missing migration target guidance: %q", got)
	}
	if !strings.Contains(errOut.String(), "continuing automatically") {
		t.Fatalf("missing non-interactive continuation note: %q", errOut.String())
	}
}

// makeZipArchive builds an in-memory zip archive containing the given files.
func makeZipArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, payload := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestExtractRampartBinaryFromZip(t *testing.T) {
	archive := makeZipArchive(t, map[string][]byte{
		"rampart.exe": []byte("windows-binary"),
	})
	got, err := extractRampartBinaryFromZip(archive)
	if err != nil {
		t.Fatalf("extractRampartBinaryFromZip returned error: %v", err)
	}
	if string(got) != "windows-binary" {
		t.Fatalf("unexpected payload: %q", string(got))
	}
}

// TestExtractRampartBinaryFromZip_GoreleaserLayout tests the real goreleaser
// zip layout where the binary lives in a versioned subdirectory.
func TestExtractRampartBinaryFromZip_GoreleaserLayout(t *testing.T) {
	// Goreleaser produces: rampart_0.7.1_windows_amd64/rampart.exe
	archive := makeZipArchive(t, map[string][]byte{
		"rampart_0.7.1_windows_amd64/rampart.exe": []byte("real-windows-binary"),
		"rampart_0.7.1_windows_amd64/LICENSE":     []byte("Apache 2.0"),
		"rampart_0.7.1_windows_amd64/README.md":   []byte("# Rampart"),
	})
	got, err := extractRampartBinaryFromZip(archive)
	if err != nil {
		t.Fatalf("extractRampartBinaryFromZip failed on goreleaser layout: %v", err)
	}
	if string(got) != "real-windows-binary" {
		t.Fatalf("unexpected payload: %q", string(got))
	}
}

func TestExtractRampartBinaryFromZip_NotFound(t *testing.T) {
	archive := makeZipArchive(t, map[string][]byte{
		"LICENSE":   []byte("Apache 2.0"),
		"README.md": []byte("# Rampart"),
	})
	_, err := extractRampartBinaryFromZip(archive)
	if err == nil {
		t.Fatal("expected error when rampart.exe not in archive, got nil")
	}
	if !strings.Contains(err.Error(), "rampart.exe not found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
