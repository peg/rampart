package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestNewUpgradeCmdDryRun(t *testing.T) {
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
