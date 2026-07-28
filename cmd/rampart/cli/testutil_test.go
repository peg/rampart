package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
)

// testSetHome overrides the home directory for testing.
// On Windows, os.UserHomeDir() checks USERPROFILE before HOME.
func testSetHome(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
	t.Setenv("HOME", dir)
	t.Setenv("CODEX_HOME", "")
}

// skipOnWindows skips the test on Windows with the given reason.
func skipOnWindows(t *testing.T, reason string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("skipping on Windows: %s", reason)
	}
}

// testExecuteRoot runs an isolated root command when a test only needs its
// success or failure. Tests that assert command output should construct the
// command directly with their own buffers.
func testExecuteRoot(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs(args)
	return cmd.Execute()
}

func testReadJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
