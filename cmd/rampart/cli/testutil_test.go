package cli

import (
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
}

// skipOnWindows skips the test on Windows with the given reason.
func skipOnWindows(t *testing.T, reason string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("skipping on Windows: %s", reason)
	}
}
