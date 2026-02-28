//go:build windows

package cli

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
)

// secureFilePermissions sets owner-only access on Windows using icacls.
// This removes inherited permissions and grants full control only to the current user.
func secureFilePermissions(path string) error {
	return setOwnerOnlyAccess(path)
}

// secureDirPermissions sets owner-only access on Windows using icacls.
func secureDirPermissions(path string) error {
	return setOwnerOnlyAccess(path)
}

func setOwnerOnlyAccess(path string) error {
	// Get current username
	currentUser, err := user.Current()
	if err != nil {
		// Fall back to no-op on error
		return nil
	}

	// icacls commands:
	// /inheritance:r - Remove inherited permissions
	// /grant:r USER:F - Replace with full control for current user only
	//
	// This is equivalent to: only the current user can read/write the file.
	cmd := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", fmt.Sprintf("%s:F", currentUser.Username),
	)
	
	// Suppress output - we only care about the exit code
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		// If icacls fails, fall back to os.Chmod (no-op on Windows, but doesn't error).
		// Warn because the file may have overly permissive inherited permissions.
		slog.Warn("token: icacls failed, file permissions may be too permissive", "path", path, "err", err)
		return os.Chmod(path, 0o600)
	}

	return nil
}
