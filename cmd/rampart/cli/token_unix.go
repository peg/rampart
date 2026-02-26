//go:build !windows

package cli

import "os"

// secureFilePermissions sets the file to owner-only access (0600).
// On Unix systems, this uses standard chmod.
func secureFilePermissions(path string) error {
	return os.Chmod(path, 0o600)
}

// secureDirPermissions sets the directory to owner-only access (0700).
// On Unix systems, this uses standard chmod.
func secureDirPermissions(path string) error {
	return os.Chmod(path, 0o700)
}
