//go:build !windows

package cli

import (
	"os"

	"github.com/peg/rampart/internal/securefile"
)

var secureOwnerOnlyFile = securefile.OwnerOnly

// secureFilePermissions sets the file to owner-only access (0600).
// On Unix systems, this uses standard chmod.
func secureFilePermissions(path string) error {
	return secureOwnerOnlyFile(path)
}

// secureDirPermissions sets the directory to owner-only access (0700).
// On Unix systems, this uses standard chmod.
func secureDirPermissions(path string) error {
	return os.Chmod(path, 0o700)
}

// Unix directory permissions never used the affected Windows ACL path.
func ensureRampartDirAccessible(string) error {
	return nil
}
