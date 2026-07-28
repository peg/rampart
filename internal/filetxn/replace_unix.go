// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

package filetxn

import (
	"os"
	"path/filepath"
)

// Replace atomically replaces destinationPath with sourcePath and persists the
// containing directory entry.
func Replace(sourcePath, destinationPath string) error {
	if err := os.Rename(sourcePath, destinationPath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(destinationPath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
