// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
)

// rampartDir returns the path to the ~/.rampart directory.
func rampartDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".rampart"), nil
}
