// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

// Package securefile applies platform-native owner-only access controls to
// files containing Rampart secrets or authorization state.
package securefile

import (
	"fmt"
	"os"
)

// OwnerOnly restricts path to the current Unix owner (0600).
func OwnerOnly(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure file for owner-only access: %w", err)
	}
	return nil
}
