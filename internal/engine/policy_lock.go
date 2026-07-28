// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package engine

import (
	"github.com/peg/rampart/internal/filetxn"
)

// withPolicyFileLock serializes a read-modify-write transaction both within
// this process and across Rampart processes. The lock lives in a stable
// sidecar because the policy itself is replaced by atomic rename, which would
// otherwise change the inode being locked.
func withPolicyFileLock(policyPath string, fn func() error) error {
	return filetxn.WithLock(policyPath, fn)
}

func canonicalPolicyPath(policyPath string) (string, error) {
	return filetxn.CanonicalPath(policyPath)
}
