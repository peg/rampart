// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

// Package filetxn coordinates atomic file transactions used by Rampart's
// policy and durable state writers.
package filetxn

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type pathMutex struct {
	mu   sync.Mutex
	refs int
}

var processLocks = struct {
	sync.Mutex
	byPath map[string]*pathMutex
}{byPath: make(map[string]*pathMutex)}

// WithLock runs fn while holding a stable sidecar lock for path. The sidecar
// is used because replacing path atomically changes the target file's inode.
func WithLock(path string, fn func() error) error {
	canonical, err := CanonicalPath(path)
	if err != nil {
		return fmt.Errorf("file transaction: canonicalize lock path: %w", err)
	}

	unlockProcess := lockProcessPath(canonical)
	defer unlockProcess()

	lockFile, err := os.OpenFile(canonical+".rampart.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("file transaction: open lock: %w", err)
	}
	defer lockFile.Close()

	unlock, err := lockFileExclusive(lockFile)
	if err != nil {
		return fmt.Errorf("file transaction: acquire lock: %w", err)
	}
	defer unlock()
	return fn()
}

func lockProcessPath(canonical string) func() {
	processLocks.Lock()
	lock := processLocks.byPath[canonical]
	if lock == nil {
		lock = &pathMutex{}
		processLocks.byPath[canonical] = lock
	}
	lock.refs++
	processLocks.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		processLocks.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(processLocks.byPath, canonical)
		}
		processLocks.Unlock()
	}
}

// CanonicalPath resolves the parent directory while allowing the target not
// to exist yet. Every cooperating writer therefore derives the same sidecar.
func CanonicalPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absPath = filepath.Clean(absPath)
	if parent, resolveErr := filepath.EvalSymlinks(filepath.Dir(absPath)); resolveErr == nil {
		absPath = filepath.Join(parent, filepath.Base(absPath))
	}
	return absPath, nil
}
