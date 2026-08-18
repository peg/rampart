// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

package filetxn

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockFileExclusive(file *os.File) (func() error, error) {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	return func() error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }, nil
}

func tryLockFileExclusive(file *os.File) (func() error, bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return func() error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }, true, nil
}

// Lifetime locks use the canonical state directory's parent rather than a
// sidecar inside the replaceable state directory. Rampart uses one data
// directory per home, so parent-directory granularity is intentional.
func lifetimeLockProcessKey(canonical string) string {
	return "lifetime-directory:" + filepath.Dir(canonical)
}

func acquireLifetimeLock(canonical string) (*os.File, func() error, bool, error) {
	directoryPath := filepath.Dir(canonical)
	before, err := os.Lstat(directoryPath)
	if err != nil {
		return nil, nil, false, fmt.Errorf("inspect lock directory: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, false, fmt.Errorf("refusing non-directory or symlinked lifetime-lock parent %s", directoryPath)
	}

	directory, err := os.Open(directoryPath)
	if err != nil {
		return nil, nil, false, fmt.Errorf("open lock directory: %w", err)
	}
	opened, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, nil, false, fmt.Errorf("inspect opened lock directory: %w", err)
	}
	if !opened.IsDir() || !os.SameFile(before, opened) {
		_ = directory.Close()
		return nil, nil, false, fmt.Errorf("lifetime-lock parent changed while opening: %s", directoryPath)
	}

	unlock, acquired, err := tryLockFileExclusive(directory)
	if err != nil || !acquired {
		return directory, nil, acquired, err
	}
	after, err := os.Lstat(directoryPath)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(opened, after) {
		_ = unlock()
		if err != nil {
			return directory, nil, false, fmt.Errorf("reinspect lock directory: %w", err)
		}
		return directory, nil, false, fmt.Errorf("lifetime-lock parent changed during acquisition: %s", directoryPath)
	}
	return directory, unlock, true, nil
}
