// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package filetxn

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockFileExclusive(file *os.File) (func() error, error) {
	overlapped := &windows.Overlapped{}
	handle := windows.Handle(file.Fd())
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		return nil, err
	}
	return func() error { return windows.UnlockFileEx(handle, 0, 1, 0, overlapped) }, nil
}
