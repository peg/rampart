// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package filetxn

import (
	"errors"
	"fmt"
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

func tryLockFileExclusive(file *os.File) (func() error, bool, error) {
	overlapped := &windows.Overlapped{}
	handle := windows.Handle(file.Fd())
	err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
	if err == windows.ERROR_LOCK_VIOLATION {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return func() error { return windows.UnlockFileEx(handle, 0, 1, 0, overlapped) }, true, nil
}

func lifetimeLockProcessKey(canonical string) string {
	return "lifetime-anchor:" + canonical + ".rampart.lock"
}

// acquireLifetimeLock opens a sibling anchor without any share permissions.
// Keeping it outside the replaceable state directory means Windows refuses a
// second owner even if that directory is renamed or recreated. The reparse
// flag lets us inspect and reject a symlink or other reparse point without
// following it.
func acquireLifetimeLock(canonical string) (*os.File, func() error, bool, error) {
	anchorPath := canonical + ".rampart.lock"
	name, err := windows.UTF16PtrFromString(anchorPath)
	if err != nil {
		return nil, nil, false, fmt.Errorf("encode lock anchor path: %w", err)
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, // No sharing: in particular, do not permit delete or replacement.
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, nil, false, nil
		}
		return nil, nil, false, fmt.Errorf("open exclusive lock anchor: %w", err)
	}
	closeHandle := func() { _ = windows.CloseHandle(handle) }

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		closeHandle()
		return nil, nil, false, fmt.Errorf("inspect lock anchor: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		closeHandle()
		return nil, nil, false, fmt.Errorf("refusing directory or reparse-point lifetime-lock anchor %s", anchorPath)
	}
	if info.NumberOfLinks != 1 {
		closeHandle()
		return nil, nil, false, fmt.Errorf("refusing hard-linked lifetime-lock anchor %s", anchorPath)
	}
	fileType, err := windows.GetFileType(handle)
	if err != nil {
		closeHandle()
		return nil, nil, false, fmt.Errorf("inspect lock anchor type: %w", err)
	}
	if fileType != windows.FILE_TYPE_DISK {
		closeHandle()
		return nil, nil, false, fmt.Errorf("refusing non-disk lifetime-lock anchor %s", anchorPath)
	}

	file := os.NewFile(uintptr(handle), anchorPath)
	if file == nil {
		closeHandle()
		return nil, nil, false, fmt.Errorf("wrap lifetime-lock anchor handle")
	}
	unlock, acquired, err := tryLockFileExclusive(file)
	if err != nil || !acquired {
		return file, nil, acquired, err
	}
	return file, unlock, true, nil
}
