// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package filetxn

import "golang.org/x/sys/windows"

// Replace replaces destinationPath with sourcePath and requests write-through.
func Replace(sourcePath, destinationPath string) error {
	source, err := windows.UTF16PtrFromString(sourcePath)
	if err != nil {
		return err
	}
	destination, err := windows.UTF16PtrFromString(destinationPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, destination,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// SyncDir is a no-op on Windows, which has no portable directory-fsync
// equivalent. File.Sync flushes newly created file metadata and contents, and
// Replace uses MoveFileEx with MOVEFILE_WRITE_THROUGH for atomic replacements.
func SyncDir(string) error {
	return nil
}
