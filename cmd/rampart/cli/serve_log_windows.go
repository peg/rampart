// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package cli

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// The caller supplies a canonical absolute path. Keep the extended form on
// the writer so both CreateFile and rotation's MoveFileEx support long paths,
// including UNC shares, without depending on the machine's long-path setting.
func serveLogNativePath(path string) string {
	if len(path) < 248 || strings.HasPrefix(path, `\\?\`) ||
		strings.HasPrefix(path, `\??\`) || strings.HasPrefix(path, `\\.\`) {
		return path
	}
	if strings.HasPrefix(path, `\\`) {
		return `\\?\UNC\` + path[2:]
	}
	return `\\?\` + path
}

func openServeLogAppend(path string, create bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.CREATE_NEW
	}
	// Match Go's O_APPEND access mask: FILE_WRITE_DATA would allow writes at
	// the inherited handle's current offset instead of always at the file end.
	access := uint32(windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES |
		windows.FILE_WRITE_EA | windows.STANDARD_RIGHTS_WRITE | windows.SYNCHRONIZE)
	// The background child keeps inherited stdout/stderr handles after opening
	// its managed writer. Those handles must permit rotation and eventual removal.
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	handle, err := windows.CreateFile(name, access, share, nil, disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
