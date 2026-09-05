// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package cli

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/peg/rampart/internal/filetxn"
	"golang.org/x/sys/windows"
)

// Windows' legacy replacement cannot evict a backup still held by inherited
// stdout/stderr. FileRenameInfoEx's POSIX flag preserves those handles while
// letting the retained backup name refer to the replacement.
func replaceServeLog(source, destination string) error {
	before, err := inspectServeLog(source)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), source)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return fmt.Errorf("serve: diagnostic backup changed before rotation")
	}
	wide, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	// FILE_RENAME_INFO has a variable-width UTF-16 tail and native HANDLE
	// alignment. Keep unsafe confined to this OS ABI buffer; no Go pointer is
	// stored in it, and the syscall completes before the buffer is released.
	type renameInfo struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	var layout renameInfo
	buffer := make([]byte, int(unsafe.Sizeof(layout))+len(wide)*2)
	info := (*renameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	info.FileNameLength = uint32((len(wide) - 1) * 2)
	offset := int(unsafe.Offsetof(layout.FileName))
	for i, unit := range wide {
		binary.LittleEndian.PutUint16(buffer[offset+i*2:], unit)
	}
	err = windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buffer[0], uint32(len(buffer)))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		// Older filesystems may support only ordinary replacement. Keep their
		// failure explicit if an open destination prevents that operation.
		return filetxn.Replace(source, destination)
	}
	return err
}

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
