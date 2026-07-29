// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/internal/securefile"
)

const maxAuditMetadataBytes = 1024 * 1024

// validateAuditDirectory rejects a symlink or non-directory at the audit root.
// We intentionally validate the configured leaf rather than every ancestor:
// common system paths (for example /tmp on macOS) may themselves be symlinks.
func validateAuditDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("audit: inspect directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("audit: directory is not a non-symlink directory: %s", dir)
	}
	return nil
}

// inspectAuditRegularPath validates the directory entry itself, without
// following a symlink. The boolean reports whether the path exists.
func inspectAuditRegularPath(path string) (os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("audit: inspect file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, true, fmt.Errorf("audit: path is not a regular non-symlink file: %s", path)
	}
	return info, true, nil
}

// openAuditRegular opens an existing regular file and verifies that the
// opened handle still names the validated directory entry. This second check
// closes the ordinary lstat/open substitution window on every supported OS.
func openAuditRegular(path string, flag int) (*os.File, error) {
	before, exists, err := inspectAuditRegularPath(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, os.ErrNotExist
	}

	file, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, err
	}
	if err := validateOpenAuditFile(path, file, before); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// openAuditAppend opens or creates an owner-only append target without ever
// using O_CREATE on a pre-existing path. New files use O_EXCL, while existing
// files are lstat/open/fstat checked before they are returned.
func openAuditAppend(path string) (*os.File, bool, error) {
	before, exists, err := inspectAuditRegularPath(path)
	if err != nil {
		return nil, false, err
	}

	created := false
	var file *os.File
	if exists {
		file, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	} else {
		file, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		created = err == nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := validateOpenAuditFile(path, file, before); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	if err := securefile.OwnerOnly(path); err != nil {
		_ = file.Close()
		return nil, false, fmt.Errorf("audit: secure file %s: %w", path, err)
	}
	if err := validateOpenAuditFile(path, file, nil); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	return file, created, nil
}

func validateOpenAuditFile(path string, file *os.File, expected os.FileInfo) error {
	openInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("audit: stat open file %s: %w", path, err)
	}
	if !openInfo.Mode().IsRegular() {
		return fmt.Errorf("audit: opened path is not a regular file: %s", path)
	}
	pathInfo, exists, err := inspectAuditRegularPath(path)
	if err != nil {
		return err
	}
	if !exists || !os.SameFile(openInfo, pathInfo) || (expected != nil && !os.SameFile(expected, pathInfo)) {
		return fmt.Errorf("audit: file changed while opening: %s", path)
	}
	return nil
}

func readAuditMetadata(path string) ([]byte, bool, error) {
	file, err := openAuditRegular(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("audit: stat metadata %s: %w", path, err)
	}
	if info.Size() > maxAuditMetadataBytes {
		return nil, false, fmt.Errorf("audit: metadata file exceeds %d-byte limit: %s", maxAuditMetadataBytes, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAuditMetadataBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("audit: read metadata %s: %w", path, err)
	}
	if len(data) > maxAuditMetadataBytes {
		return nil, false, fmt.Errorf("audit: metadata file exceeds %d-byte limit: %s", maxAuditMetadataBytes, path)
	}
	return data, true, nil
}

// replaceAuditMetadata writes through a random, owner-only temporary file and
// then atomically replaces a missing or regular destination. A predictable
// temporary name must not be used here because an attacker could pre-create a
// symlink at that path.
func replaceAuditMetadata(path string, data []byte, syncFile bool) (err error) {
	if _, _, err := inspectAuditRegularPath(path); err != nil {
		return err
	}
	if err := validateAuditDirectory(filepath.Dir(path)); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("audit: create metadata temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := validateOpenAuditFile(tmpPath, tmp, nil); err != nil {
		return err
	}
	if err := securefile.OwnerOnly(tmpPath); err != nil {
		return fmt.Errorf("audit: secure metadata temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("audit: write metadata temp: %w", err)
	}
	if syncFile {
		if err := tmp.Sync(); err != nil {
			return fmt.Errorf("audit: fsync metadata temp: %w", err)
		}
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("audit: close metadata temp: %w", err)
	}

	// Re-check immediately before replacement. Replace itself renames the
	// directory entry, so it never writes through a link planted afterward.
	if _, _, err := inspectAuditRegularPath(path); err != nil {
		return err
	}
	if err := filetxn.Replace(tmpPath, path); err != nil {
		return fmt.Errorf("audit: replace metadata: %w", err)
	}
	return nil
}
