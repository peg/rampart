// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/peg/rampart/internal/notify"
	"github.com/peg/rampart/internal/securefile"
)

const (
	serveLogMaxBytes  = 10 << 20
	serveLogBackups   = 3
	serveLogMaxRecord = 64 << 10
)

// serveLog receives complete diagnostic records from slog and command output.
// Audit events have their own required persistence and retention contract.
type serveLog struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	maxBytes int64
	backups  int
	err      error
}

func openServeLog(path string, maxBytes int64, backups int) (*serveLog, error) {
	if maxBytes <= 0 || backups < 1 {
		return nil, fmt.Errorf("serve: invalid diagnostic log retention limits")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("serve: resolve log directory: %w", err)
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return nil, err
	}
	w := &serveLog{path: serveLogNativePath(filepath.Join(parent, filepath.Base(path))), maxBytes: maxBytes, backups: backups}
	if err := w.open(); err != nil {
		return nil, err
	}
	info, err := w.file.Stat()
	if err == nil && info.Size() >= maxBytes {
		err = w.rotate()
	}
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

func inspectServeLog(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("serve: diagnostic log must be a regular non-symlink file")
	}
	return info, nil
}

func (w *serveLog) open() error {
	before, err := inspectServeLog(w.path)
	create := errors.Is(err, os.ErrNotExist)
	if err != nil && !create {
		return err
	}
	file, err := openServeLogAppend(w.path, create)
	if err != nil {
		return fmt.Errorf("serve: open diagnostic log: %w", err)
	}
	w.file = file
	if err = w.validate(before); err == nil {
		err = securefile.OwnerOnlyFile(file)
	}
	if err == nil {
		err = w.validate(nil)
	}
	if err != nil {
		_ = file.Close()
		w.file = nil
		return err
	}
	return nil
}

func (w *serveLog) validate(expected os.FileInfo) error {
	current, err := inspectServeLog(w.path)
	if err != nil {
		return err
	}
	opened, err := w.file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(current, opened) || (expected != nil && !os.SameFile(expected, opened)) {
		return fmt.Errorf("serve: diagnostic log was replaced")
	}
	return securefile.SingleLink(w.file)
}

func (w *serveLog) rotate() error {
	if err := w.validate(nil); err != nil {
		return err
	}
	// Inspect the whole managed suffix set before changing it. Renames replace
	// directory entries, preserving unrelated hard links to retained files.
	for i := 1; i <= w.backups; i++ {
		if _, err := inspectServeLog(fmt.Sprintf("%s.%d", w.path, i)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	for i := w.backups; i >= 1; i-- {
		source := w.path
		if i > 1 {
			source = fmt.Sprintf("%s.%d", w.path, i-1)
		}
		if err := replaceServeLog(source, fmt.Sprintf("%s.%d", w.path, i)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("serve: rotate diagnostic backup %d: %w", i, err)
		}
	}
	return w.open()
}

func (w *serveLog) Write(record []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.file == nil {
		return 0, os.ErrClosed
	}
	// Bound work before redaction. An oversized diagnostic record is replaced
	// entirely; truncating the input first could expose part of a credential.
	text := "serve: oversized diagnostic record omitted\n"
	if len(record) <= serveLogMaxRecord {
		text = notify.SanitizeCommand(string(record))
	}
	if int64(len(text)) > w.maxBytes {
		text = "[diagnostic record omitted]\n"
	}
	if int64(len(text)) > w.maxBytes {
		return 0, fmt.Errorf("serve: diagnostic log limit is smaller than an omission marker")
	}
	if err := w.validate(nil); err != nil {
		w.err = err
		return 0, err
	}
	info, err := w.file.Stat()
	if err == nil && info.Size()+int64(len(text)) > w.maxBytes {
		err = w.rotate()
	}
	if err == nil {
		_, err = w.file.WriteString(text)
	}
	if err != nil {
		w.err = err
		return 0, err
	}
	return len(record), nil
}

func (w *serveLog) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return w.err
	}
	err := w.file.Close()
	w.file = nil
	return errors.Join(w.err, err)
}
