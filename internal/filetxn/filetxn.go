// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

// Package filetxn coordinates atomic file transactions used by Rampart's
// policy and durable state writers.
package filetxn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrLockHeld reports that AcquireLock found another live owner. Anchor files
// may remain on disk after exit; ownership is determined by the OS lock, not
// by file existence.
var ErrLockHeld = errors.New("file transaction: lock is already held")

// Lock is a process- and OS-bound advisory lock held until Close.
type Lock struct {
	file          *os.File
	unlockFile    func() error
	unlockProcess func()
	once          sync.Once
	err           error
}

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

// AcquireLock takes a non-blocking lifetime lock for an existing data
// directory. The platform helper anchors ownership outside that directory so
// replacing the state-directory pathname cannot create a second owner. The
// caller must Close the returned lock. It returns ErrLockHeld when another
// goroutine or process owns it.
func AcquireLock(path string) (*Lock, error) {
	canonical, err := CanonicalPath(path)
	if err != nil {
		return nil, fmt.Errorf("file transaction: canonicalize lock path: %w", err)
	}
	targetBefore, err := os.Lstat(canonical)
	if err != nil {
		return nil, fmt.Errorf("file transaction: inspect lifetime-lock directory: %w", err)
	}
	if targetBefore.Mode()&os.ModeSymlink != 0 || !targetBefore.IsDir() {
		return nil, fmt.Errorf("file transaction: refusing non-directory or symlinked lifetime-lock target %s", canonical)
	}

	processKey := lifetimeLockProcessKey(canonical)
	unlockProcess, acquired := tryLockProcessPath(processKey)
	if !acquired {
		return nil, ErrLockHeld
	}

	lockFile, unlockFile, acquired, err := acquireLifetimeLock(canonical)
	if err != nil {
		if lockFile != nil {
			_ = lockFile.Close()
		}
		unlockProcess()
		return nil, fmt.Errorf("file transaction: acquire lifetime lock: %w", err)
	}
	if !acquired {
		if lockFile != nil {
			_ = lockFile.Close()
		}
		unlockProcess()
		return nil, ErrLockHeld
	}
	targetAfter, err := os.Lstat(canonical)
	if err != nil || targetAfter.Mode()&os.ModeSymlink != 0 || !targetAfter.IsDir() || !os.SameFile(targetBefore, targetAfter) {
		if unlockFile != nil {
			_ = unlockFile()
		}
		if lockFile != nil {
			_ = lockFile.Close()
		}
		unlockProcess()
		if err != nil {
			return nil, fmt.Errorf("file transaction: reinspect lifetime-lock directory: %w", err)
		}
		return nil, fmt.Errorf("file transaction: lifetime-lock directory changed during acquisition: %s", canonical)
	}

	return &Lock{file: lockFile, unlockFile: unlockFile, unlockProcess: unlockProcess}, nil
}

// Close releases the lifetime lock. It is safe to call more than once.
func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.unlockFile != nil {
			l.err = l.unlockFile()
		}
		if l.file != nil {
			if err := l.file.Close(); l.err == nil {
				l.err = err
			}
		}
		if l.unlockProcess != nil {
			l.unlockProcess()
		}
	})
	return l.err
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
	return processPathUnlock(canonical, lock)
}

func tryLockProcessPath(canonical string) (func(), bool) {
	processLocks.Lock()
	lock := processLocks.byPath[canonical]
	if lock == nil {
		lock = &pathMutex{}
		processLocks.byPath[canonical] = lock
	}
	lock.refs++
	processLocks.Unlock()

	if !lock.mu.TryLock() {
		processLocks.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(processLocks.byPath, canonical)
		}
		processLocks.Unlock()
		return nil, false
	}
	return processPathUnlock(canonical, lock), true
}

func processPathUnlock(canonical string, lock *pathMutex) func() {
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
