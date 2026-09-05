// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package filetxn

import (
	"context"
	"fmt"
	"os"
	"time"
)

// WithLockContext uses the same canonical key and sidecar as WithLock, while
// waiting through nonblocking process/OS primitives. It never leaves a detached
// acquisition goroutine behind after cancellation. The callback owns its own
// cancellation behavior; filesystem system calls remain subject to OS behavior.
func WithLockContext(ctx context.Context, path string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	canonical, err := CanonicalPath(path)
	if err != nil {
		return fmt.Errorf("file transaction: canonicalize lock path: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		unlock, acquired := tryLockProcessPath(canonical)
		if acquired {
			defer unlock()
			break
		}
		if err := waitLockRetry(ctx); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(canonical+".rampart.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("file transaction: open lock: %w", err)
	}
	defer file.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		unlock, acquired, err := tryLockFileExclusive(file)
		if err != nil {
			return fmt.Errorf("file transaction: acquire lock: %w", err)
		}
		if acquired {
			defer unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			return fn()
		}
		if err := waitLockRetry(ctx); err != nil {
			return err
		}
	}
}

func waitLockRetry(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
