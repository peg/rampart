// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package engine

import (
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/peg/rampart/internal/securefile"
)

const (
	persistentCallCounterVersion       = 1
	maxPersistentCallCounterStateBytes = 32 * 1024 * 1024
)

// PersistentCallCounter is a bounded CallCounter for short-lived native hook
// processes. Increment performs a locked read-prune-update-atomic-replace
// transaction, then retains that exact snapshot for policy evaluation in the
// current process. Separate hook processes therefore share call_count history
// without merging tool identities or depending on a daemon.
type PersistentCallCounter struct {
	path string

	mu    sync.RWMutex
	local *SlidingWindowCounter
}

type persistentCallCounterState struct {
	Version   int                `json:"version"`
	UpdatedAt time.Time          `json:"updated_at"`
	Tools     map[string][]int64 `json:"tools"`
}

// NewPersistentCallCounter creates a hook-oriented counter backed by path.
// Disk I/O is deferred until Increment so construction alone does not create
// state. A successful Increment must precede policy evaluation; its error is a
// fail-closed signal to the caller.
func NewPersistentCallCounter(path string) (*PersistentCallCounter, error) {
	if path == "" {
		return nil, errors.New("persistent call counter path is empty")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("persistent call counter path: %w", err)
	}
	return &PersistentCallCounter{
		path:  absPath,
		local: NewSlidingWindowCounter(),
	}, nil
}

// Increment records a call in one cross-process transaction. The local
// snapshot is updated only after the durable atomic replacement succeeds.
func (c *PersistentCallCounter) Increment(tool string, at time.Time) error {
	if tool == "" {
		return nil
	}
	if len(tool) > maxCallCountToolNameBytes {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrCallCounterToolName, len(tool), maxCallCountToolNameBytes)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("persistent call counter create directory: %w", err)
	}

	var committed *SlidingWindowCounter
	err := withPolicyFileLock(c.path, func() error {
		counter, err := loadPersistentCallCounter(c.path)
		if err != nil {
			return err
		}

		// Compact every tool on each transaction. This bounds both cardinality
		// and the sidecar size even if a tool is never queried again.
		counter.mu.Lock()
		counter.pruneAllLocked(at.Add(-maxCallCountWindow))
		counter.mu.Unlock()

		if err := counter.Increment(tool, at); err != nil {
			return err
		}
		if err := writePersistentCallCounter(c.path, counter, at); err != nil {
			return err
		}
		committed = counter
		return nil
	})
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.local = committed
	c.mu.Unlock()
	return nil
}

// Count evaluates against the snapshot committed by this process's most
// recent Increment. Hook callers increment immediately before evaluation.
func (c *PersistentCallCounter) Count(tool string, window time.Duration, now time.Time) int {
	c.mu.RLock()
	local := c.local
	c.mu.RUnlock()
	return local.Count(tool, window, now)
}

// Snapshot returns counts from the snapshot committed by this process's most
// recent Increment.
func (c *PersistentCallCounter) Snapshot(window time.Duration, now time.Time) map[string]int {
	c.mu.RLock()
	local := c.local
	c.mu.RUnlock()
	return local.Snapshot(window, now)
}

func loadPersistentCallCounter(path string) (*SlidingWindowCounter, error) {
	counter := NewSlidingWindowCounter()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return counter, nil
	}
	if err != nil {
		return nil, fmt.Errorf("persistent call counter stat: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("persistent call counter is not a regular non-symlink file: %s", path)
	}
	if info.Size() > maxPersistentCallCounterStateBytes {
		return nil, fmt.Errorf("persistent call counter state is %d bytes (max %d)", info.Size(), maxPersistentCallCounterStateBytes)
	}
	if err := securefile.OwnerOnly(path); err != nil {
		return nil, fmt.Errorf("persistent call counter secure state: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("persistent call counter read: %w", err)
	}
	var state persistentCallCounterState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("persistent call counter parse: %w", err)
	}
	if state.Version != persistentCallCounterVersion {
		return nil, fmt.Errorf("persistent call counter version %d is unsupported", state.Version)
	}
	if len(state.Tools) > maxTrackedCallCountTools {
		return nil, fmt.Errorf("persistent call counter has %d tools (max %d)", len(state.Tools), maxTrackedCallCountTools)
	}

	for tool, values := range state.Tools {
		if tool == "" || len(tool) > maxCallCountToolNameBytes {
			return nil, fmt.Errorf("persistent call counter contains invalid tool name of %d bytes", len(tool))
		}
		if len(values) > maxCallCountThreshold {
			return nil, fmt.Errorf("persistent call counter tool %q has %d timestamps (max %d)", tool, len(values), maxCallCountThreshold)
		}
		series := make(timestampHeap, len(values))
		for i, unixNano := range values {
			series[i] = time.Unix(0, unixNano).UTC()
		}
		heap.Init(&series)
		counter.calls[tool] = &series
	}
	return counter, nil
}

func writePersistentCallCounter(path string, counter *SlidingWindowCounter, now time.Time) error {
	state := persistentCallCounterState{
		Version:   persistentCallCounterVersion,
		UpdatedAt: now.UTC(),
		Tools:     make(map[string][]int64, len(counter.calls)),
	}

	counter.mu.Lock()
	for tool, series := range counter.calls {
		values := make([]int64, len(*series))
		for i, at := range *series {
			values[i] = at.UnixNano()
		}
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		state.Tools[tool] = values
	}
	counter.mu.Unlock()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("persistent call counter marshal: %w", err)
	}
	if len(data) > maxPersistentCallCounterStateBytes {
		return fmt.Errorf("persistent call counter state is %d bytes (max %d)", len(data), maxPersistentCallCounterStateBytes)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".call-counts-*.json.tmp")
	if err != nil {
		return fmt.Errorf("persistent call counter create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := securefile.OwnerOnly(tmpPath); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("persistent call counter secure temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("persistent call counter write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("persistent call counter sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("persistent call counter close temporary file: %w", err)
	}
	if err := replaceFileAtomic(tmpPath, path); err != nil {
		return fmt.Errorf("persistent call counter replace state: %w", err)
	}
	removeTemp = false
	return nil
}

// SetCallCounter replaces the engine's counter. It is intended for
// initialization before the engine is used by a hook invocation.
func (e *Engine) SetCallCounter(counter CallCounter) {
	if e == nil || counter == nil {
		return
	}
	e.mu.Lock()
	e.callCounter = counter
	e.mu.Unlock()
}
