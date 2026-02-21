// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package engine

import (
	"sync"
	"time"
)

// CallCounter tracks per-tool call counts in a sliding time window.
type CallCounter interface {
	Increment(tool string, at time.Time)
	Count(tool string, window time.Duration, now time.Time) int
	Snapshot(window time.Duration, now time.Time) map[string]int
}

// SlidingWindowCounter is an in-memory per-tool sliding window counter.
// It is safe for concurrent use.
type SlidingWindowCounter struct {
	mu    sync.Mutex
	calls map[string][]time.Time
}

// NewSlidingWindowCounter creates a new empty counter.
func NewSlidingWindowCounter() *SlidingWindowCounter {
	return &SlidingWindowCounter{
		calls: make(map[string][]time.Time),
	}
}

// Increment records one tool invocation at time at.
func (c *SlidingWindowCounter) Increment(tool string, at time.Time) {
	if tool == "" {
		return
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[tool] = append(c.calls[tool], at)
}

// Count returns how many calls for tool occurred in the given sliding window.
// Old entries outside the window are pruned on each check.
func (c *SlidingWindowCounter) Count(tool string, window time.Duration, now time.Time) int {
	if tool == "" || window <= 0 {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ts := c.pruneLocked(tool, window, now)
	return len(ts)
}

// Snapshot returns current per-tool counts in the given sliding window.
// Old entries outside the window are pruned for each tool on each check.
func (c *SlidingWindowCounter) Snapshot(window time.Duration, now time.Time) map[string]int {
	if window <= 0 {
		return map[string]int{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	out := make(map[string]int, len(c.calls))
	for tool := range c.calls {
		ts := c.pruneLocked(tool, window, now)
		if len(ts) > 0 {
			out[tool] = len(ts)
		}
	}
	return out
}

func (c *SlidingWindowCounter) pruneLocked(tool string, window time.Duration, now time.Time) []time.Time {
	ts := c.calls[tool]
	if len(ts) == 0 {
		return nil
	}

	cutoff := now.Add(-window)
	keepFrom := 0
	for keepFrom < len(ts) && ts[keepFrom].Before(cutoff) {
		keepFrom++
	}

	if keepFrom == len(ts) {
		delete(c.calls, tool)
		return nil
	}
	if keepFrom > 0 {
		ts = append([]time.Time(nil), ts[keepFrom:]...)
		c.calls[tool] = ts
	}
	return ts
}
