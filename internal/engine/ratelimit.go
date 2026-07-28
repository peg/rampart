// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package engine

import (
	"container/heap"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// Call-count rules are intentionally bounded so a compromised agent cannot
	// turn the long-running serve process into an unbounded timestamp store.
	maxCallCountWindow        = 30 * 24 * time.Hour
	maxCallCountThreshold     = 1_000
	maxTrackedCallCountTools  = 1_024
	maxCallCountToolNameBytes = 256
)

var (
	ErrCallCounterCapacity = errors.New("call counter capacity exhausted")
	ErrCallCounterToolName = errors.New("call counter tool name too long")
)

// CallCounter tracks per-tool call counts in a sliding time window.
type CallCounter interface {
	Increment(tool string, at time.Time) error
	Count(tool string, window time.Duration, now time.Time) int
	Snapshot(window time.Duration, now time.Time) map[string]int
}

// timestampHeap is a min-heap retaining the newest
// maxCallCountThreshold timestamps. It is order-independent: concurrent
// requests may acquire the counter lock in a different order than their
// timestamps were captured.
type timestampHeap []time.Time

func (h timestampHeap) Len() int           { return len(h) }
func (h timestampHeap) Less(i, j int) bool { return h[i].Before(h[j]) }
func (h timestampHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *timestampHeap) Push(value any)    { *h = append(*h, value.(time.Time)) }
func (h *timestampHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = time.Time{}
	*h = old[:last]
	return value
}

func (h *timestampHeap) record(at time.Time) {
	if len(*h) < maxCallCountThreshold {
		heap.Push(h, at)
		return
	}
	// Retain the newest threshold events. This preserves exact rule semantics:
	// once a window contains the maximum accepted threshold, older additional
	// events cannot change whether any valid call_count rule matches.
	if at.After((*h)[0]) {
		(*h)[0] = at
		heap.Fix(h, 0)
	}
}

func (h *timestampHeap) pruneBefore(cutoff time.Time) {
	for len(*h) > 0 && (*h)[0].Before(cutoff) {
		heap.Pop(h)
	}
}

func (h timestampHeap) countWindow(cutoff, now time.Time) int {
	count := 0
	for _, at := range h {
		if !at.Before(cutoff) && !at.After(now) {
			count++
		}
	}
	return count
}

// SlidingWindowCounter is a bounded, exact per-tool sliding window counter. It
// is safe for concurrent use. If all tool slots contain live data, recording a
// previously unseen tool returns ErrCallCounterCapacity; enforcement callers
// must fail closed rather than merge identities or silently under-count.
type SlidingWindowCounter struct {
	mu    sync.Mutex
	calls map[string]*timestampHeap
}

// NewSlidingWindowCounter creates a new empty counter.
func NewSlidingWindowCounter() *SlidingWindowCounter {
	return &SlidingWindowCounter{calls: make(map[string]*timestampHeap)}
}

// RequiresCallCount reports whether recording this tool invocation can affect
// an active call_count rule. Native hooks use it to avoid a durable file
// transaction for unrelated tools. An explicit call_count.tool is global to
// that tool; an implicit target applies only when the policy scope matches the
// current call.
func (e *Engine) RequiresCallCount(call ToolCall) bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()
	if cfg == nil {
		return false
	}

	for _, policy := range cfg.Policies {
		if !policy.IsEnabled() {
			continue
		}
		scopeMatches := e.matchesScope(policy.Match, call)
		for _, rule := range policy.Rules {
			if rule.IsExpired() || rule.When.CallCount == nil {
				continue
			}
			target := strings.TrimSpace(rule.When.CallCount.Tool)
			if target == "" {
				if scopeMatches {
					return true
				}
				continue
			}
			if target == call.Tool {
				return true
			}
		}
	}
	return false
}

// Increment records one tool invocation at time at.
func (c *SlidingWindowCounter) Increment(tool string, at time.Time) error {
	if tool == "" {
		return nil
	}
	if len(tool) > maxCallCountToolNameBytes {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrCallCounterToolName, len(tool), maxCallCountToolNameBytes)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	series, ok := c.calls[tool]
	if !ok {
		c.pruneAllLocked(at.Add(-maxCallCountWindow))
		if len(c.calls) >= maxTrackedCallCountTools {
			return fmt.Errorf("%w: maximum %d active tools", ErrCallCounterCapacity, maxTrackedCallCountTools)
		}
		series = &timestampHeap{}
		c.calls[tool] = series
	}
	series.pruneBefore(at.Add(-maxCallCountWindow))
	series.record(at)
	return nil
}

// Count returns how many calls for tool occurred in the given sliding window.
// Counts saturate at maxCallCountThreshold, which is also the largest accepted
// policy threshold.
func (c *SlidingWindowCounter) Count(tool string, window time.Duration, now time.Time) int {
	if tool == "" || window <= 0 {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	series, ok := c.calls[tool]
	if !ok {
		return 0
	}
	series.pruneBefore(now.Add(-maxCallCountWindow))
	if len(*series) == 0 {
		delete(c.calls, tool)
		return 0
	}
	return series.countWindow(now.Add(-window), now)
}

// Snapshot returns current per-tool counts in the provided window.
func (c *SlidingWindowCounter) Snapshot(window time.Duration, now time.Time) map[string]int {
	if window <= 0 {
		return map[string]int{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneAllLocked(now.Add(-maxCallCountWindow))
	cutoff := now.Add(-window)
	out := make(map[string]int, len(c.calls))
	for tool, series := range c.calls {
		if count := series.countWindow(cutoff, now); count > 0 {
			out[tool] = count
		}
	}
	return out
}

func (c *SlidingWindowCounter) pruneAllLocked(cutoff time.Time) {
	for tool, series := range c.calls {
		series.pruneBefore(cutoff)
		if len(*series) == 0 {
			delete(c.calls, tool)
		}
	}
}
