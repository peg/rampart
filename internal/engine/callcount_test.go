package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCallCountBasic(t *testing.T) {
	counter := NewSlidingWindowCounter()
	call := ToolCall{Tool: "fetch"}
	cond := Condition{
		CallCount: &CallCountCondition{
			Gte:    3,
			Window: "1h",
		},
	}

	now := time.Now().UTC()
	if err := counter.Increment("fetch", now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match at count=1")
	}

	if err := counter.Increment("fetch", now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match at count=2")
	}

	if err := counter.Increment("fetch", now.Add(-1*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !matchCondition(cond, call, counter) {
		t.Fatal("expected match at count=3")
	}
}

func TestCallCountSliding(t *testing.T) {
	counter := NewSlidingWindowCounter()
	call := ToolCall{Tool: "fetch"}
	cond := Condition{
		CallCount: &CallCountCondition{
			Gte:    2,
			Window: "1h",
		},
	}

	now := time.Now().UTC()
	if err := counter.Increment("fetch", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := counter.Increment("fetch", now.Add(-45*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match with only one call inside 1h window")
	}

	if err := counter.Increment("fetch", now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !matchCondition(cond, call, counter) {
		t.Fatal("expected match with two calls inside 1h window")
	}
}

func TestCallCountToolFilter(t *testing.T) {
	counter := NewSlidingWindowCounter()
	call := ToolCall{Tool: "fetch"}
	cond := Condition{
		CallCount: &CallCountCondition{
			Tool:   "web_search",
			Gte:    2,
			Window: "1h",
		},
	}

	now := time.Now().UTC()
	if err := counter.Increment("fetch", now.Add(-1*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := counter.Increment("fetch", now.Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match when threshold is not met for specified tool")
	}

	if err := counter.Increment("web_search", now.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match at web_search count=1")
	}

	if err := counter.Increment("web_search", now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !matchCondition(cond, call, counter) {
		t.Fatal("expected match at web_search count=2")
	}
}

func TestCallCountShortSnapshotPreservesLongWindow(t *testing.T) {
	counter := NewSlidingWindowCounter()
	now := time.Now().UTC()
	if err := counter.Increment("fetch", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if got := counter.Snapshot(time.Hour, now)["fetch"]; got != 0 {
		t.Fatalf("1h snapshot count = %d, want 0", got)
	}
	if got := counter.Count("fetch", 3*time.Hour, now); got != 1 {
		t.Fatalf("3h count after shorter snapshot = %d, want 1", got)
	}
}

func TestCallCountPerToolStorageIsBoundedAndSaturating(t *testing.T) {
	counter := NewSlidingWindowCounter()
	now := time.Now().UTC()
	for i := 0; i < maxCallCountThreshold+500; i++ {
		if err := counter.Increment("fetch", now.Add(time.Duration(i)*time.Nanosecond)); err != nil {
			t.Fatal(err)
		}
	}

	series := counter.calls["fetch"]
	if series == nil {
		t.Fatal("missing fetch series")
	}
	if len(*series) != maxCallCountThreshold {
		t.Fatalf("retained timestamps = %d, want %d", len(*series), maxCallCountThreshold)
	}
	if got := counter.Count("fetch", time.Hour, now.Add(time.Second)); got != maxCallCountThreshold {
		t.Fatalf("saturated count = %d, want %d", got, maxCallCountThreshold)
	}
}

func TestCallCountToolCardinalityFailsClosedAndReclaimsExpiredSlots(t *testing.T) {
	counter := NewSlidingWindowCounter()
	now := time.Now().UTC()
	for i := 0; i < maxTrackedCallCountTools; i++ {
		if err := counter.Increment(fmt.Sprintf("tool-%d", i), now); err != nil {
			t.Fatal(err)
		}
	}

	if got := len(counter.calls); got != maxTrackedCallCountTools {
		t.Fatalf("tracked tool keys = %d, want %d", got, maxTrackedCallCountTools)
	}
	if err := counter.Increment("one-too-many", now); !errors.Is(err, ErrCallCounterCapacity) {
		t.Fatalf("capacity error = %v, want %v", err, ErrCallCounterCapacity)
	}

	// Once every retained timestamp is outside the maximum window, a new tool
	// can safely reclaim a slot without merging or losing live identity state.
	later := now.Add(maxCallCountWindow + time.Second)
	if err := counter.Increment("replacement", later); err != nil {
		t.Fatalf("replacement after expiry: %v", err)
	}
	if got := len(counter.calls); got != 1 {
		t.Fatalf("tracked tool keys after expiry = %d, want 1", got)
	}
}

func TestCallCountHandlesOutOfOrderTimestamps(t *testing.T) {
	counter := NewSlidingWindowCounter()
	now := time.Now().UTC()
	for _, age := range []time.Duration{10 * time.Minute, 50 * time.Minute, 5 * time.Minute, 2 * time.Hour, 30 * time.Minute} {
		if err := counter.Increment("fetch", now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	if got := counter.Count("fetch", time.Hour, now); got != 4 {
		t.Fatalf("out-of-order count = %d, want 4", got)
	}
}

func TestCallCountRejectsOversizedToolName(t *testing.T) {
	counter := NewSlidingWindowCounter()
	err := counter.Increment(strings.Repeat("x", maxCallCountToolNameBytes+1), time.Now().UTC())
	if !errors.Is(err, ErrCallCounterToolName) {
		t.Fatalf("tool-name error = %v, want %v", err, ErrCallCounterToolName)
	}
}

func TestCallCountValidationBounds(t *testing.T) {
	if err := validateCallCountCondition(&CallCountCondition{
		Gte:    maxCallCountThreshold + 1,
		Window: "1h",
	}); err == nil {
		t.Fatal("expected oversized threshold to fail validation")
	}
	if err := validateCallCountCondition(&CallCountCondition{
		Gte:    1,
		Window: (maxCallCountWindow + time.Second).String(),
	}); err == nil {
		t.Fatal("expected oversized window to fail validation")
	}
}
