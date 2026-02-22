package engine

import (
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
	counter.Increment("fetch", now.Add(-10*time.Minute))
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match at count=1")
	}

	counter.Increment("fetch", now.Add(-5*time.Minute))
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match at count=2")
	}

	counter.Increment("fetch", now.Add(-1*time.Minute))
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
	counter.Increment("fetch", now.Add(-2*time.Hour))
	counter.Increment("fetch", now.Add(-45*time.Minute))
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match with only one call inside 1h window")
	}

	counter.Increment("fetch", now.Add(-5*time.Minute))
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
	counter.Increment("fetch", now.Add(-1*time.Minute))
	counter.Increment("fetch", now.Add(-30*time.Second))
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match when threshold is not met for specified tool")
	}

	counter.Increment("web_search", now.Add(-30*time.Minute))
	if matchCondition(cond, call, counter) {
		t.Fatal("expected no match at web_search count=1")
	}

	counter.Increment("web_search", now.Add(-10*time.Minute))
	if !matchCondition(cond, call, counter) {
		t.Fatal("expected match at web_search count=2")
	}
}
