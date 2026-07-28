// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPersistentCallCounterSharesHistoryAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-call-counts.json")
	now := time.Now().UTC()

	first, err := NewPersistentCallCounter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Increment("fetch", now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}

	second, err := NewPersistentCallCounter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Increment("fetch", now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := second.Count("fetch", time.Hour, now); got != 2 {
		t.Fatalf("shared count = %d, want 2", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not implement POSIX permission bits; Go reports 0666 for
	// regular files there regardless of the mode requested at creation time.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state permissions = %o, want no group/other access", info.Mode().Perm())
	}
}

func TestPersistentCallCounterConcurrentInstancesDoNotLoseUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-call-counts.json")
	now := time.Now().UTC()
	const writers = 32

	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			counter, err := NewPersistentCallCounter(path)
			if err == nil {
				err = counter.Increment("exec", now.Add(time.Duration(i)*time.Nanosecond))
			}
			if err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent increment: %v", err)
	}

	loaded, err := loadPersistentCallCounter(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Count("exec", time.Hour, now.Add(time.Second)); got != writers {
		t.Fatalf("persisted concurrent count = %d, want %d", got, writers)
	}
}

func TestPersistentCallCounterRejectsCorruptStateWithoutReplacingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-call-counts.json")
	want := []byte("{not-json}\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	counter, err := NewPersistentCallCounter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := counter.Increment("exec", time.Now().UTC()); err == nil {
		t.Fatal("expected corrupt state to fail closed")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("corrupt state was replaced: got %q, want %q", got, want)
	}
}

func TestPersistentCallCounterReclaimsExpiredToolSlots(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook-call-counts.json")
	old := time.Now().UTC().Add(-maxCallCountWindow - time.Hour)
	tools := make(map[string][]int64, maxTrackedCallCountTools)
	for i := 0; i < maxTrackedCallCountTools; i++ {
		tools[fmt.Sprintf("tool-%d", i)] = []int64{old.UnixNano()}
	}
	data, err := json.Marshal(persistentCallCounterState{
		Version: persistentCallCounterVersion,
		Tools:   tools,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	counter, err := NewPersistentCallCounter(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := counter.Increment("replacement", now); err != nil {
		t.Fatal(err)
	}
	if got := counter.Count("replacement", time.Hour, now); got != 1 {
		t.Fatalf("replacement count = %d, want 1", got)
	}

	loaded, err := loadPersistentCallCounter(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.calls) != 1 || loaded.calls["replacement"] == nil {
		t.Fatalf("persisted tools = %#v, want only replacement", loaded.calls)
	}
}
