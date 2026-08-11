// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"strings"
	"sync"
	"testing"

	"github.com/peg/rampart/internal/audit"
)

func TestSSEHubClose_NoDoubleClosePanic(t *testing.T) {
	hub := newSSEHub()
	ch, unsub := hub.subscribe()

	// Close the hub (simulating shutdown)
	hub.Close()

	// Unsubscribe should not panic even though Close() already closed the channel
	unsub()

	// Channel should be closed
	_, ok := <-ch
	if ok {
		t.Error("expected channel to be closed")
	}
}

func TestSSEHubSubscribeAfterClose(t *testing.T) {
	hub := newSSEHub()
	hub.Close()

	// Subscribe after close should return immediately-closed channel
	ch, unsub := hub.subscribe()
	defer unsub()

	// Channel should already be closed
	_, ok := <-ch
	if ok {
		t.Error("expected channel to be closed for post-Close subscription")
	}
}

func TestSSEHubBroadcastAfterClose(t *testing.T) {
	hub := newSSEHub()
	hub.Close()

	// Broadcast after close should not panic
	hub.broadcast([]byte("test"))
}

func TestSSEHubConcurrentCloseAndBroadcast(t *testing.T) {
	hub := newSSEHub()

	// Subscribe some clients
	for i := 0; i < 10; i++ {
		_, _ = hub.subscribe()
	}

	// Concurrent close and broadcast - should not panic or race
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			hub.broadcast([]byte("test"))
		}
	}()

	go func() {
		defer wg.Done()
		hub.Close()
	}()

	wg.Wait()
}

func TestSSEHubConcurrentSubscribeAndClose(t *testing.T) {
	hub := newSSEHub()

	var wg sync.WaitGroup
	wg.Add(2)

	// Concurrent subscribe and close
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			ch, unsub := hub.subscribe()
			// Drain channel to avoid blocking
			go func(c chan []byte) {
				for range c {
				}
			}(ch)
			_ = unsub // don't call, let Close handle it
		}
	}()

	go func() {
		defer wg.Done()
		hub.Close()
	}()

	wg.Wait()
}

func TestBroadcastAuditEventRedactsCredentials(t *testing.T) {
	srv := &Server{sse: newSSEHub()}
	ch, unsubscribe := srv.sse.subscribe()
	defer unsubscribe()

	srv.broadcastAuditEvent(audit.Event{
		Request: map[string]any{
			"command":        "curl -H 'Authorization: Bearer live-secret' https://example.test",
			"command_b64":    "encoded-secret",
			"custom_api_key": "short-secret",
		},
	})

	payload := string(<-ch)
	for _, secret := range []string{"live-secret", "encoded-secret", "short-secret"} {
		if strings.Contains(payload, secret) {
			t.Fatalf("SSE audit payload leaked %q: %s", secret, payload)
		}
	}
	if !strings.Contains(payload, "[REDACTED]") {
		t.Fatalf("SSE audit payload did not contain a redaction marker: %s", payload)
	}
}
