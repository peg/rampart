// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"sync"
)

type sseHub struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
	closed  bool
}

func newSSEHub() *sseHub {
	return &sseHub{clients: make(map[chan []byte]struct{})}
}

func (h *sseHub) subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 32)
	h.mu.Lock()
	defer h.mu.Unlock()

	// If hub is closed (shutdown in progress), return immediately-closed channel.
	// Handler will see ok=false on receive and exit gracefully.
	if h.closed {
		close(ch)
		return ch, func() {} // no-op unsubscribe
	}

	h.clients[ch] = struct{}{}
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		// Check if channel still exists (might have been closed by sseHub.Close())
		if _, exists := h.clients[ch]; exists {
			delete(h.clients, ch)
			close(ch)
		}
	}
}

func (h *sseHub) broadcast(data []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Skip broadcast if hub is closed
	if h.closed {
		return
	}
	for ch := range h.clients {
		select {
		case ch <- data:
		default:
		}
	}
}

// Close disconnects all SSE clients. Called during server shutdown.
func (h *sseHub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for ch := range h.clients {
		close(ch)
		delete(h.clients, ch)
	}
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	// Admin-only: SSE stream carries real-time audit events for all agents.
	// Agent tokens must not receive cross-agent command/path/decision data.
	if !s.checkAdminAuth(w, r) {
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsubscribe := s.sse.subscribe()
	defer unsubscribe()

	if _, err := w.Write([]byte("data: {\"type\":\"connected\"}\n\n")); err != nil {
		return
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write(data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) broadcastSSE(msg map[string]any) {
	if s.sse == nil {
		return
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		s.logger.Error("proxy: sse marshal failed", "error", err)
		return
	}
	s.sse.broadcast([]byte("data: " + string(payload) + "\n\n"))
}
