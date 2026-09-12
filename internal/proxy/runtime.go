// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import "github.com/peg/rampart/internal/build"

// RuntimeIdentity identifies one server start. InstanceID is freshness evidence,
// not authentication or proof that the process belongs to the current user.
// Process IDs, executable paths, and launch arguments remain in private state.
type RuntimeIdentity struct {
	InstanceID string `json:"instance_id,omitempty"`
	Version    string `json:"version"`
	Commit     string `json:"commit,omitempty"`
	Mode       string `json:"mode"`
}

// HealthResponse is the unauthenticated, credential-free health contract.
type HealthResponse struct {
	RuntimeIdentity
	Service       string `json:"service"`
	Status        string `json:"status"`
	UptimeSeconds *int   `json:"uptime_seconds"`
}

// RuntimeIdentity returns the identity shared by health and private serve.state.
func (s *Server) RuntimeIdentity() RuntimeIdentity {
	return RuntimeIdentity{InstanceID: s.instanceID, Version: build.Version, Commit: build.Commit, Mode: s.mode}
}
