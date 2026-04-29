// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// serveState is written by `rampart serve` so other commands (doctor, watch, log)
// can discover the serve URL and port without requiring flags or env vars.
type serveState struct {
	URL     string `json:"url"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Started string `json:"started"`
}

const serveStateFile = "serve.state"

// writeServeState writes the serve state to ~/.rampart/serve.state.
func writeServeState(dir string, port, pid int, tls bool) error {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	state := serveState{
		URL:     fmt.Sprintf("%s://localhost:%d", scheme, port),
		Port:    port,
		PID:     pid,
		Started: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, serveStateFile), data, 0o600)
}

// removeServeState removes the state file on shutdown.
func removeServeState(dir string) {
	os.Remove(filepath.Join(dir, serveStateFile))
}

// resolveServeURL determines the serve URL using this priority:
//  1. Explicit flag value (if non-empty)
//  2. RAMPART_URL / config url  (via loadUserConfig: env overrides file)
//  3. RAMPART_SERVE_URL env var
//  4. serve.state file in ~/.rampart/ (written by rampart serve)
//  5. Default port (9090)
func resolveServeURL(flagValue string) string {
	if flagValue != "" {
		return strings.TrimRight(flagValue, "/")
	}

	cfg, _ := loadUserConfig()
	if cfg.URL != "" {
		return cfg.URL
	}
	if u := strings.TrimSpace(os.Getenv("RAMPART_SERVE_URL")); u != "" {
		return strings.TrimRight(u, "/")
	}

	// Runtime state written by rampart serve.
	if dir, err := rampartDir(); err == nil {
		statePath := filepath.Join(dir, serveStateFile)
		if data, err := os.ReadFile(statePath); err == nil {
			var state serveState
			if json.Unmarshal(data, &state) == nil && state.URL != "" {
				return state.URL
			}
		}
	}

	return fmt.Sprintf("http://localhost:%d", defaultServePort)
}


