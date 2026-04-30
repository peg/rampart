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

// resolveServeURLStrict determines the serve URL using this priority:
//  1. Explicit flag value (if non-empty)
//  2. RAMPART_URL / config url
//  3. RAMPART_SERVE_URL / config serve_url (compatibility alias)
//  4. serve.state file in ~/.rampart/
//  5. Provided fallback URL
func resolveServeURLStrict(flagValue, fallback string) (string, error) {
	if flagValue != "" {
		return strings.TrimRight(flagValue, "/"), nil
	}

	if cfg, err := loadUserConfig(); err == nil {
		if cfg.URL != "" {
			return cfg.URL, nil
		}
		if cfg.ServeURL != "" {
			return cfg.ServeURL, nil
		}
	} else {
		return "", err
	}

	// Try state file.
	if dir, err := rampartDir(); err == nil {
		statePath := filepath.Join(dir, serveStateFile)
		if data, err := os.ReadFile(statePath); err == nil {
			var state serveState
			if json.Unmarshal(data, &state) == nil && state.URL != "" {
				return state.URL, nil
			}
		}
	}

	return fallback, nil
}

// resolveServeURL is a best-effort helper for legacy/internal call sites that
// prefer fallback behavior over surfacing configuration errors.
func resolveServeURL(flagValue string) string {
	resolved, err := resolveServeURLStrict(flagValue, fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return fmt.Sprintf("http://localhost:%d", defaultServePort)
	}
	return resolved
}
