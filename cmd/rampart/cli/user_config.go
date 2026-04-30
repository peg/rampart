// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// UserConfig holds persistent user-level settings loaded from ~/.rampart/config.yaml.
// Environment variables override file values.
type UserConfig struct {
	// URL is the primary base URL for Rampart runtime traffic. Env: RAMPART_URL.
	URL string `yaml:"url,omitempty"`
	// ServeURL is a backward-compatible alias for URL. Env: RAMPART_SERVE_URL.
	ServeURL string `yaml:"serve_url,omitempty"`
	// APIAddr is an advanced override for approval/control API flows. Env: RAMPART_API.
	APIAddr string `yaml:"api,omitempty"`
}

func userConfigPath() (string, error) {
	dir, err := rampartDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

func loadUserConfig() (UserConfig, error) {
	var cfg UserConfig

	p, err := userConfigPath()
	if err != nil {
		return cfg, err
	}
	if data, err := os.ReadFile(p); err == nil {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return cfg, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return cfg, err
	}

	if v := strings.TrimSpace(os.Getenv("RAMPART_URL")); v != "" {
		cfg.URL = v
	}
	if v := strings.TrimSpace(os.Getenv("RAMPART_SERVE_URL")); v != "" {
		cfg.ServeURL = v
	}
	if v := strings.TrimSpace(os.Getenv("RAMPART_API")); v != "" {
		cfg.APIAddr = v
	}

	cfg.URL = strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	cfg.ServeURL = strings.TrimRight(strings.TrimSpace(cfg.ServeURL), "/")
	cfg.APIAddr = strings.TrimRight(strings.TrimSpace(cfg.APIAddr), "/")

	return cfg, nil
}

func resolveTokenValue() (string, string) {
	if v := strings.TrimSpace(os.Getenv("RAMPART_TOKEN")); v != "" {
		return v, "env"
	}
	if tok, err := readPersistedToken(); err == nil && tok != "" {
		return tok, "file"
	}
	return "", ""
}
