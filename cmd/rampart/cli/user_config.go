// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// UserConfig holds persistent user-level settings. Values are loaded from
// ~/.rampart/config.yaml first, then overridden by environment variables.
// Priority for any field: env var > config file > zero value.
type UserConfig struct {
	// URL is the rampart proxy base URL. Env: RAMPART_URL.
	URL string `yaml:"url,omitempty"`
	// APIAddr is the API address for approve/deny/pending commands. Env: RAMPART_API.
	APIAddr string `yaml:"api,omitempty"`
	// Token is the auth token. Not stored in yaml; sourced from RAMPART_TOKEN env or ~/.rampart/token.
	Token string `yaml:"-"`
}

// userConfigPath returns the path to ~/.rampart/config.yaml.
func userConfigPath() (string, error) {
	dir, err := rampartDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// loadUserConfig reads ~/.rampart/config.yaml then overlays environment
// variables. The file is optional — missing file is not an error.
func loadUserConfig() (UserConfig, error) {
	var cfg UserConfig

	p, err := userConfigPath()
	if err != nil {
		return cfg, err
	}
	if data, err := os.ReadFile(p); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, err
		}
	}

	// Env vars override file values.
	if v := strings.TrimSpace(os.Getenv("RAMPART_URL")); v != "" {
		cfg.URL = v
	}
	if v := strings.TrimSpace(os.Getenv("RAMPART_API")); v != "" {
		cfg.APIAddr = v
	}

	cfg.URL = strings.TrimRight(cfg.URL, "/")
	cfg.APIAddr = strings.TrimRight(cfg.APIAddr, "/")

	if v := strings.TrimSpace(os.Getenv("RAMPART_TOKEN")); v != "" {
		cfg.Token = v
	} else if tok, err := readPersistedToken(); err == nil && tok != "" {
		cfg.Token = tok
	}

	return cfg, nil
}
