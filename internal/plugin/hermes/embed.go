// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package hermes provides the bundled experimental Rampart Hermes Agent plugin.
package hermes

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed __init__.py plugin.yaml
var PluginFS embed.FS

// Version returns the bundled plugin version from plugin.yaml.
func Version() string {
	data, err := PluginFS.ReadFile("plugin.yaml")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "version" {
			continue
		}
		version := strings.Trim(strings.TrimSpace(value), `"'`)
		if version != "" {
			return version
		}
	}
	return "unknown"
}

// Extract writes the embedded plugin files to dir.
func Extract(dir string) error {
	files := []string{"__init__.py", "plugin.yaml"}
	for _, name := range files {
		data, err := PluginFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read embedded Hermes plugin file %q: %w", name, err)
		}
		dest := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("create Hermes plugin dir for %q: %w", dest, err)
		}
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			return fmt.Errorf("write Hermes plugin file %q: %w", dest, err)
		}
	}
	return nil
}
