// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

// Package opencode provides Rampart's experimental OpenCode policy plugin.
package opencode

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
)

//go:embed rampart.js
var source []byte

const ownershipHeader = "// Rampart OpenCode policy gate\n// Managed by rampart setup opencode; template v1.\n"

// Managed recognizes the versioned ownership header at the start of a file.
// A same-name file or an incidental mention of Rampart is not ownership.
func Managed(data []byte) bool {
	return bytes.HasPrefix(data, []byte(ownershipHeader))
}

// Render binds the embedded dependency-free plugin to this Rampart executable.
// JSON encoding preserves paths with spaces, quotes, and JavaScript metacharacters.
func Render(binary string) ([]byte, error) {
	if !filepath.IsAbs(binary) {
		return nil, fmt.Errorf("OpenCode plugin requires an absolute Rampart executable path")
	}
	placeholder := []byte("__RAMPART_BINARY_JSON__")
	if bytes.Count(source, placeholder) != 1 || !Managed(source) {
		return nil, fmt.Errorf("invalid embedded OpenCode plugin template")
	}
	encoded, err := json.Marshal(binary)
	if err != nil {
		return nil, fmt.Errorf("encode OpenCode executable binding: %w", err)
	}
	return bytes.Replace(source, placeholder, encoded, 1), nil
}
