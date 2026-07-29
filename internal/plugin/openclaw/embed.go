// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package openclaw provides the bundled Rampart OpenClaw plugin.
// The plugin is embedded into the Rampart binary at build time and
// extracted to a temp directory during `rampart setup openclaw`.
package openclaw

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed index.js package.json openclaw.plugin.json README.md hooks/rampart/HOOK.md hooks/rampart/index.js
var PluginFS embed.FS

var pluginFiles = []string{
	"index.js",
	"package.json",
	"openclaw.plugin.json",
	"README.md",
	"hooks/rampart/HOOK.md",
	"hooks/rampart/index.js",
}

// Version returns the bundled plugin version from package.json.
func Version() string {
	data, err := PluginFS.ReadFile("package.json")
	if err != nil {
		return "unknown"
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "unknown"
	}
	return pkg.Version
}

// Extract writes the embedded plugin files to dir and returns the path.
// The caller is responsible for cleanup if the returned path is a temp dir.
func Extract(dir string) error {
	for _, name := range pluginFiles {
		data, err := PluginFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read embedded plugin file %q: %w", name, err)
		}
		dest := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("create plugin dir for %q: %w", dest, err)
		}
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			return fmt.Errorf("write plugin file %q: %w", dest, err)
		}
	}
	return nil
}

// Current reports whether every managed plugin file is a regular file that
// exactly matches this binary's embedded payload. This catches same-version
// drift in package metadata and nested hook files, not only in index.js.
func Current(dir string) bool {
	for _, name := range pluginFiles {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		got, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		want, err := PluginFS.ReadFile(name)
		if err != nil || !bytes.Equal(got, want) {
			return false
		}
	}
	return true
}
