// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package hermes provides the bundled experimental Rampart Hermes Agent plugin.
package hermes

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed __init__.py plugin.yaml
var PluginFS embed.FS

var pluginFiles = []string{"__init__.py", "plugin.yaml"}

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

// Managed reports whether dir is positively identifiable as a Rampart-owned
// Hermes plugin. The directory name alone is never treated as ownership.
func Managed(dir string) bool {
	for _, name := range pluginFiles {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		return false
	}
	var manifest struct {
		Name          string   `yaml:"name"`
		Author        string   `yaml:"author"`
		ProvidesHooks []string `yaml:"provides_hooks"`
	}
	if yaml.Unmarshal(manifestData, &manifest) != nil ||
		manifest.Name != "rampart" ||
		!strings.EqualFold(strings.TrimSpace(manifest.Author), "peg") ||
		!contains(manifest.ProvidesHooks, "pre_tool_call") {
		return false
	}
	runtimeData, err := os.ReadFile(filepath.Join(dir, "__init__.py"))
	return err == nil &&
		strings.Contains(string(runtimeData), "Rampart policy gate for Hermes Agent") &&
		strings.Contains(string(runtimeData), "def register(")
}

// Current reports whether the managed files exactly match this binary's
// embedded plugin. Unrelated regular files are intentionally ignored.
func Current(dir string) bool {
	if !Managed(dir) {
		return false
	}
	for _, name := range pluginFiles {
		if !embeddedFileCurrent(filepath.Join(dir, name), name) {
			return false
		}
	}
	return true
}

func embeddedFileCurrent(path, name string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	want, err := PluginFS.ReadFile(name)
	return err == nil && bytes.Equal(got, want)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func writeEmbeddedFiles(dir string) error {
	for _, name := range pluginFiles {
		data, err := PluginFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read embedded Hermes plugin file %q: %w", name, err)
		}
		dest := filepath.Join(dir, name)
		if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("replace staged Hermes plugin file %q: %w", dest, err)
		}
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			return fmt.Errorf("write Hermes plugin file %q: %w", dest, err)
		}
	}
	return nil
}

// Extract installs the embedded plugin transactionally. It refuses links and
// same-name directories without positive Rampart ownership, stages a complete
// replacement on the target filesystem, swaps only Rampart-managed files, and
// restores the prior files if any activation or validation step fails. Other
// operator-owned files in the plugin directory remain untouched.
func Extract(dir string) error {
	return extractWithRename(dir, os.Rename)
}

func extractWithRename(dir string, rename func(string, string) error) error {
	dir = filepath.Clean(dir)
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create Hermes plugin parent %q: %w", parent, err)
	}

	hadPrior := false
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace symlinked Hermes plugin directory %s", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("refusing to replace non-directory Hermes plugin path %s", dir)
		}
		if !Managed(dir) {
			return fmt.Errorf("refusing to replace non-Rampart Hermes plugin directory %s", dir)
		}
		hadPrior = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect Hermes plugin directory %s: %w", dir, err)
	}

	txnDir, err := os.MkdirTemp(parent, ".rampart-hermes-install-*")
	if err != nil {
		return fmt.Errorf("create Hermes plugin transaction: %w", err)
	}
	preserveTxn := false
	defer func() {
		if !preserveTxn {
			_ = os.RemoveAll(txnDir)
		}
	}()
	stageDir := filepath.Join(txnDir, "stage")
	backupDir := filepath.Join(txnDir, "backup")
	if err := os.Mkdir(stageDir, 0o755); err != nil {
		return fmt.Errorf("create staged Hermes plugin: %w", err)
	}
	if err := writeEmbeddedFiles(stageDir); err != nil {
		return err
	}
	if !Current(stageDir) {
		return fmt.Errorf("staged Hermes plugin failed integrity validation")
	}

	if hadPrior {
		if err := os.Mkdir(backupDir, 0o700); err != nil {
			return fmt.Errorf("create Hermes plugin backup: %w", err)
		}
	} else if err := os.Mkdir(dir, 0o755); err != nil {
		return fmt.Errorf("create Hermes plugin directory: %w", err)
	}

	var backedUp []string
	var activated []string
	rollback := func(cause error) error {
		var rollbackErrs []string
		for i := len(activated) - 1; i >= 0; i-- {
			name := activated[i]
			target := filepath.Join(dir, name)
			if !embeddedFileCurrent(target, name) {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("refusing to remove changed replacement %s", target))
				continue
			}
			if err := os.Remove(target); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("remove replacement %s: %v", target, err))
			}
		}
		for i := len(backedUp) - 1; i >= 0; i-- {
			name := backedUp[i]
			target := filepath.Join(dir, name)
			if _, err := os.Lstat(target); err == nil {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("restore %s: target is occupied", name))
				continue
			} else if !os.IsNotExist(err) {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("restore %s: %v", name, err))
				continue
			}
			if err := rename(filepath.Join(backupDir, name), target); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("restore %s: %v", name, err))
			}
		}
		if !hadPrior {
			_ = os.Remove(dir) // succeeds only when no unexpected content appeared
		}
		if len(rollbackErrs) > 0 {
			preserveTxn = true
			return fmt.Errorf("%w (rollback incomplete: %s; prior files preserved at %s)", cause, strings.Join(rollbackErrs, "; "), backupDir)
		}
		return cause
	}

	if hadPrior {
		for _, name := range pluginFiles {
			if err := rename(filepath.Join(dir, name), filepath.Join(backupDir, name)); err != nil {
				return rollback(fmt.Errorf("back up existing Hermes plugin file %s: %w", name, err))
			}
			backedUp = append(backedUp, name)
		}
	}
	for _, name := range pluginFiles {
		if err := rename(filepath.Join(stageDir, name), filepath.Join(dir, name)); err != nil {
			return rollback(fmt.Errorf("activate Hermes plugin file %s: %w", name, err))
		}
		activated = append(activated, name)
	}
	if !Current(dir) {
		return rollback(fmt.Errorf("installed Hermes plugin failed integrity validation"))
	}
	_ = os.RemoveAll(filepath.Join(dir, "__pycache__"))

	if err := os.RemoveAll(txnDir); err != nil {
		preserveTxn = true
		return fmt.Errorf("installed Hermes plugin, but prior transaction cleanup failed at %s: %w", txnDir, err)
	}
	return nil
}
