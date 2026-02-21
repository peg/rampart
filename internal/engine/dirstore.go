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

package engine

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// maxPolicyFileSize is the maximum size of a policy YAML file we will parse.
// This prevents billion-laughs / anchor-expansion DoS where a small YAML input
// expands to an arbitrarily large in-memory structure.
// 1MB is orders of magnitude larger than any reasonable policy file.
const maxPolicyFileSize = 1 << 20 // 1 MiB

// safeUnmarshal wraps yaml.Unmarshal with two protections:
//  1. Input size cap — rejects data larger than maxPolicyFileSize.
//  2. Panic recovery — catches panics from malformed/adversarial YAML and
//     returns them as errors instead of crashing the process.
func safeUnmarshal(data []byte, v any) (retErr error) {
	if len(data) > maxPolicyFileSize {
		return fmt.Errorf("policy file too large (%d bytes, max %d)", len(data), maxPolicyFileSize)
	}
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("yaml parse panic: %v", r)
		}
	}()
	return yaml.Unmarshal(data, v)
}

// PolicyStore is the interface for loading policy configurations.
// Implemented by FileStore, DirStore, and MultiStore.
type PolicyStore interface {
	Load() (*Config, error)
	Path() string
}

// DirStore loads and merges all *.yaml files from a directory.
// Files are loaded in sorted order for deterministic behavior.
type DirStore struct {
	dir    string
	logger *slog.Logger
}

// NewDirStore creates a policy store that reads all YAML files from dir.
func NewDirStore(dir string, logger *slog.Logger) *DirStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &DirStore{dir: dir, logger: logger}
}

// Load reads all *.yaml files from the directory, merges them into a single Config.
// Invalid files are logged and skipped. Returns error only if the directory
// cannot be read at all.
func (s *DirStore) Load() (*Config, error) {
	absDir, err := filepath.Abs(s.dir)
	if err != nil {
		return nil, fmt.Errorf("engine: resolve dir %q: %w", s.dir, err)
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist yet — return empty config (not an error).
			s.logger.Debug("engine: config dir does not exist, skipping", "dir", absDir)
			return &Config{Version: "1"}, nil
		}
		return nil, fmt.Errorf("engine: read dir %q: %w", absDir, err)
	}

	// Collect and sort yaml files.
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml" {
			files = append(files, filepath.Join(absDir, name))
		}
	}
	sort.Strings(files)

	if len(files) == 0 {
		s.logger.Debug("engine: no yaml files in config dir", "dir", absDir)
		return &Config{Version: "1"}, nil
	}

	return mergeYAMLFiles(files, s.logger)
}

// Path returns the directory path.
func (s *DirStore) Path() string {
	return s.dir
}

// MultiStore combines a primary config file with additional files from a directory.
type MultiStore struct {
	file   string // primary config file (may be empty)
	dir    string // directory of additional configs (may be empty)
	logger *slog.Logger
}

// NewMultiStore creates a store that loads from a file and/or directory.
// Either file or dir may be empty.
func NewMultiStore(file, dir string, logger *slog.Logger) *MultiStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &MultiStore{file: file, dir: dir, logger: logger}
}

// Load reads the primary file (if set) and all directory files, merging them.
func (s *MultiStore) Load() (*Config, error) {
	var allFiles []string

	// Primary config file first.
	if s.file != "" {
		absFile, err := filepath.Abs(s.file)
		if err != nil {
			return nil, fmt.Errorf("engine: resolve file %q: %w", s.file, err)
		}
		allFiles = append(allFiles, absFile)
	}

	// Then directory files in sorted order.
	if s.dir != "" {
		absDir, err := filepath.Abs(s.dir)
		if err != nil {
			return nil, fmt.Errorf("engine: resolve dir %q: %w", s.dir, err)
		}

		entries, err := os.ReadDir(absDir)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("engine: read dir %q: %w", absDir, err)
		}
		if err == nil {
			var dirFiles []string
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml" {
					full := filepath.Join(absDir, name)
					// Skip if same as primary file.
					if s.file != "" {
						absFile, _ := filepath.Abs(s.file)
						if full == absFile {
							continue
						}
					}
					dirFiles = append(dirFiles, full)
				}
			}
			sort.Strings(dirFiles)
			allFiles = append(allFiles, dirFiles...)
		} else {
			s.logger.Debug("engine: config dir does not exist, skipping", "dir", absDir)
		}
	}

	if len(allFiles) == 0 {
		return nil, fmt.Errorf("engine: no config file or directory specified")
	}

	return mergeYAMLFiles(allFiles, s.logger)
}

// Path returns a description of the sources.
func (s *MultiStore) Path() string {
	if s.file != "" && s.dir != "" {
		return fmt.Sprintf("%s + %s/", s.file, s.dir)
	}
	if s.file != "" {
		return s.file
	}
	return s.dir + "/"
}

// MixedStore combines a primary PolicyStore (e.g. MemoryStore) with additional
// YAML files from a directory. Useful when the primary config is not file-based.
type MixedStore struct {
	primary PolicyStore
	dir     string
	logger  *slog.Logger
}

// NewMixedStore creates a store that merges a primary PolicyStore with a directory.
func NewMixedStore(primary PolicyStore, dir string, logger *slog.Logger) *MixedStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &MixedStore{primary: primary, dir: dir, logger: logger}
}

// Load reads the primary store and all directory files, merging them.
func (s *MixedStore) Load() (*Config, error) {
	// Load primary store first.
	merged, err := s.primary.Load()
	if err != nil {
		return nil, fmt.Errorf("engine: load primary store: %w", err)
	}

	// Load directory files.
	if s.dir == "" {
		return merged, nil
	}

	absDir, err := filepath.Abs(s.dir)
	if err != nil {
		return nil, fmt.Errorf("engine: resolve dir %q: %w", s.dir, err)
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.Debug("engine: config dir does not exist, skipping", "dir", absDir)
			return merged, nil
		}
		return nil, fmt.Errorf("engine: read dir %q: %w", absDir, err)
	}

	var dirFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml" {
			dirFiles = append(dirFiles, filepath.Join(absDir, name))
		}
	}
	sort.Strings(dirFiles)

	if len(dirFiles) == 0 {
		return merged, nil
	}

	// Merge directory configs into merged.
	seen := make(map[string]bool)
	for _, p := range merged.Policies {
		seen[p.Name] = true
	}

	dirCfg, err := mergeYAMLFiles(dirFiles, s.logger)
	if err != nil {
		// Log and return primary only; directory errors are non-fatal.
		s.logger.Warn("engine: failed to load config dir, using primary only", "dir", absDir, "error", err)
		return merged, nil
	}

	if merged.DefaultAction == "" && dirCfg.DefaultAction != "" {
		merged.DefaultAction = dirCfg.DefaultAction
	}
	if merged.Notify == nil && dirCfg.Notify != nil {
		merged.Notify = dirCfg.Notify
	}
	for _, p := range dirCfg.Policies {
		if seen[p.Name] {
			// Debug-level: duplicates between the primary store (e.g. embedded standard)
			// and the config dir are expected — the primary always takes precedence.
			s.logger.Debug("engine: skip duplicate policy from config dir", "name", p.Name)
			continue
		}
		seen[p.Name] = true
		merged.Policies = append(merged.Policies, p)
	}
	if merged.responseRegexCache == nil {
		merged.responseRegexCache = make(map[string]*regexp.Regexp)
	}
	for k, v := range dirCfg.responseRegexCache {
		merged.responseRegexCache[k] = v
	}

	return merged, nil
}

// Path returns a description of this store's sources.
func (s *MixedStore) Path() string {
	return s.primary.Path() + " + " + s.dir + "/"
}

// mergeYAMLFiles reads and merges multiple YAML policy files into one Config.
// The first file that specifies default_action wins. Invalid files are skipped.
func mergeYAMLFiles(files []string, logger *slog.Logger) (*Config, error) {
	merged := &Config{
		Version:            "1",
		responseRegexCache: make(map[string]*regexp.Regexp),
	}
	seen := make(map[string]bool) // track policy names for dedup
	var loadedFiles []string

	for _, f := range files {
		// Check file size before reading to avoid loading huge files into memory.
		if info, statErr := os.Stat(f); statErr == nil && info.Size() > maxPolicyFileSize {
			logger.Error("engine: skip oversized policy file", "path", f, "size", info.Size(), "max", maxPolicyFileSize)
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			logger.Error("engine: skip unreadable file", "path", f, "error", err)
			continue
		}

		var cfg Config
		if err := safeUnmarshal(data, &cfg); err != nil {
			logger.Error("engine: skip invalid yaml", "path", f, "error", err)
			continue
		}

		// Take default_action from first file that specifies one.
		if merged.DefaultAction == "" && cfg.DefaultAction != "" {
			merged.DefaultAction = cfg.DefaultAction
		}

		// Take notify from first file that specifies one.
		if merged.Notify == nil && cfg.Notify != nil {
			merged.Notify = cfg.Notify
		}

		// Merge policies, skipping duplicates.
		for _, p := range cfg.Policies {
			if p.Name == "" {
				logger.Error("engine: skip unnamed policy", "path", f)
				continue
			}
			if seen[p.Name] {
				logger.Debug("engine: skip duplicate policy", "name", p.Name, "path", f)
				continue
			}
			seen[p.Name] = true

			// Validate rules.
			valid := true
			for j, r := range p.Rules {
				if _, err := r.ParseAction(); err != nil {
					logger.Error("engine: skip policy with invalid rule", "policy", p.Name, "rule", j, "path", f, "error", err)
					valid = false
					break
				}
				if err := compileResponseRegexes(r.When, merged.responseRegexCache); err != nil {
					logger.Error("engine: skip policy with invalid regex", "policy", p.Name, "rule", j, "path", f, "error", err)
					valid = false
					break
				}
			}
			if valid {
				merged.Policies = append(merged.Policies, p)
			}
		}

		loadedFiles = append(loadedFiles, f)
	}

	if len(loadedFiles) == 0 {
		return nil, fmt.Errorf("engine: no valid policy files found")
	}

	logger.Info("engine: loaded policy files", "files", loadedFiles, "policies", len(merged.Policies))
	return merged, nil
}

// LayeredStore wraps a base PolicyStore and layers an optional extra policy file on top.
// The base store's DefaultAction and Notify take precedence. Deny wins across both layers.
// If the extra file fails to load, the base store is used alone (non-fatal degradation).
type LayeredStore struct {
	base   PolicyStore
	extra  string // path to extra policy file; empty = disabled
	logger *slog.Logger
}

// NewLayeredStore creates a LayeredStore. If extraPath is empty, it behaves identically to base.
func NewLayeredStore(base PolicyStore, extraPath string, logger *slog.Logger) *LayeredStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &LayeredStore{base: base, extra: extraPath, logger: logger}
}

// Load loads the base config and merges the extra project policy on top.
// If the extra file is missing or invalid, the base config is returned unchanged (non-fatal).
func (s *LayeredStore) Load() (*Config, error) {
	cfg, err := s.base.Load()
	if err != nil {
		return nil, err
	}
	if s.extra == "" {
		return cfg, nil
	}
	if info, statErr := os.Stat(s.extra); statErr == nil && info.Size() > maxPolicyFileSize {
		s.logger.Warn("project policy too large, using global policy only", "path", s.extra, "size", info.Size())
		return cfg, nil
	}
	data, err := os.ReadFile(s.extra)
	if err != nil {
		s.logger.Warn("project policy unreadable, using global policy only", "path", s.extra, "error", err)
		return cfg, nil
	}
	var extraCfg Config
	if err := safeUnmarshal(data, &extraCfg); err != nil {
		s.logger.Warn("project policy parse error, using global policy only", "path", s.extra, "error", err)
		return cfg, nil
	}
	return mergeProjectPolicy(cfg, &extraCfg, s.extra, s.logger), nil
}

// Path returns a combined description of both sources.
func (s *LayeredStore) Path() string {
	if s.extra == "" {
		return s.base.Path()
	}
	return s.base.Path() + " + " + s.extra
}

// mergeProjectPolicy merges project policies into the base config.
// Base wins for DefaultAction and Notify. Duplicate policy names are skipped with a warning.
func mergeProjectPolicy(base, project *Config, projectPath string, logger *slog.Logger) *Config {
	result := *base
	result.Policies = make([]Policy, len(base.Policies))
	copy(result.Policies, base.Policies)

	seen := make(map[string]bool, len(base.Policies))
	for _, p := range base.Policies {
		seen[p.Name] = true
	}
	for _, p := range project.Policies {
		if seen[p.Name] {
			logger.Warn("project policy: duplicate policy name skipped", "name", p.Name, "project", projectPath)
			continue
		}
		seen[p.Name] = true
		result.Policies = append(result.Policies, p)
	}
	// Deep-copy responseRegexCache to avoid aliasing base's map.
	newCache := make(map[string]*regexp.Regexp, len(base.responseRegexCache)+len(project.responseRegexCache))
	for k, v := range base.responseRegexCache {
		newCache[k] = v
	}
	for k, v := range project.responseRegexCache {
		newCache[k] = v
	}
	result.responseRegexCache = newCache
	return &result
}
