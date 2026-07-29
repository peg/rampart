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
	"bytes"
	"fmt"
	"io"
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

// safeUnmarshal wraps strict YAML decoding with three protections:
//  1. Input size cap — rejects data larger than maxPolicyFileSize.
//  2. Panic recovery — catches panics from malformed/adversarial YAML and
//     returns them as errors instead of crashing the process.
//  3. Known-field validation — rejects misspelled policy fields instead of
//     silently broadening a rule when an unknown condition decodes as empty.
func safeUnmarshal(data []byte, v any) (retErr error) {
	if len(data) > maxPolicyFileSize {
		return fmt.Errorf("policy file too large (%d bytes, max %d)", len(data), maxPolicyFileSize)
	}
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("yaml parse panic: %v", r)
		}
	}()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("policy must contain exactly one YAML document")
	} else if err != io.EOF {
		return err
	}
	return nil
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

// Load reads all *.yaml files from the directory and merges them into a single
// Config. A present but invalid policy is an error: silently skipping a broken
// deny file would widen the effective policy.
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
		return nil, fmt.Errorf("engine: load config dir %q: %w", absDir, err)
	}

	if merged.DefaultAction == "" && dirCfg.DefaultAction != "" {
		merged.DefaultAction = dirCfg.DefaultAction
	}
	if merged.Notify == nil && dirCfg.Notify != nil {
		merged.Notify = dirCfg.Notify
	}
	// On-disk policies override embedded ones with the same name.
	// Rationale: if a user (or `rampart upgrade`) placed a policy file on disk,
	// it should take effect. An attacker with write access to the policies dir
	// can already add new catch-all allow rules, so protecting embedded names
	// provides no real security benefit while breaking upgrade workflows.
	dirNames := make(map[string]bool)
	for _, p := range dirCfg.Policies {
		dirNames[p.Name] = true
	}
	// Remove embedded policies that are superseded by on-disk versions.
	if len(dirNames) > 0 {
		filtered := merged.Policies[:0]
		for _, p := range merged.Policies {
			if dirNames[p.Name] {
				s.logger.Debug("engine: on-disk policy overrides embedded", "name", p.Name)
				continue
			}
			filtered = append(filtered, p)
		}
		merged.Policies = filtered
		// Rebuild seen set after filtering.
		seen = make(map[string]bool)
		for _, p := range merged.Policies {
			seen[p.Name] = true
		}
	}
	for _, p := range dirCfg.Policies {
		if seen[p.Name] {
			continue // shouldn't happen, but guard against dir-internal dupes
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
// The first file that specifies default_action wins. Present invalid files fail
// the load so malformed restrictions are never silently omitted.
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
			return nil, fmt.Errorf("engine: policy %q is too large (%d bytes, max %d)", f, info.Size(), maxPolicyFileSize)
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("engine: read policy %q: %w", f, err)
		}

		var cfg Config
		if err := safeUnmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("engine: parse policy %q: %w", f, err)
		}
		if err := cfg.validate(); err != nil {
			return nil, fmt.Errorf("engine: invalid policy file %q: %w", f, err)
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
				return nil, fmt.Errorf("engine: policy in %q has no name", f)
			}
			if seen[p.Name] {
				return nil, fmt.Errorf("engine: duplicate policy name %q in %q", p.Name, f)
			}
			p.FilePath = f
			seen[p.Name] = true
			merged.Policies = append(merged.Policies, p)
		}
		for pattern, compiled := range cfg.responseRegexCache {
			merged.responseRegexCache[pattern] = compiled
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
// An empty extra path disables layering. Once a path is configured, every load
// failure is an error so repository restrictions cannot disappear through
// malformed input or a file-removal race.
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

// Load loads the base config and merges the extra project policy on top. An
// empty project path is optional, but a configured path must remain readable
// and valid so enforcement callers fail closed.
func (s *LayeredStore) Load() (*Config, error) {
	cfg, err := s.base.Load()
	if err != nil {
		return nil, err
	}
	if s.extra == "" {
		return cfg, nil
	}
	info, err := os.Stat(s.extra)
	if err != nil {
		return nil, fmt.Errorf("engine: inspect project policy %q: %w", s.extra, err)
	}
	if info.Size() > maxPolicyFileSize {
		return nil, fmt.Errorf("engine: project policy %q is too large (%d bytes, max %d)", s.extra, info.Size(), maxPolicyFileSize)
	}
	data, err := os.ReadFile(s.extra)
	if err != nil {
		return nil, fmt.Errorf("engine: read project policy %q: %w", s.extra, err)
	}
	var extraCfg Config
	if err := safeUnmarshal(data, &extraCfg); err != nil {
		return nil, fmt.Errorf("engine: parse project policy %q: %w", s.extra, err)
	}
	if err := extraCfg.validate(); err != nil {
		return nil, fmt.Errorf("engine: validate project policy %q: %w", s.extra, err)
	}
	for _, policy := range extraCfg.Policies {
		for index, rule := range policy.Rules {
			action, _ := rule.ParseAction()
			if action == ActionWebhook {
				return nil, fmt.Errorf("engine: project policy %q contains forbidden webhook action in policy %q rule %d", s.extra, policy.Name, index)
			}
		}
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
		// Mark policy as coming from project policy file.
		p.Source = "project"
		if p.FilePath == "" {
			p.FilePath = projectPath
		}
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
