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
		data, err := os.ReadFile(f)
		if err != nil {
			logger.Error("engine: skip unreadable file", "path", f, "error", err)
			continue
		}

		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
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
				logger.Warn("engine: skip duplicate policy", "name", p.Name, "path", f)
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
