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

package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/peg/rampart/internal/policy"
	"gopkg.in/yaml.v3"
)

// learnRequest is the request body for POST /v1/rules/learn.
type learnRequest struct {
	Tool     string `json:"tool"`
	Args     string `json:"args"`
	Decision string `json:"decision"`
	Source   string `json:"source"`
	Agent    string `json:"agent"`
	Session  string `json:"session"`
}

// learnResponse is the response body for POST /v1/rules/learn.
type learnResponse struct {
	RuleName string `json:"rule_name"`
	Tool     string `json:"tool"`
	Pattern  string `json:"pattern"`
	Decision string `json:"decision"`
	Source   string `json:"source"`
}

// userOverridesPolicy is the YAML structure for user-overrides.yaml.
type userOverridesPolicy struct {
	Policies []userOverrideEntry `yaml:"policies"`
}

type userOverrideEntry struct {
	Name  string             `yaml:"name"`
	Match userOverrideMatch  `yaml:"match"`
	Rules []userOverrideRule `yaml:"rules"`
}

// toolList unmarshals both scalar ("exec") and sequence (["exec"]) YAML forms.
type toolList []string

func (t *toolList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try sequence first
	var seq []string
	if err := unmarshal(&seq); err == nil {
		*t = seq
		return nil
	}
	// Fall back to scalar string
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	*t = []string{s}
	return nil
}

type userOverrideMatch struct {
	Tool toolList `yaml:"tool"`
}

type userOverrideRule struct {
	When    userOverrideWhen `yaml:"when"`
	Action  string           `yaml:"action"`
	Message string           `yaml:"message"`
}

type userOverrideWhen struct {
	CommandMatches []string `yaml:"command_matches,omitempty,flow"`
}

func (s *Server) handleLearnRule(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	var req learnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Tool == "" || req.Args == "" {
		writeError(w, http.StatusBadRequest, "tool and args are required")
		return
	}
	if req.Decision != "allow" && req.Decision != "deny" {
		writeError(w, http.StatusBadRequest, "decision must be \"allow\" or \"deny\"")
		return
	}

	// Compute smart glob pattern.
	pattern := policy.BuildAllowPattern(req.Args)
	hash := policy.HashPattern(pattern)
	ruleName := fmt.Sprintf("user-allow-%s", hash)

	// Resolve overrides path.
	home, err := os.UserHomeDir()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve home directory")
		return
	}
	overridesPath := filepath.Join(home, ".rampart", "policies", "user-overrides.yaml")

	// Ensure directory exists.
	if err := os.MkdirAll(filepath.Dir(overridesPath), 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create policies dir: %v", err))
		return
	}

	s.policyWriteMu.Lock()
	defer s.policyWriteMu.Unlock()

	// Read or initialize the file.
	var cfg userOverridesPolicy
	data, err := os.ReadFile(overridesPath)
	if err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to parse user-overrides.yaml: %v", err))
			return
		}
	}
	// If file doesn't exist, cfg.Policies will be nil — that's fine.

	// Check for duplicate pattern (by rule name).
	for _, p := range cfg.Policies {
		if p.Name == ruleName {
			// 409 — return existing rule.
			writeJSON(w, http.StatusConflict, learnResponse{
				RuleName: ruleName,
				Tool:     req.Tool,
				Pattern:  pattern,
				Decision: req.Decision,
				Source:   req.Source,
			})
			return
		}
	}

	// Build new entry.
	entry := userOverrideEntry{
		Name: ruleName,
		Match: userOverrideMatch{
			Tool: []string{req.Tool},
		},
		Rules: []userOverrideRule{
			{
				When: userOverrideWhen{
					CommandMatches: []string{pattern},
				},
				Action:  req.Decision,
				Message: fmt.Sprintf("User %s (always) via %s", req.Decision, req.Source),
			},
		},
	}
	cfg.Policies = append(cfg.Policies, entry)

	// Marshal and write atomically.
	out, err := yaml.Marshal(&cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal policy: %v", err))
		return
	}

	header := "# Rampart user override policies\n# Auto-generated entries are added here when you click \"Always Allow\"\n# This file is never overwritten by upgrades or rampart setup\n"
	content := header + string(out)

	dir := filepath.Dir(overridesPath)
	tmpFile, err := os.CreateTemp(dir, ".rampart-user-overrides-*.yaml.tmp")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create temp file: %v", err))
		return
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to write: %v", err))
		return
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to close temp file: %v", err))
		return
	}
	if err := os.Rename(tmpPath, overridesPath); err != nil {
		os.Remove(tmpPath)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to rename: %v", err))
		return
	}

	// Reload policies so the new rule takes effect immediately.
	if s.engine != nil {
		if reloadErr := s.engine.Reload(); reloadErr != nil {
			s.logger.Warn("proxy: learn rule written but reload failed", "error", reloadErr)
		}
	}

	s.logger.Info("proxy: learned rule", "rule", ruleName, "tool", req.Tool, "pattern", pattern, "decision", req.Decision)

	// Broadcast SSE event.
	s.broadcastSSE(map[string]any{
		"type":      "rule.learned",
		"rule_name": ruleName,
		"tool":      req.Tool,
		"pattern":   pattern,
		"decision":  req.Decision,
	})

	writeJSON(w, http.StatusCreated, learnResponse{
		RuleName: ruleName,
		Tool:     req.Tool,
		Pattern:  pattern,
		Decision: req.Decision,
		Source:   req.Source,
	})
}
