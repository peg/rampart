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
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/peg/rampart/internal/engine"
	"gopkg.in/yaml.v3"
)

// autoAllowedRule is a single rule returned by the rules API.
type autoAllowedRule struct {
	Index          int    `json:"index"`
	Tool           string `json:"tool"`
	CommandPattern string `json:"command_pattern"`
	PathPattern    string `json:"path_pattern,omitempty"`
	Name           string `json:"name"`
	Created        string `json:"created,omitempty"`
}

func (s *Server) handleGetAutoAllowed(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	policyPath := engine.DefaultAutoAllowedPath()
	data, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to read auto-allowed rules: %v", err))
		return
	}

	var cfg engine.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to parse auto-allowed rules: %v", err))
		return
	}

	rules := make([]autoAllowedRule, 0, len(cfg.Policies))
	for i, p := range cfg.Policies {
		rule := autoAllowedRule{
			Index: i,
			Name:  p.Name,
		}

		if len(p.Match.Tool) > 0 {
			rule.Tool = p.Match.Tool[0]
		}

		// Extract command/path pattern from the first rule's conditions.
		if len(p.Rules) > 0 {
			r := p.Rules[0]
			if len(r.When.CommandMatches) > 0 {
				rule.CommandPattern = r.When.CommandMatches[0]
			}
			if len(r.When.PathMatches) > 0 {
				rule.PathPattern = r.When.PathMatches[0]
			}
		}

		rule.Created = autoAllowedRuleCreated(p.Name)

		rules = append(rules, rule)
	}

	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// autoAllowedRuleCreated supports both historical names ending in the UTC
// timestamp and current names which append a stable authority hash. Scanning
// complete dash-delimited components keeps old persisted rules readable while
// avoiding a migration solely for display metadata.
func autoAllowedRuleCreated(name string) string {
	parts := strings.Split(name, "-")
	for index := len(parts) - 1; index >= 0; index-- {
		if parsed, err := time.Parse("20060102T150405Z", parts[index]); err == nil {
			return parsed.Format(time.RFC3339)
		}
	}
	return ""
}

func (s *Server) handleDeleteAutoAllowed(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "rule name is required")
		return
	}

	policyPath := engine.DefaultAutoAllowedPath()

	s.policyWriteMu.Lock()
	defer s.policyWriteMu.Unlock()

	removed, _, err := engine.RemoveAllowRule(policyPath, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to remove rule: %v", err))
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no rule with name %q", name))
		return
	}

	// Force immediate engine reload so the revoked rule stops applying right away.
	if s.engine != nil {
		if reloadErr := s.engine.Reload(); reloadErr != nil {
			s.logger.Error("proxy: post-change reload failed", "error", reloadErr)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("policy written but reload failed: %v", reloadErr))
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
