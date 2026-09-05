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
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/notify"
	"github.com/peg/rampart/internal/policy"
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

// learnRateLimit is the minimum interval between successful /v1/rules/learn writes.
// Prevents bulk rule injection via a compromised admin token.
const learnRateLimit = 200 * time.Millisecond // max ~5 writes/sec

func (s *Server) handleLearnRule(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	var req learnRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.Tool = strings.TrimSpace(req.Tool)
	if req.Tool == "" || strings.TrimSpace(req.Args) == "" {
		writeError(w, http.StatusBadRequest, "tool and args are required")
		return
	}
	// Only "allow" is accepted — this endpoint exists for "Always Allow" writeback.
	// Deny rules belong in policy YAML, not auto-generated via the learn API.
	if req.Decision != "allow" {
		writeError(w, http.StatusBadRequest, "decision must be \"allow\" — use policy YAML for deny rules")
		return
	}
	switch req.Tool {
	case "exec", "read", "write", "edit":
		// These tools have exact command/path conditions in the policy schema.
	default:
		writeError(w, http.StatusBadRequest, "automatic allow persistence supports exec, read, write, and edit only; use an explicit policy for other tools")
		return
	}

	if notify.SanitizeCommand(req.Args) != req.Args {
		writeError(w, http.StatusBadRequest, "credential-bearing actions cannot create permanent literal rules; use an explicit policy")
		return
	}

	// Persist exactly the approved invocation. Shell wildcard characters are
	// escaped so an approval cannot silently authorize related commands.
	pattern := policy.BuildExactAllowPattern(req.Args)
	// Resolve overrides path.
	home, err := os.UserHomeDir()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve home directory")
		return
	}
	overridesPath := filepath.Join(home, ".rampart", "policies", "user-overrides.yaml")

	s.policyWriteMu.Lock()
	defer s.policyWriteMu.Unlock()

	ruleName := policy.UserOverrideRuleName(req.Tool, pattern)
	existing, err := policy.LoadUserOverridesPolicy(overridesPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load user overrides: %v", err))
		return
	}
	for _, entry := range existing.Policies {
		if entry.Name == ruleName {
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

	// Serialize the inexpensive rate check with policy creation. The durable
	// helper below adds a cross-process lock for bridges or parallel services.
	s.mu.Lock()
	if time.Since(s.lastLearnAPI) < learnRateLimit {
		s.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "learn rate limited — slow down rule writes")
		return
	}
	s.mu.Unlock()

	result, err := policy.EnsureUserOverrideAllow(
		overridesPath,
		req.Tool,
		pattern,
		fmt.Sprintf("User %s (always) via %s", req.Decision, req.Source),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to persist user override: %v", err))
		return
	}
	if !result.Created {
		writeJSON(w, http.StatusConflict, learnResponse{
			RuleName: result.Name,
			Tool:     req.Tool,
			Pattern:  result.Pattern,
			Decision: req.Decision,
			Source:   req.Source,
		})
		return
	}
	s.mu.Lock()
	s.lastLearnAPI = time.Now()
	s.mu.Unlock()

	// Reload policies so the new rule takes effect immediately.
	if s.engine != nil {
		if reloadErr := s.engine.Reload(); reloadErr != nil {
			s.logger.Warn("proxy: learn rule written but reload failed", "error", reloadErr)
		}
	}

	s.logger.Info("proxy: learned rule", "rule", result.Name, "tool", req.Tool, "pattern", result.Pattern, "decision", req.Decision)

	// Broadcast SSE event.
	s.broadcastSSE(map[string]any{
		"type":      "rule.learned",
		"rule_name": result.Name,
		"tool":      req.Tool,
		"pattern":   result.Pattern,
		"decision":  req.Decision,
	})

	writeJSON(w, http.StatusCreated, learnResponse{
		RuleName: result.Name,
		Tool:     req.Tool,
		Pattern:  result.Pattern,
		Decision: req.Decision,
		Source:   req.Source,
	})
}
