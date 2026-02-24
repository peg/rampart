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
	"net/http"
	"time"
)

// handlePolicyReload forces an immediate reload of all policy files.
// POST /v1/policy/reload
//
// Requires a valid bearer token. Returns the number of policies and rules
// loaded after reload, plus the time taken in milliseconds.
//
// Response (200 OK):
//
//	{
//	  "success": true,
//	  "policies_loaded": 3,
//	  "rules_total": 26,
//	  "reload_time_ms": 12
//	}
// reloadCooldown is the minimum time between reload API calls.
const reloadCooldown = 1 * time.Second

func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if s.engine == nil {
		writeError(w, http.StatusServiceUnavailable, "policy engine not initialized")
		return
	}

	// Rate limiting: reject if last reload was less than 1 second ago
	s.mu.Lock()
	if time.Since(s.lastReloadAPI) < reloadCooldown {
		s.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "reload rate limited, try again in 1 second")
		return
	}
	s.lastReloadAPI = time.Now()
	s.mu.Unlock()

	start := time.Now()

	if err := s.engine.Reload(); err != nil {
		s.logger.Error("proxy: policy reload via API failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	stats := s.engine.Stats()
	elapsed := time.Since(start)

	s.logger.Info("proxy: policy reload via API succeeded",
		"policies", stats.PolicyCount,
		"rules", stats.RuleCount,
		"duration_ms", elapsed.Milliseconds(),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"success":         true,
		"policies_loaded": stats.PolicyCount,
		"rules_total":     stats.RuleCount,
		"reload_time_ms":  elapsed.Milliseconds(),
	})
}
