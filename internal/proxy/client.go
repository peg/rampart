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
	"io"
	"net/http"
	"time"
)

// httpClient is used for all outgoing requests from the proxy client.
// It has a timeout to prevent hangs if the target server is unresponsive.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// ReloadResponse is the JSON body returned by POST /v1/policy/reload.
type ReloadResponse struct {
	Success        bool   `json:"success"`
	PoliciesLoaded int    `json:"policies_loaded"`
	RulesTotal     int    `json:"rules_total"`
	ReloadTimeMs   int64  `json:"reload_time_ms"`
	Error          string `json:"error,omitempty"`
}

// ReloadPolicy calls POST /v1/policy/reload on a running serve instance and
// forces an immediate policy reload. It returns the reload response on success
// or an error if the request fails or the server returns a non-200 status.
//
// baseURL should be the base URL of the running serve instance
// (e.g. "http://localhost:19090"). token is the bearer auth token.
func ReloadPolicy(baseURL, token string) (*ReloadResponse, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/policy/reload", nil)
	if err != nil {
		return nil, fmt.Errorf("reload: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reload: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reload: read response: %w", err)
	}

	var result ReloadResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("reload: decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if result.Error != "" {
			return nil, fmt.Errorf("reload failed: %s", result.Error)
		}
		return nil, fmt.Errorf("reload failed: HTTP %d", resp.StatusCode)
	}

	return &result, nil
}
