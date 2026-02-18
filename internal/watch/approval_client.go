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

package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PendingApproval represents a pending approval from the serve API.
type PendingApproval struct {
	ID        string    `json:"id"`
	Tool      string    `json:"tool"`
	Command   string    `json:"command"`
	Agent     string    `json:"agent"`
	Session   string    `json:"session"`
	Message   string    `json:"message"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ApprovalClient polls the serve API for pending approvals.
type ApprovalClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewApprovalClient creates a new client for the serve approval API.
func NewApprovalClient(baseURL, token string) *ApprovalClient {
	return &ApprovalClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// ListPending fetches pending approvals from the serve API.
func (c *ApprovalClient) ListPending(ctx context.Context) ([]PendingApproval, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/approvals", nil)
	if err != nil {
		return nil, fmt.Errorf("approval client: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("approval client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("approval client: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Approvals []PendingApproval `json:"approvals"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("approval client: decode: %w", err)
	}

	// Filter to only pending.
	pending := make([]PendingApproval, 0, len(result.Approvals))
	for _, a := range result.Approvals {
		if a.Status == "pending" {
			pending = append(pending, a)
		}
	}
	return pending, nil
}

// Resolve resolves an approval (approve or deny).
func (c *ApprovalClient) Resolve(ctx context.Context, id string, approved bool) error {
	body, _ := json.Marshal(map[string]any{
		"approved":    approved,
		"resolved_by": "watch-tui",
	})

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/approvals/"+id+"/resolve", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("approval client: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("approval client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("approval client: HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
