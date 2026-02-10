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

package mcp

import (
	"bytes"
	"encoding/json"
)

// Request is the minimal JSON-RPC 2.0 request/notification envelope used by MCP.
type Request struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is the minimal JSON-RPC 2.0 response envelope used by MCP.
type Response struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ErrorObject    `json:"error,omitempty"`
}

// ErrorObject is a JSON-RPC error payload.
type ErrorObject struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolsCallParams is the request body for MCP tools/call.
type ToolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// NormalizedID returns a stable key for request/response ID tracking.
func NormalizedID(id json.RawMessage) string {
	return string(bytes.TrimSpace(id))
}

// HasID reports whether the JSON-RPC message has a non-empty id field.
func HasID(id json.RawMessage) bool {
	return len(bytes.TrimSpace(id)) > 0
}

// MarshalErrorResponse builds a JSON-RPC error response for a given id.
func MarshalErrorResponse(id json.RawMessage, code int, message string) ([]byte, error) {
	payload := Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &ErrorObject{
			Code:    code,
			Message: message,
		},
	}
	return json.Marshal(payload)
}
