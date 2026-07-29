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
	"fmt"
	"io"
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

// validateUniqueJSONKeys rejects duplicate object members at every nesting
// level. Different JSON implementations are permitted to select different
// duplicate values; a security proxy must not evaluate one interpretation and
// forward the same bytes to a child that may execute another.
func validateUniqueJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple top-level JSON values")
		}
		return err
	}
	return nil
}

func validateUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object member name is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object member %q", key)
			}
			seen[key] = struct{}{}
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	want := json.Delim('}')
	if delim == '[' {
		want = ']'
	}
	if closing != want {
		return fmt.Errorf("unexpected JSON closing delimiter %q", closing)
	}
	return nil
}
