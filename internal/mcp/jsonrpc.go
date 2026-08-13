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
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
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

// NormalizedID returns a stable key for request/response ID tracking. It
// distinguishes JSON strings from JSON numbers and normalizes equivalent JSON
// spellings to the same value. Invalid IDs return the empty string.
func NormalizedID(id json.RawMessage) string {
	key, err := normalizedID(id)
	if err != nil {
		return ""
	}
	return key
}

// HasID reports whether the JSON-RPC message has a non-empty id field.
func HasID(id json.RawMessage) bool {
	return len(bytes.TrimSpace(id)) > 0
}

// maxRequestIDBytes bounds exact ID normalization work. MCP request IDs are
// opaque correlation tokens, not payload carriers; UUID-sized IDs are typical.
// Without a separate bound, a child can force expensive big-integer parsing up
// to the four-megabyte JSON-RPC line limit.
const maxRequestIDBytes = 1024

// normalizedID decodes an MCP request ID before deriving its correlation key.
// The raw JSON spelling is not an identity: for example, "a" and "\\u0061"
// are the same JSON string. Numeric identities stay exact by using big.Rat,
// rather than float64, and only integral values are accepted for MCP IDs.
func normalizedID(id json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(id)
	if len(trimmed) == 0 {
		return "", fmt.Errorf("missing id")
	}
	if len(trimmed) > maxRequestIDBytes {
		return "", fmt.Errorf("id exceeds %d-byte limit", maxRequestIDBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("decode id: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return "", err
	}

	switch value := value.(type) {
	case string:
		if err := validateJSONStringEncoding(trimmed); err != nil {
			return "", err
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("encode string id: %w", err)
		}
		if len(canonical) > maxRequestIDBytes {
			return "", fmt.Errorf("normalized id exceeds %d-byte limit", maxRequestIDBytes)
		}
		// Keep the JSON type in the key. Without this prefix, the string ID
		// "1" would collide with the numeric ID 1 after numeric
		// canonicalization.
		return "s:" + string(canonical), nil
	case json.Number:
		canonical, err := canonicalIntegerID(value.String())
		if err != nil {
			return "", err
		}
		return "n:" + canonical, nil
	default:
		return "", fmt.Errorf("id must be a string or integer")
	}
}

// validateJSONStringEncoding rejects encodings that encoding/json repairs by
// substitution. In particular, JavaScript preserves lone UTF-16 surrogates
// while Go converts them to U+FFFD; accepting both would make distinct peer IDs
// share a correlation key.
func validateJSONStringEncoding(raw []byte) error {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || !utf8.Valid(raw) {
		return fmt.Errorf("id must be a valid UTF-8 JSON string")
	}
	for index := 1; index < len(raw)-1; index++ {
		if raw[index] != '\\' {
			continue
		}
		index++
		if index >= len(raw)-1 {
			return fmt.Errorf("invalid string escape in id")
		}
		if raw[index] != 'u' {
			continue
		}
		unit, ok := decodeJSONHexUnit(raw, index+1)
		if !ok {
			return fmt.Errorf("invalid unicode escape in id")
		}
		index += 4
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
				return fmt.Errorf("unpaired high surrogate in id")
			}
			low, validLow := decodeJSONHexUnit(raw, index+3)
			if !validLow || low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("unpaired high surrogate in id")
			}
			index += 6
		case unit >= 0xdc00 && unit <= 0xdfff:
			return fmt.Errorf("unpaired low surrogate in id")
		}
	}
	return nil
}

func decodeJSONHexUnit(raw []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, char := range raw[start : start+4] {
		value <<= 4
		switch {
		case char >= '0' && char <= '9':
			value |= uint16(char - '0')
		case char >= 'a' && char <= 'f':
			value |= uint16(char-'a') + 10
		case char >= 'A' && char <= 'F':
			value |= uint16(char-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func ensureJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func canonicalIntegerID(raw string) (string, error) {
	if exponentAt := strings.IndexAny(raw, "eE"); exponentAt >= 0 {
		exponent, err := strconv.Atoi(raw[exponentAt+1:])
		if err != nil || exponent > maxRequestIDBytes || exponent < -maxRequestIDBytes {
			return "", fmt.Errorf("id exponent exceeds normalization limit")
		}
	}
	rational, ok := new(big.Rat).SetString(raw)
	if !ok || !rational.IsInt() {
		return "", fmt.Errorf("id must be an integer")
	}
	canonical := rational.Num().String()
	if len(canonical) > maxRequestIDBytes {
		return "", fmt.Errorf("normalized id exceeds %d-byte limit", maxRequestIDBytes)
	}
	return canonical, nil
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

// decodeCanonicalJSONObject rejects case-shadowed protocol fields before Go's
// case-insensitive struct decoder can choose a different value than an MCP peer
// using exact JavaScript object keys. Unknown extension fields remain allowed.
func decodeCanonicalJSONObject(data []byte, canonicalKeys ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	for key := range object {
		for _, expected := range canonicalKeys {
			// encoding/json matches struct fields with Unicode simple folding,
			// not strings.ToLower. EqualFold mirrors that behavior and catches
			// spellings such as the long-s variant of "scheme" or "result".
			if key != expected && strings.EqualFold(key, expected) {
				return nil, fmt.Errorf("noncanonical object member %q; use %q", key, expected)
			}
		}
	}
	return object, nil
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
