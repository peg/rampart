// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/peg/rampart/internal/engine"
)

const maxToolNameLength = 128

// canonicalToolName normalizes the policy tool class at the HTTP trust
// boundary. Policy scopes are case-sensitive, while several security-field
// extractors intentionally recognize canonical tool classes case-insensitively;
// using one representation prevents those two views from disagreeing.
func canonicalToolName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return "", fmt.Errorf("tool name is required")
	}
	if len(name) > maxToolNameLength {
		return "", fmt.Errorf("tool name exceeds %d bytes", maxToolNameLength)
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '_', '-', '.', ':':
			continue
		default:
			return "", fmt.Errorf("tool name contains unsupported character %q", char)
		}
	}
	return name, nil
}

// decodeJSONBody accepts exactly one JSON value plus optional trailing
// whitespace. Keeping this check in one place prevents request smuggling by
// concatenating a second object that individual handlers would otherwise
// silently ignore.
func decodeJSONBody(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return fmt.Errorf("invalid trailing data: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func generateToken(logger *slog.Logger) string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is a critical system issue. Fail hard rather
		// than starting with a predictable token.
		logger.Error("proxy: crypto/rand unavailable, cannot generate secure token", "error", err)
		panic("rampart: crypto/rand failed; refusing to start with insecure token")
	}
	return hex.EncodeToString(buf)
}

// extractToolInput returns the best-available input map for tool parameter
// matching. For MCP-style requests, prefer nested argument objects; otherwise
// fall back to the top-level params map.
func extractToolInput(toolName string, params map[string]any, explicitInput map[string]any) map[string]any {
	if len(explicitInput) > 0 {
		return explicitInput
	}
	if args, ok := params["arguments"].(map[string]any); ok && len(args) > 0 {
		return args
	}
	if input, ok := params["tool_input"].(map[string]any); ok && len(input) > 0 {
		return input
	}
	if strings.HasPrefix(toolName, "mcp") {
		return params
	}
	return params
}

// toolInputMaps returns every representation a supported host can use for
// security-sensitive tool arguments. extractToolInput deliberately chooses one
// preferred view for policy matching, but validation must consider all views:
// otherwise a caller could put a benign value in the preferred map and a
// different value in a nested arguments/tool_input map consumed by the host.
func toolInputMaps(params map[string]any, explicitInput map[string]any) []map[string]any {
	maps := []map[string]any{params}
	if explicitInput != nil {
		maps = append(maps, explicitInput)
	}
	for _, key := range []string{"arguments", "tool_input"} {
		if nested, ok := params[key].(map[string]any); ok && nested != nil {
			maps = append(maps, nested)
		}
	}
	return maps
}

// prepareToolRequest canonicalizes security-sensitive aliases before policy
// evaluation. Requests may use legacy params, MCP-style input, or top-level
// convenience fields, but distinct non-empty values are ambiguous and must be
// rejected rather than resolved by precedence.
func prepareToolRequest(toolName string, req *toolRequest) error {
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	input := extractToolInput(toolName, req.Params, req.Input)
	maps := toolInputMaps(req.Params, req.Input)

	commandKeys := []string{"command"}
	commandInitial := []string{req.Command}
	if toolName == "exec" {
		commandKeys = append(commandKeys, "cmd", "input")
		for _, values := range maps {
			encoded, exists := values["command_b64"]
			if !exists || encoded == nil || strings.TrimSpace(fmt.Sprint(encoded)) == "" {
				continue
			}
			if _, ok := encoded.(string); !ok {
				return fmt.Errorf("command_b64 must be a string")
			}
			decoded, ok := decodeBase64Command(values)
			if !ok {
				return fmt.Errorf("command_b64 must be valid bounded base64")
			}
			commandInitial = append(commandInitial, decoded)
		}
	}
	command, err := canonicalStringAliases("command", commandInitial, maps, commandKeys...)
	if err != nil {
		return err
	}

	pathKeys := []string{"path", "file_path"}
	switch toolName {
	case "read", "write", "edit", "mcp-destructive":
		pathKeys = append(pathKeys, "file", "filepath", "target")
	}
	path, err := canonicalStringAliases("path", []string{req.Path}, maps, pathKeys...)
	if err != nil {
		return err
	}
	workDir, err := canonicalStringAliases("working directory", []string{req.WorkDir, req.CWD}, maps, "workdir", "cwd")
	if err != nil {
		return err
	}

	urlKeys := []string{"url"}
	switch toolName {
	case "fetch", "http", "web_fetch", "browser":
		urlKeys = append(urlKeys, "uri", "href")
	}
	rawURL, err := canonicalStringAliases("url", []string{req.URL}, maps, urlKeys...)
	if err != nil {
		return err
	}
	for _, field := range []string{"domain", "scheme"} {
		if _, err := canonicalStringAliases(field, nil, maps, field); err != nil {
			return err
		}
	}

	for _, values := range maps {
		delete(values, "command_effective")
		if command != "" {
			values["command"] = command
		}
		if path != "" {
			values["path"] = path
		}
		if workDir != "" {
			values["workdir"] = workDir
		}
		if rawURL != "" {
			values["url"] = rawURL
			// Domain and scheme are derived data. Never retain caller-supplied
			// decoys when a URL is available.
			delete(values, "domain")
			delete(values, "scheme")
		}
		enrichParams(toolName, values)
	}

	// Keep the legacy Params view complete for audit and policy consumers while
	// retaining the original structured input for exact replay fingerprints.
	for _, field := range []string{"url", "domain", "scheme", "path", "command", "workdir"} {
		if value, ok := input[field]; ok {
			if _, exists := req.Params[field]; !exists {
				req.Params[field] = value
			}
		}
	}
	return nil
}

func canonicalStringAliases(field string, initial []string, maps []map[string]any, keys ...string) (string, error) {
	values := make(map[string]struct{}, len(initial)+len(maps)*len(keys))
	selected := ""
	add := func(value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		if selected == "" {
			selected = value
		}
		values[value] = struct{}{}
	}
	for _, value := range initial {
		add(value)
	}
	for _, valuesMap := range maps {
		for _, key := range keys {
			value, exists := valuesMap[key]
			if !exists || value == nil {
				continue
			}
			text, ok := value.(string)
			if !ok {
				return "", fmt.Errorf("%s must be a string", field)
			}
			add(text)
		}
	}
	if len(values) > 1 {
		return "", fmt.Errorf("conflicting %s aliases", field)
	}
	return selected, nil
}

// requestWorkingDirectory returns the canonical directory prepared by
// prepareToolRequest. That validation has already required every non-empty
// top-level, params, and input alias to agree.
func requestWorkingDirectory(req toolRequest) string {
	call := engine.ToolCall{Params: req.Params, Input: req.Input}
	if workDir := call.WorkingDirectory(); workDir != "" {
		return workDir
	}
	if workDir := strings.TrimSpace(req.WorkDir); workDir != "" {
		return workDir
	}
	return strings.TrimSpace(req.CWD)
}

// enrichParams adds derived fields to params for richer policy matching.
// For fetch/HTTP tools, it parses the URL to extract domain, scheme, and path.
func enrichParams(toolName string, params map[string]any) {
	if toolName == "exec" {
		if cmd, ok := decodeBase64Command(params); ok {
			params["command"] = cmd
		}
		// Strip leading shell comment lines (e.g. "# description\nactual command")
		// so that command_matches patterns work against the real command.
		if cmd, ok := params["command"].(string); ok {
			params["command"] = stripLeadingComments(cmd)
		}
	}

	if toolName == "agent" {
		// Claude Code Task tool sends the task prompt in "description".
		// Expose it as "command" so command_matches policies work against
		// the sub-agent's task description.
		if desc, ok := params["description"].(string); ok && desc != "" {
			params["command"] = desc
		} else if prompt, ok := params["prompt"].(string); ok && prompt != "" {
			params["command"] = prompt
		}
	}

	if toolName == "fetch" || toolName == "http" || toolName == "web_fetch" || toolName == "browser" {
		rawURL, _ := params["url"].(string)
		if rawURL == "" {
			return
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			return
		}
		// These fields are derived from URL, not independent caller authority.
		params["domain"] = parsed.Hostname()
		params["scheme"] = parsed.Scheme
		if _, ok := params["path"]; !ok {
			params["path"] = parsed.Path
		}
	}
}

// stripLeadingComments removes leading lines that start with # (shell comments)
// from multi-line command strings. Agent frameworks often prepend descriptive
// comments (e.g. "# Check disk space\ndf -h") which break command_matches
// patterns that expect the actual command at the start of the string.
func stripLeadingComments(cmd string) string {
	lines := strings.Split(cmd, "\n")
	start := 0
	for start < len(lines) {
		trimmed := strings.TrimSpace(lines[start])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			start++
			continue
		}
		break
	}
	if start == 0 {
		return cmd
	}
	if start >= len(lines) {
		return "" // all comments/blank lines — return empty
	}
	return strings.Join(lines[start:], "\n")
}

func decodeBase64Command(params map[string]any) (string, bool) {
	encoded, _ := params["command_b64"].(string)
	if strings.TrimSpace(encoded) == "" {
		return "", false
	}

	// Cap encoded input at 1MB to prevent memory exhaustion.
	const maxBase64Len = 1 << 20
	if len(encoded) > maxBase64Len {
		return "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}

	return string(decoded), true
}
