// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

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

// promoteTopLevelParams copies convenience fields (command, path) from the
// top-level request into Params when they aren't already present. This allows
// callers to use the flat form {"command":"rm -rf /"} instead of the nested
// form {"params":{"command":"rm -rf /"}}.
func promoteTopLevelParams(req *toolRequest) {
	if req.Command != "" {
		if _, exists := req.Params["command"]; !exists {
			req.Params["command"] = req.Command
		}
	}
	if req.Path != "" {
		if _, exists := req.Params["path"]; !exists {
			req.Params["path"] = req.Path
		}
	}
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

	if toolName == "fetch" || toolName == "http" || toolName == "web_fetch" {
		rawURL, _ := params["url"].(string)
		if rawURL == "" {
			return
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			return
		}
		if _, ok := params["domain"]; !ok {
			params["domain"] = parsed.Hostname()
		}
		if _, ok := params["scheme"]; !ok {
			params["scheme"] = parsed.Scheme
		}
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
