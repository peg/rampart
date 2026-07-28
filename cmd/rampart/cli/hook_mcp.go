// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"strings"

	mcppolicy "github.com/peg/rampart/internal/mcp"
)

// classifyNativeMCPTool routes hook-visible MCP calls through the same
// classifier as the MCP proxy. Host protocols either encode the MCP tool in
// the hook tool name or wrap it in a generic use_mcp_tool call with the real
// name in params. Evaluate every trustworthy candidate and keep the most
// security-sensitive classification.
func classifyNativeMCPTool(hostToolName string, params map[string]any) string {
	candidates := []string{strings.TrimSpace(hostToolName)}
	lower := strings.ToLower(strings.TrimSpace(hostToolName))
	if strings.HasPrefix(lower, "mcp__") {
		parts := strings.Split(strings.TrimPrefix(lower, "mcp__"), "__")
		if len(parts) > 1 {
			candidates = append(candidates, parts[len(parts)-1])
		}
	}
	for _, key := range []string{"mcp_tool", "tool_name", "toolName"} {
		if value, ok := params[key].(string); ok && strings.TrimSpace(value) != "" {
			candidates = append(candidates, value)
		}
	}

	selected := "mcp"
	selectedRank := nativeMCPClassificationRank(selected)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		mapped := mcppolicy.MapToolName(candidate, nil)
		if rank := nativeMCPClassificationRank(mapped); rank > selectedRank {
			selected = mapped
			selectedRank = rank
		}
	}
	return selected
}

func nativeMCPClassificationRank(tool string) int {
	switch tool {
	case "mcp-destructive":
		return 7
	case "exec":
		return 6
	case "mcp-dangerous":
		return 5
	case "write":
		return 4
	case "fetch":
		return 3
	case "read":
		return 2
	case "mcp":
		return 1
	default:
		return 0
	}
}
