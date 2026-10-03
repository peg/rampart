// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/peg/rampart/internal/notify"
)

// The managed plugin sends the original V1 dispatch identity and arguments.
// This is a before-only protocol; it does not report execution or scan results.
type openCodeHookInput struct {
	Tool      string         `json:"tool"`
	SessionID string         `json:"sessionID"`
	CallID    string         `json:"callID"`
	Directory string         `json:"directory"`
	Args      map[string]any `json:"args"`
}

func parseOpenCodeInput(reader io.Reader) (*hookParseResult, error) {
	var input openCodeHookInput
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("hook: invalid OpenCode input")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("hook: OpenCode requires one JSON object")
	}
	if strings.TrimSpace(input.SessionID) == "" || strings.TrimSpace(input.CallID) == "" || !filepath.IsAbs(input.Directory) || input.Args == nil {
		return nil, fmt.Errorf("hook: OpenCode requires dispatch identity, arguments, and an absolute directory")
	}
	if err := validateToolUseID(input.CallID); err != nil {
		return nil, fmt.Errorf("hook: invalid OpenCode call identity")
	}
	params := cloneHookParams(input.Args)
	result := &hookParseResult{
		Params: params, WorkDir: input.Directory, Agent: "opencode",
		RunID: deriveRunID(input.SessionID), SessionID: input.SessionID,
		ToolUseID: input.CallID, HookEventName: "PreToolUse",
	}
	required := func(field string) (string, error) {
		value, ok := input.Args[field].(string)
		if !ok || strings.TrimSpace(value) == "" || strings.IndexByte(value, 0) >= 0 {
			return "", fmt.Errorf("hook: OpenCode requires a valid %s", field)
		}
		return value, nil // Presence checks never change the action's bytes.
	}
	switch input.Tool {
	case "bash":
		result.Tool = "exec"
		command, err := required("command")
		if err != nil {
			return nil, err
		}
		params["command"] = command
		if raw, exists := input.Args["workdir"]; exists {
			dir, ok := raw.(string)
			if !ok || strings.TrimSpace(dir) == "" || strings.IndexByte(dir, 0) >= 0 {
				return nil, fmt.Errorf("hook: invalid OpenCode workdir")
			}
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(input.Directory, dir)
			}
			result.WorkDir = dir
			params["workdir"] = dir
		}
	case "read", "write", "edit":
		result.Tool = "write"
		if input.Tool == "read" {
			result.Tool = "read"
		}
		target, err := required("filePath")
		if err != nil {
			return nil, err
		}
		params["path"] = target
	case "apply_patch":
		result.Tool = "write"
		patch, err := required("patchText")
		if err != nil {
			return nil, err
		}
		result.PolicyPaths, err = extractOpenCodePatchPaths(patch)
		if err != nil {
			return nil, err
		}
		params["path"] = result.PolicyPaths[0]
		params["paths"] = append([]string(nil), result.PolicyPaths...)
	case "webfetch":
		result.Tool = "fetch"
		target, err := required("url")
		if err != nil {
			return nil, err
		}
		params["url"] = target
	case "question", "plan_exit":
		result.Tool = "interact"
	case "todowrite":
		result.Tool = "process"
	default:
		// Searches, unknown/custom/MCP, code mode, delegated agents and skills do
		// not inherit an unmatched allow before their consequences are mapped.
		return nil, fmt.Errorf("hook: unsupported OpenCode tool; execution refused")
	}
	return result, nil
}

func extractOpenCodePatchPaths(patch string) ([]string, error) {
	// OpenCode's parser applies ECMAScript trim to headers. Normalize only
	// that representation, then reuse the shared bounded multi-target parser.
	trim := func(value string) string {
		return strings.Trim(value, "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff")
	}
	patch = strings.ReplaceAll(patch, "\r\n", "\n")
	if strings.ContainsRune(patch, '\r') {
		return nil, fmt.Errorf("hook: unsupported OpenCode patch line ending")
	}
	lines := strings.Split(patch, "\n")
	for i, line := range lines {
		for _, prefix := range []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"} {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			target := trim(strings.TrimPrefix(line, prefix))
			// The shared parser historically trims Go whitespace. Refuse the
			// uncommon control-path difference instead of evaluating another path.
			if strings.TrimSpace(target) != target {
				return nil, fmt.Errorf("hook: unsupported OpenCode patch target")
			}
			lines[i] = prefix + " " + target
			break
		}
	}
	return extractCodexPatchPaths(strings.Join(lines, "\n"))
}

func outputOpenCodeHookResult(writer io.Writer, decision hookDecisionType, reason string) error {
	value := "deny"
	if decision == hookAllow {
		value = "allow"
	}
	return json.NewEncoder(writer).Encode(struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason,omitempty"`
	}{value, notify.SanitizeCommand(reason)})
}
