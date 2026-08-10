// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCanonicalToolName(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "canonical exec", raw: "exec", want: "exec"},
		{name: "mixed case and whitespace", raw: "  Exec  ", want: "exec"},
		{name: "structured custom name", raw: "MCP.Custom-Tool:V1", want: "mcp.custom-tool:v1"},
		{name: "empty", raw: "  ", wantErr: true},
		{name: "path separator", raw: "custom/tool", wantErr: true},
		{name: "embedded whitespace", raw: "web fetch", wantErr: true},
		{name: "non ascii", raw: "exéc", wantErr: true},
		{name: "too long", raw: strings.Repeat("a", maxToolNameLength+1), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicalToolName(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("canonicalToolName(%q) = %q, want error", test.raw, got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("canonicalToolName(%q) = %q, %v; want %q", test.raw, got, err, test.want)
			}
		})
	}
}

func TestPrepareToolRequestRejectsConflictingAliases(t *testing.T) {
	tests := []struct {
		name string
		tool string
		req  toolRequest
	}{
		{
			name: "params input command",
			tool: "exec",
			req: toolRequest{Params: map[string]any{"command": "echo safe"},
				Input: map[string]any{"command": "rm -rf /"}},
		},
		{
			name: "top level path",
			tool: "write",
			req: toolRequest{Path: "/tmp/safe", Params: map[string]any{
				"file_path": "/etc/shadow",
			}},
		},
		{
			name: "working directory",
			tool: "exec",
			req: toolRequest{WorkDir: "/tmp/safe", Input: map[string]any{
				"cwd": "/etc",
			}},
		},
		{
			name: "url aliases",
			tool: "fetch",
			req: toolRequest{URL: "https://github.com", Params: map[string]any{
				"href": "https://webhook.site/steal",
			}},
		},
		{
			name: "base64 command",
			tool: "exec",
			req: toolRequest{Command: "echo safe", Params: map[string]any{
				"command_b64": base64.StdEncoding.EncodeToString([]byte("rm -rf /")),
			}},
		},
		{
			name: "non string command",
			tool: "exec",
			req: toolRequest{Params: map[string]any{
				"command": []string{"echo", "safe"},
			}},
		},
		{
			name: "explicit input and nested arguments",
			tool: "exec",
			req: toolRequest{
				Input: map[string]any{"command": "echo safe"},
				Params: map[string]any{"arguments": map[string]any{
					"command": "rm -rf /",
				}},
			},
		},
		{
			name: "explicit input and nested tool input",
			tool: "write",
			req: toolRequest{
				Input: map[string]any{"path": "/tmp/safe"},
				Params: map[string]any{"tool_input": map[string]any{
					"file_path": "/etc/shadow",
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := prepareToolRequest(tt.tool, &tt.req)
			if err == nil || !strings.Contains(err.Error(), "command") &&
				!strings.Contains(err.Error(), "path") &&
				!strings.Contains(err.Error(), "directory") &&
				!strings.Contains(err.Error(), "url") {
				t.Fatalf("prepareToolRequest error = %v, want alias validation error", err)
			}
		})
	}
}

func TestPrepareToolRequestCanonicalizesEveryInputRepresentation(t *testing.T) {
	req := toolRequest{
		Input: map[string]any{"cmd": "echo safe"},
		Params: map[string]any{
			"arguments":  map[string]any{"input": "echo safe"},
			"tool_input": map[string]any{"command": "echo safe"},
		},
	}
	if err := prepareToolRequest("exec", &req); err != nil {
		t.Fatalf("prepareToolRequest: %v", err)
	}
	for name, values := range map[string]map[string]any{
		"params":     req.Params,
		"input":      req.Input,
		"arguments":  req.Params["arguments"].(map[string]any),
		"tool_input": req.Params["tool_input"].(map[string]any),
	} {
		if got := values["command"]; got != "echo safe" {
			t.Fatalf("%s command = %v, want echo safe", name, got)
		}
	}
}

func TestPrepareToolRequestDerivesURLMetadataAndDropsEffectiveCommand(t *testing.T) {
	req := toolRequest{
		URL: "https://webhook.site/collect",
		Params: map[string]any{
			"command":           "rm -rf /",
			"command_effective": "echo safe",
			"url":               "https://webhook.site/collect",
			"domain":            "github.com",
			"scheme":            "file",
		},
	}
	if err := prepareToolRequest("fetch", &req); err != nil {
		t.Fatalf("prepareToolRequest: %v", err)
	}
	if got := req.Params["domain"]; got != "webhook.site" {
		t.Fatalf("domain = %v, want URL-derived webhook.site", got)
	}
	if got := req.Params["scheme"]; got != "https" {
		t.Fatalf("scheme = %v, want URL-derived https", got)
	}
	if _, exists := req.Params["command_effective"]; exists {
		t.Fatal("caller-supplied command_effective survived canonicalization")
	}
}
