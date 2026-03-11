// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"testing"
)

func TestPromoteTopLevelParams(t *testing.T) {
	tests := []struct {
		name     string
		req      toolRequest
		wantCmd  string
		wantPath string
	}{
		{
			name:    "flat command promoted",
			req:     toolRequest{Command: "rm -rf /", Params: map[string]any{}},
			wantCmd: "rm -rf /",
		},
		{
			name:     "flat path promoted",
			req:      toolRequest{Path: "/etc/shadow", Params: map[string]any{}},
			wantPath: "/etc/shadow",
		},
		{
			name:    "params takes precedence over flat command",
			req:     toolRequest{Command: "flat-cmd", Params: map[string]any{"command": "params-cmd"}},
			wantCmd: "params-cmd",
		},
		{
			name:     "params takes precedence over flat path",
			req:      toolRequest{Path: "flat-path", Params: map[string]any{"path": "params-path"}},
			wantPath: "params-path",
		},
		{
			name:    "both command and path promoted",
			req:     toolRequest{Command: "ls", Path: "/tmp", Params: map[string]any{}},
			wantCmd: "ls",
		},
		{
			name: "nil params initialized and promoted",
			req:  toolRequest{Command: "echo hello"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.req.Params == nil {
				tt.req.Params = map[string]any{}
			}
			promoteTopLevelParams(&tt.req)

			if tt.wantCmd != "" {
				got, _ := tt.req.Params["command"].(string)
				if got != tt.wantCmd {
					t.Errorf("command = %q, want %q", got, tt.wantCmd)
				}
			}
			if tt.wantPath != "" {
				got, _ := tt.req.Params["path"].(string)
				if got != tt.wantPath {
					t.Errorf("path = %q, want %q", got, tt.wantPath)
				}
			}
		})
	}
}
