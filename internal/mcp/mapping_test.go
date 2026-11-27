// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package mcp

import "testing"

func TestMapToolNameDestructiveInferencePrecedesOrdinaryDefaults(t *testing.T) {
	if got := MapToolName("delete_file"); got != "mcp-destructive" {
		t.Fatalf("delete_file = %q, want mcp-destructive", got)
	}
	if got := MapToolName("filesystem_delete_file"); got != "mcp-destructive" {
		t.Fatalf("filesystem_delete_file = %q, want mcp-destructive", got)
	}
	if got := MapToolName("execute_command"); got != "exec" {
		t.Fatalf("execute_command = %q, want exec", got)
	}
	if got := MapToolName("move_file"); got != "mcp-dangerous" {
		t.Fatalf("move_file = %q, want mcp-dangerous", got)
	}
}
