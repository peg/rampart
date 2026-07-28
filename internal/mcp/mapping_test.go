// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package mcp

import "testing"

func TestMapToolNameDestructiveInferencePrecedesOrdinaryDefaults(t *testing.T) {
	if got := MapToolName("delete_file", nil); got != "mcp-destructive" {
		t.Fatalf("delete_file = %q, want mcp-destructive", got)
	}
	if got := MapToolName("filesystem_delete_file", nil); got != "mcp-destructive" {
		t.Fatalf("filesystem_delete_file = %q, want mcp-destructive", got)
	}
	if got := MapToolName("execute_command", nil); got != "exec" {
		t.Fatalf("execute_command = %q, want exec", got)
	}
}

func TestMapToolNameExplicitCustomMappingStillWins(t *testing.T) {
	custom := map[string]string{"delete_file": "write"}
	if got := MapToolName("delete_file", custom); got != "write" {
		t.Fatalf("custom delete_file = %q, want write", got)
	}
}
