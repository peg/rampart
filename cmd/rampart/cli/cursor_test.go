// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestSetupCursor_WrapServers(t *testing.T) {
	// Create temp directory with mock config
	tmpDir := t.TempDir()
	cursorDir := filepath.Join(tmpDir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(cursorDir, "mcp.json")
	initialConfig := mcpConfig{
		MCPServers: map[string]mcpServer{
			"filesystem": {
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-filesystem", "/docs"},
			},
		},
	}
	data, _ := json.MarshalIndent(initialConfig, "", "  ")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Test wrapping
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := wrapMCPServers(cmd, configPath, "Cursor", false); err != nil {
		t.Fatalf("wrapMCPServers failed: %v", err)
	}

	// Verify output
	if !bytes.Contains(out.Bytes(), []byte("Wrapped 1 MCP server")) {
		t.Errorf("expected success message, got: %s", out.String())
	}

	// Verify config was modified
	newData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var newConfig mcpConfig
	if err := json.Unmarshal(newData, &newConfig); err != nil {
		t.Fatalf("invalid JSON after wrap: %v", err)
	}

	server := newConfig.MCPServers["filesystem"]
	if len(server.Args) < 3 || server.Args[0] != "mcp" || server.Args[1] != "--" {
		t.Errorf("server not wrapped correctly: %+v", server)
	}
}

func TestSetupCursor_UnwrapServers(t *testing.T) {
	tmpDir := t.TempDir()
	cursorDir := filepath.Join(tmpDir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(cursorDir, "mcp.json")
	wrappedConfig := mcpConfig{
		MCPServers: map[string]mcpServer{
			"github": {
				Command: "/usr/local/bin/rampart",
				Args:    []string{"mcp", "--", "npx", "-y", "@mcp/server-github"},
				Env:     map[string]string{"GITHUB_TOKEN": "test"},
			},
		},
	}
	data, _ := json.MarshalIndent(wrappedConfig, "", "  ")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := unwrapMCPServers(cmd, configPath, "Cursor"); err != nil {
		t.Fatalf("unwrapMCPServers failed: %v", err)
	}

	// Verify output
	if !bytes.Contains(out.Bytes(), []byte("Unwrapped 1 MCP server")) {
		t.Errorf("expected success message, got: %s", out.String())
	}

	// Verify config was restored
	newData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var newConfig mcpConfig
	if err := json.Unmarshal(newData, &newConfig); err != nil {
		t.Fatalf("invalid JSON after unwrap: %v", err)
	}

	server := newConfig.MCPServers["github"]
	if server.Command != "npx" {
		t.Errorf("expected command 'npx', got %q", server.Command)
	}
	if len(server.Args) != 2 || server.Args[0] != "-y" {
		t.Errorf("args not restored correctly: %v", server.Args)
	}
	if server.Env["GITHUB_TOKEN"] != "test" {
		t.Errorf("env not preserved: %v", server.Env)
	}
}

func TestSetupCursor_NoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".cursor", "mcp.json")

	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := wrapMCPServers(cmd, configPath, "Cursor", false); err != nil {
		t.Fatalf("should not fail on missing config: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("No MCP configuration found")) {
		t.Errorf("expected 'No MCP configuration found', got: %s", out.String())
	}
}

func TestSetupCursor_AlreadyWrapped(t *testing.T) {
	tmpDir := t.TempDir()
	cursorDir := filepath.Join(tmpDir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(cursorDir, "mcp.json")
	wrappedConfig := mcpConfig{
		MCPServers: map[string]mcpServer{
			"test": {
				Command: "rampart",
				Args:    []string{"mcp", "--", "npx", "test-server"},
			},
		},
	}
	data, _ := json.MarshalIndent(wrappedConfig, "", "  ")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := wrapMCPServers(cmd, configPath, "Cursor", false); err != nil {
		t.Fatalf("should not fail on already wrapped: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("already protected")) {
		t.Errorf("expected 'already protected', got: %s", out.String())
	}
}

func TestIsRampartWrapped(t *testing.T) {
	tests := []struct {
		name    string
		server  mcpServer
		wrapped bool
	}{
		{
			name:    "bare rampart",
			server:  mcpServer{Command: "rampart", Args: []string{"mcp", "--", "npx"}},
			wrapped: true,
		},
		{
			name:    "absolute path",
			server:  mcpServer{Command: "/usr/local/bin/rampart", Args: []string{"mcp", "--", "npx"}},
			wrapped: true,
		},
		{
			name:    "versioned binary",
			server:  mcpServer{Command: "/tmp/rampart-0.6.0", Args: []string{"mcp", "--", "npx"}},
			wrapped: true,
		},
		{
			name:    "not wrapped",
			server:  mcpServer{Command: "npx", Args: []string{"-y", "server"}},
			wrapped: false,
		},
		{
			name:    "rampart but wrong args",
			server:  mcpServer{Command: "rampart", Args: []string{"serve"}},
			wrapped: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isRampartWrapped(tc.server)
			if got != tc.wrapped {
				t.Errorf("isRampartWrapped() = %v, want %v", got, tc.wrapped)
			}
		})
	}
}
