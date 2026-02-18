// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGeneralizeCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"kubectl apply -f deployment.yaml", "kubectl apply *"},
		{"npm install express", "npm install *"},
		{"git push origin main", "git push *"},
		{"ls", "ls *"},
		{"cat /etc/passwd", "cat /etc/passwd *"},
		{"", "*"},
		{"  kubectl   apply  -f  foo  ", "kubectl apply *"},
	}
	for _, tt := range tests {
		got := GeneralizeCommand(tt.input)
		if got != tt.want {
			t.Errorf("GeneralizeCommand(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerateAllowRule_Exec(t *testing.T) {
	call := ToolCall{
		Tool:   "exec",
		Params: map[string]any{"command": "kubectl apply -f deploy.yaml"},
	}
	p := GenerateAllowRule(call)

	if len(p.Match.Tool) != 1 || p.Match.Tool[0] != "exec" {
		t.Fatalf("expected tool match [exec], got %v", p.Match.Tool)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
	if p.Rules[0].Action != "allow" {
		t.Errorf("expected allow action, got %s", p.Rules[0].Action)
	}
	if len(p.Rules[0].When.CommandMatches) != 1 || p.Rules[0].When.CommandMatches[0] != "kubectl apply *" {
		t.Errorf("expected command_matches [kubectl apply *], got %v", p.Rules[0].When.CommandMatches)
	}
	if !strings.HasPrefix(p.Name, "auto-allow-kubectl-apply-") {
		t.Errorf("unexpected name: %s", p.Name)
	}
}

func TestGenerateAllowRule_Read(t *testing.T) {
	call := ToolCall{
		Tool:   "read",
		Params: map[string]any{"path": "/etc/passwd"},
	}
	p := GenerateAllowRule(call)

	if p.Match.Tool[0] != "read" {
		t.Fatalf("expected tool read, got %v", p.Match.Tool)
	}
	if p.Rules[0].When.PathMatches[0] != "/etc/passwd" {
		t.Errorf("expected exact path, got %v", p.Rules[0].When.PathMatches)
	}
}

func TestGenerateAllowRule_Write(t *testing.T) {
	call := ToolCall{
		Tool:   "write",
		Params: map[string]any{"path": "/tmp/output.txt"},
	}
	p := GenerateAllowRule(call)

	if p.Match.Tool[0] != "write" {
		t.Fatalf("expected tool write, got %v", p.Match.Tool)
	}
	if p.Rules[0].When.PathMatches[0] != "/tmp/output.txt" {
		t.Errorf("expected exact path, got %v", p.Rules[0].When.PathMatches)
	}
}

func TestGenerateAllowRule_MCP(t *testing.T) {
	call := ToolCall{
		Tool:   "mcp.my_custom_tool",
		Params: map[string]any{},
	}
	p := GenerateAllowRule(call)

	if p.Match.Tool[0] != "mcp.my_custom_tool" {
		t.Fatalf("expected tool mcp.my_custom_tool, got %v", p.Match.Tool)
	}
	if !p.Rules[0].When.Default {
		t.Error("expected default condition for MCP tool")
	}
}

func TestAppendAllowRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auto-allowed.yaml")

	call1 := ToolCall{
		Tool:   "exec",
		Params: map[string]any{"command": "kubectl apply -f foo"},
	}
	if err := AppendAllowRule(path, call1); err != nil {
		t.Fatal(err)
	}

	// Verify file is valid YAML and loadable.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated YAML is invalid: %v", err)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(cfg.Policies))
	}

	// Append a second rule.
	call2 := ToolCall{
		Tool:   "read",
		Params: map[string]any{"path": "/etc/hosts"},
	}
	if err := AppendAllowRule(path, call2); err != nil {
		t.Fatal(err)
	}

	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 Config
	if err := yaml.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("generated YAML is invalid after append: %v", err)
	}
	if len(cfg2.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(cfg2.Policies))
	}

	// Verify the config is loadable by the engine's validator.
	if err := cfg2.validate(); err != nil {
		t.Fatalf("generated config fails validation: %v", err)
	}
}

func TestAppendAllowRule_CreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deep", "nested", "auto-allowed.yaml")

	call := ToolCall{
		Tool:   "exec",
		Params: map[string]any{"command": "echo hello"},
	}
	if err := AppendAllowRule(path, call); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/etc/passwd", "etc-passwd"},
		{"mcp.tool.name", "mcp-tool-name"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		got := sanitizeName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
