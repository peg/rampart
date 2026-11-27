// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/engine"
)

func openCodeTestInput(t *testing.T, directory, tool string, args map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(openCodeHookInput{tool, "session-fixed", "call-fixed", directory, args})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOpenCodeActionIdentity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "directory ")
	for _, tool := range []string{"read", "write", "edit"} {
		parsed, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, directory, tool, map[string]any{"filePath": " target ", "path": "decoy"})))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.WorkDir != directory || parsed.Params["path"] != " target " || parsed.Params["filePath"] != " target " || parsed.SessionID != "session-fixed" || parsed.ToolUseID != "call-fixed" {
			t.Fatalf("identity changed: %#v", parsed)
		}
	}
	parsed, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, directory, "bash", map[string]any{"command": "printf marker ", "workdir": "nested "})))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.WorkDir != filepath.Join(directory, "nested ") || parsed.Params["workdir"] != parsed.WorkDir || parsed.Params["command"] != "printf marker " {
		t.Fatalf("command/CWD changed: %#v", parsed)
	}
}

func TestOpenCodeMalformedOrUnsupportedActionRefuses(t *testing.T) {
	dir := t.TempDir()
	for _, tool := range []string{"task", "skill", "execute", "lsp", "websearch", "mcp_example", "custom_tool", " Bash"} {
		if _, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, dir, tool, map[string]any{}))); err == nil {
			t.Fatalf("unexpected support for %q", tool)
		}
	}
	for _, args := range []map[string]any{{}, {"filePath": 42}, {"filePath": ""}, {"filePath": "x\x00y"}} {
		if _, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, dir, "write", args))); err == nil {
			t.Fatalf("invalid target accepted: %#v", args)
		}
	}
	valid := openCodeTestInput(t, dir, "read", map[string]any{"filePath": "marker"})
	for _, payload := range [][]byte{nil, []byte(`null`), append(append([]byte{}, valid...), []byte(` {}`)...), []byte(`{"tool":"read"}`)} {
		if _, err := parseOpenCodeInput(bytes.NewReader(payload)); err == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
}

func TestOpenCodePatchUsesHostTargetsAndDenyWins(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: \ufeff allowed.txt \t\n+marker\n*** Update File: prior.txt\n*** Move to: protected.txt \n@@\n-old\n+marker\n*** End Patch"
	parsed, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, t.TempDir(), "apply_patch", map[string]any{"patchText": patch})))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed.PolicyPaths, []string{"allowed.txt", "prior.txt", "protected.txt"}) || parsed.Params["patchText"] != patch {
		t.Fatalf("host targets/identity = %#v", parsed)
	}
	policy := []byte("version: '1'\ndefault_action: allow\npolicies:\n  - name: marker-policy\n    match:\n      tool: [write]\n    rules:\n      - action: deny\n        when:\n          path_matches: ['**/protected.txt', 'protected.txt']\n")
	eng, err := engine.New(engine.NewMemoryStore(policy, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, decision := evaluateHookCall(eng, engine.ToolCall{Agent: "opencode", Tool: "write", WorkDir: parsed.WorkDir, Params: parsed.Params}, parsed.PolicyPaths)
	if decision.Action != engine.ActionDeny {
		t.Fatalf("multi-target decision=%v", decision.Action)
	}
}

func TestOpenCodePatchLineEndings(t *testing.T) {
	patch := "*** Begin Patch\r\n*** Add File: marker.txt\r\n+marker\r\n*** End Patch"
	paths, err := extractOpenCodePatchPaths(patch)
	if err != nil || !reflect.DeepEqual(paths, []string{"marker.txt"}) {
		t.Fatalf("CRLF targets = %v, %v", paths, err)
	}
	if _, err := extractOpenCodePatchPaths(strings.ReplaceAll(patch, "\r\n", "\r")); err == nil {
		t.Fatal("bare carriage return accepted")
	}
}

// Only a clean allow evaluation answers allow; every other outcome refuses.
func TestOpenCodeHookDecisions(t *testing.T) {
	for _, action := range []string{"allow", "ask", "invalid-policy", "audit-failure", "empty-input"} {
		t.Run(action, func(t *testing.T) {
			home := t.TempDir()
			testSetHome(t, home)
			t.Setenv("RAMPART_TOKEN", "")
			t.Setenv("RAMPART_SERVE_URL", "http://127.0.0.1:1")
			t.Setenv("RAMPART_NO_PROJECT_POLICY", "1")
			policy := filepath.Join(home, "policy.yaml")
			policyAction := action
			if action == "audit-failure" || action == "empty-input" {
				policyAction = "allow"
			}
			if action == "invalid-policy" {
				policyAction = "invalid-action"
			}
			policyBytes := []byte("version: '1'\ndefault_action: allow\npolicies:\n  - name: marker-test\n    match:\n      tool: [write]\n    rules:\n      - action: " + policyAction + "\n")
			eng, err := engine.New(engine.NewMemoryStore(policyBytes, ""), nil)
			if action == "invalid-policy" {
				if err == nil {
					t.Fatal("invalid fixture policy accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if got := eng.Evaluate(engine.ToolCall{Tool: "write", Params: map[string]any{"path": "marker"}}).Action.String(); got != policyAction {
				t.Fatalf("fixture decision %q, want %q", got, policyAction)
			}
			if err := os.WriteFile(policy, policyBytes, 0600); err != nil {
				t.Fatal(err)
			}
			auditPath := filepath.Join(home, "audit")
			if action == "audit-failure" {
				if err := os.WriteFile(auditPath, []byte("marker"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var out, diagnostics bytes.Buffer
			cmd := NewRootCmd(context.Background(), &out, &diagnostics)
			payload := openCodeTestInput(t, home, "write", map[string]any{"filePath": "marker"})
			if action == "empty-input" {
				payload = nil
			}
			cmd.SetIn(bytes.NewReader(payload))
			cmd.SetArgs([]string{"--config", policy, "hook", "--format", "opencode", "--audit-dir", auditPath})
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			var reply map[string]any
			if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			want := "deny"
			if action == "allow" {
				want = "allow"
			}
			if reply["decision"] != want {
				t.Fatalf("decision=%v, want %s", reply, want)
			}
		})
	}
}

func FuzzOpenCodeInput(f *testing.F) {
	f.Add([]byte(`{"tool":"write","sessionID":"s","callID":"c","directory":"/tmp","args":{"filePath":"marker"}}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseOpenCodeInput(bytes.NewReader(data)) })
}

func TestOpenCodeFeedbackRedacts(t *testing.T) {
	var out bytes.Buffer
	if err := outputOpenCodeHookResult(&out, hookDeny, "Authorization: Bearer synthetic-credential-marker"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "synthetic-credential-marker") {
		t.Fatal("feedback persisted sensitive value")
	}
}

func TestOpenCodeSearchesAreReadsOfTheirRoot(t *testing.T) {
	directory := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), ".ssh") // absolute on every OS
	cases := []struct {
		tool string
		args map[string]any
		want string
	}{
		{"grep", map[string]any{"pattern": "TODO"}, directory},
		{"glob", map[string]any{"pattern": "**/*.go", "path": "src"}, filepath.Join(directory, "src")},
		{"list", map[string]any{"path": elsewhere}, elsewhere},
	}
	for _, tc := range cases {
		parsed, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, directory, tc.tool, tc.args)))
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		if parsed.Tool != "read" || parsed.Params["path"] != tc.want {
			t.Fatalf("%s mapped to %q %v, want read %q", tc.tool, parsed.Tool, parsed.Params["path"], tc.want)
		}
	}
	if _, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, directory, "grep", map[string]any{"path": 7}))); err == nil {
		t.Fatal("non-string search path was accepted")
	}
}

// grep returns file contents, including hidden files, so it must not search
// above the project or across the home directory.
func TestOpenCodeGrepStaysInProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	project := filepath.Join(home, "proj")
	for _, args := range []map[string]any{
		{"pattern": "PRIVATE KEY", "path": ".."},
		{"pattern": "PRIVATE KEY", "path": home, "include": ".ssh/*"},
		{"pattern": "PRIVATE KEY", "path": filepath.Join(t.TempDir(), "elsewhere")},
	} {
		if _, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, project, "grep", args))); err == nil {
			t.Fatalf("grep %v was accepted", args)
		}
	}
	if _, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, home, "grep", map[string]any{"pattern": "x"}))); err == nil {
		t.Fatal("grep across the home directory was accepted")
	}
	if _, err := parseOpenCodeInput(bytes.NewReader(openCodeTestInput(t, project, "grep", map[string]any{"pattern": "x", "path": "src"}))); err != nil {
		t.Fatalf("grep inside the project was refused: %v", err)
	}
}
