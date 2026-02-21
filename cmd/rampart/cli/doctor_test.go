// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunDoctor(t *testing.T) {
	var buf bytes.Buffer
	err := runDoctor(&buf, false)
	if err != nil && err.Error() != "exit status 1" {
		t.Fatalf("runDoctor returned unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "🩺 Rampart Doctor") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "✓ Version:") {
		t.Error("missing version check")
	}
	if !strings.Contains(out, "System:") {
		t.Error("missing system info")
	}
}

func TestRelHome(t *testing.T) {
	got := relHome("/home/user/.rampart/audit", "/home/user")
	if got != ".rampart/audit" {
		t.Errorf("relHome = %q, want .rampart/audit", got)
	}
}

func TestFormatAgo(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"30s", "30s ago"},
		{"5m", "5m ago"},
		{"3h", "3h ago"},
	}
	for _, tt := range tests {
		d, _ := time.ParseDuration(tt.input)
		got := formatAgo(d)
		if got != tt.contains {
			t.Errorf("formatAgo(%s) = %q, want %q", tt.input, got, tt.contains)
		}
	}
}

func TestCountClaudeHookMatchers(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks": []any{
						map[string]any{"type": "command", "command": "rampart hook"},
					},
				},
			},
		},
	}
	count := countClaudeHookMatchers(settings)
	if count == 0 {
		t.Error("expected non-zero count for rampart hooks")
	}
}

func TestRunDoctor_JSON(t *testing.T) {
	var buf bytes.Buffer
	err := runDoctor(&buf, true)
	// May return exitCodeError if issues found — that's expected in test env.
	if err != nil {
		var exitErr exitCodeError
		if !errors.As(err, &exitErr) {
			t.Fatalf("unexpected error type: %v", err)
		}
	}
	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON output invalid: %v\noutput: %s", err, buf.String())
	}
	if _, ok := result["checks"]; !ok {
		t.Error("JSON output missing 'checks' field")
	}
	if _, ok := result["issues"]; !ok {
		t.Error("JSON output missing 'issues' field")
	}
}

func TestRunDoctor_ExitCode(t *testing.T) {
	var buf bytes.Buffer
	err := runDoctor(&buf, false)
	out := buf.String()
	// In CI/test environment, we expect some checks to fail (no rampart serve running).
	// Verify the output contains the header.
	if !strings.Contains(out, "🩺 Rampart Doctor") {
		t.Error("missing doctor header in output")
	}
	// Error should be nil or exitCodeError{1}.
	if err != nil {
		var exitErr exitCodeError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected exitCodeError, got: %T %v", err, err)
		}
		if exitErr.code != 1 {
			t.Errorf("expected exit code 1, got %d", exitErr.code)
		}
	}
}

func TestDoctorToken_EnvVar(t *testing.T) {
	t.Setenv("RAMPART_TOKEN", "test-token-xyz")
	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}
	issues, token := doctorToken(emit)
	if issues != 0 {
		t.Errorf("expected 0 issues with RAMPART_TOKEN set, got %d", issues)
	}
	if token != "test-token-xyz" {
		t.Errorf("expected token 'test-token-xyz', got %q", token)
	}
	if len(results) == 0 || results[0].Status != "ok" {
		t.Errorf("expected ok status, got %+v", results)
	}
}

func TestDoctorToken_Missing(t *testing.T) {
	// Ensure no token present.
	t.Setenv("RAMPART_TOKEN", "")
	// Can't easily clear ~/.rampart/token in test — just test env path.
	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}
	// With empty env var, will fall through to persisted token check.
	// Just verify no panic.
	_, _ = doctorToken(emit)
}

func TestDoctorHooks_PathHints(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	claudeDir := filepath.Join(home, ".claude")
	requireNoErr(t, os.MkdirAll(claudeDir, 0o755))
	requireNoErr(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"hooks":{}}`), 0o644))

	clineHooksDir := filepath.Join(home, "Documents", "Cline", "Hooks")
	requireNoErr(t, os.MkdirAll(clineHooksDir, 0o755))

	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}
	issues := doctorHooks(emit)
	if issues != 2 {
		t.Fatalf("expected 2 issues, got %d (%+v)", issues, results)
	}

	out := ""
	for _, r := range results {
		out += r.Message + "\n"
	}
	if !strings.Contains(out, filepath.Join(home, ".claude", "settings.json")) {
		t.Fatalf("expected Claude settings path in output, got: %s", out)
	}
	if !strings.Contains(out, filepath.Join(home, "Documents", "Cline", "Hooks")) {
		t.Fatalf("expected Cline hooks path in output, got: %s", out)
	}
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
