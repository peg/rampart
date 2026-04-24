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
	"runtime"
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
	want := filepath.FromSlash(".rampart/audit")
	if got != want {
		t.Errorf("relHome = %q, want %s", got, want)
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
	testSetHome(t, home)

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

func TestDoctorPolicies_EmptyCustomPlaceholderIsNotWarn(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	policyDir := filepath.Join(home, ".rampart", "policies")
	requireNoErr(t, os.MkdirAll(policyDir, 0o755))
	requireNoErr(t, os.WriteFile(filepath.Join(policyDir, "custom.yaml"), []byte("version: \"1\"\n"), 0o644))

	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}

	issues := doctorPolicies(emit)
	if issues != 0 {
		t.Fatalf("expected no policy issues, got %d", issues)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].Status != "ok" {
		t.Fatalf("expected ok status for empty custom placeholder, got %q (%s)", results[0].Status, results[0].Message)
	}
	if strings.Contains(results[0].Message, "lint warning") {
		t.Fatalf("expected lint warning to be suppressed, got %q", results[0].Message)
	}
}

// TestDoctorHooks_ClaudeBinaryNoDir verifies that doctorHooks flags a missing hook
// when the claude binary is in PATH but ~/.claude/ has never been created.
func TestDoctorHooks_ClaudeBinaryNoDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH shim binaries in this test are Unix-only")
	}
	home := t.TempDir()
	testSetHome(t, home)

	// ~/.claude/ intentionally absent — simulate fresh claude install
	binDir := t.TempDir()
	writeTestExecutable(t, filepath.Join(binDir, "claude"))
	t.Setenv("PATH", binDir)

	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}
	issues := doctorHooks(emit)
	if issues != 1 {
		t.Fatalf("expected 1 issue (missing Claude Code hook), got %d (%+v)", issues, results)
	}
	if results[0].Status != "fail" {
		t.Fatalf("expected fail status, got %q", results[0].Status)
	}
	if !strings.Contains(results[0].Message, ".claude") {
		t.Fatalf("expected .claude path in message, got: %s", results[0].Message)
	}
}

// TestDoctorCoverage_OpenClawOnlyWithClaudeBinary verifies that a contextual warning
// is emitted when OpenClaw protection is configured but claude binary has no native hooks.
func TestDoctorCoverage_OpenClawOnlyWithClaudeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH shim binaries in this test are Unix-only")
	}
	home := t.TempDir()
	testSetHome(t, home)

	binDir := t.TempDir()
	writeTestExecutable(t, filepath.Join(binDir, "claude"))
	t.Setenv("PATH", binDir)

	protected := []string{"OpenClaw (plugin)"}
	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}
	warnings := doctorCoverage(emit, protected)
	if warnings != 1 {
		t.Fatalf("expected 1 warning, got %d (%+v)", warnings, results)
	}
	if results[0].Status != "warn" {
		t.Fatalf("expected warn status, got %q", results[0].Status)
	}
	if !strings.Contains(results[0].Message, "OpenClaw") {
		t.Fatalf("expected OpenClaw mentioned in message, got: %s", results[0].Message)
	}
}

// TestDoctorCoverage_NativeHooksPresent verifies no warning when Claude Code hooks are configured.
func TestDoctorCoverage_NativeHooksPresent(t *testing.T) {
	protected := []string{"Claude Code (hooks)", "OpenClaw (plugin)"}
	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}
	warnings := doctorCoverage(emit, protected)
	if warnings != 0 {
		t.Fatalf("expected no warnings when Claude Code hooks configured, got %d (%+v)", warnings, results)
	}
}

// TestDoctorCoverage_OpenClawOnlyNoClaude verifies no warning when claude binary absent.
func TestDoctorCoverage_OpenClawOnlyNoClaude(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir()) // empty bin dir, no claude binary

	protected := []string{"OpenClaw (plugin)"}
	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}
	warnings := doctorCoverage(emit, protected)
	if warnings != 0 {
		t.Fatalf("expected no warnings when claude not in PATH, got %d (%+v)", warnings, results)
	}
}

func TestDoctorOpenClawReadiness(t *testing.T) {
	t.Run("skips when plugin inactive", func(t *testing.T) {
		var results []checkResult
		emit := func(name, status, msg string) {
			results = append(results, checkResult{Name: name, Status: status, Message: msg})
		}
		warnings := doctorOpenClawReadiness(emit, false, "", "")
		if warnings != 0 || len(results) != 0 {
			t.Fatalf("expected skip, got warnings=%d results=%+v", warnings, results)
		}
	})

	t.Run("warns when serve unreachable", func(t *testing.T) {
		home := t.TempDir()
		testSetHome(t, home)
		requireNoErr(t, os.MkdirAll(filepath.Join(home, ".openclaw"), 0o755))
		var results []checkResult
		emit := func(name, status, msg string) {
			results = append(results, checkResult{Name: name, Status: status, Message: msg})
		}
		warnings := doctorOpenClawReadiness(emit, true, "", "token")
		if warnings != 1 || len(results) != 1 || results[0].Status != "warn" {
			t.Fatalf("expected one warning, got warnings=%d results=%+v", warnings, results)
		}
		if !strings.Contains(results[0].Message, "approval learning is unavailable") {
			t.Fatalf("expected approval learning warning, got %s", results[0].Message)
		}
	})

	t.Run("ok when prerequisites present", func(t *testing.T) {
		home := t.TempDir()
		testSetHome(t, home)
		requireNoErr(t, os.MkdirAll(filepath.Join(home, ".openclaw"), 0o755))
		var results []checkResult
		emit := func(name, status, msg string) {
			results = append(results, checkResult{Name: name, Status: status, Message: msg})
		}
		warnings := doctorOpenClawReadiness(emit, true, "http://localhost:9090", "token")
		if warnings != 0 || len(results) != 1 || results[0].Status != "ok" {
			t.Fatalf("expected ok, got warnings=%d results=%+v", warnings, results)
		}
		if !strings.Contains(results[0].Message, "approval learning prerequisites present") {
			t.Fatalf("expected readiness summary, got %s", results[0].Message)
		}
	})
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
