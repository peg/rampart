// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hermesplugin "github.com/peg/rampart/internal/plugin/hermes"
	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
)

func TestConfiguredVerificationTargetsIncludesPolicyAndConfiguredHooks(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	command, commandWindows := currentCodexHookCommands()
	if err := installCodexHooks(hooksPath, command, commandWindows, false); err != nil {
		t.Fatal(err)
	}
	hermesHome := filepath.Join(home, ".hermes")
	if err := hermesplugin.Extract(filepath.Join(hermesHome, "plugins", "rampart")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hermesHome, "config.yaml"), []byte("plugins:\n  enabled: [rampart]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	targets := configuredVerificationTargets(home)
	if got := strings.Join(targets, ","); got != "policy,codex" {
		t.Fatalf("configured verification targets = %q, want policy,codex (static Hermes must be skipped)", got)
	}
}

func TestRunAllBehavioralVerificationsWritesAggregateEvidence(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("RAMPART_TOKEN", "verification-token")
	command, commandWindows := currentCodexHookCommands()
	if err := installCodexHooks(filepath.Join(home, ".codex", "hooks.json"), command, commandWindows, false); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer verification-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		var body struct {
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		decision := "deny"
		if body.Params["command"] == "pwd" {
			decision = "allow"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allowed": decision == "allow", "decision": decision, "message": "safe test decision",
		})
	}))
	defer server.Close()

	report, err := runAllBehavioralVerifications(context.Background(), server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != verifyAllJSONSchemaVersion || !report.SafeCanaries {
		t.Fatalf("unexpected aggregate metadata: %#v", report)
	}
	if report.Summary.Targets != 2 || report.Summary.PassedTargets != 2 || report.Summary.Checks != 12 {
		t.Fatalf("unexpected aggregate summary: %#v", report.Summary)
	}
	if len(report.Results) != 2 || report.Results[0].Target != "policy" || report.Results[1].Target != "codex" {
		t.Fatalf("unexpected aggregate results: %#v", report.Results)
	}
	if _, err := os.Stat(filepath.Join(home, ".rampart", "verification", "codex.json")); err != nil {
		t.Fatalf("aggregate verification receipt missing: %v", err)
	}
}

func TestVerifyAllRejectsExplicitTarget(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := NewRootCmd(context.Background(), &out, &errOut)
	cmd.SetArgs([]string{"verify", "codex", "--all"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--all cannot be combined") {
		t.Fatalf("error = %v, want --all target conflict", err)
	}
}

func TestBehavioralVerificationSafeCanariesPass(t *testing.T) {
	installVerificationToken(t, "verification-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer verification-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		var body struct {
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		decision := "deny"
		if body.Params["command"] == "pwd" {
			decision = "allow"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allowed": decision == "allow", "decision": decision, "message": "safe test decision",
		})
	}))
	defer server.Close()

	report := runBehavioralVerification(context.Background(), "policy", server.URL, time.Second)
	if report.SchemaVersion != verifyJSONSchemaVersion || !report.SafeCanaries {
		t.Fatalf("unexpected report metadata: %#v", report)
	}
	if report.Summary.Checks != 5 || report.Summary.Passed != 5 || report.Summary.Failed != 0 || report.Summary.Unverified != 0 {
		t.Fatalf("unexpected summary: %#v", report.Summary)
	}
}

func TestBehavioralVerificationDetectsWrongDecision(t *testing.T) {
	installVerificationToken(t, "verification-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "decision": "allow"})
	}))
	defer server.Close()

	report := runBehavioralVerification(context.Background(), "policy", server.URL, time.Second)
	if report.Summary.Failed == 0 {
		t.Fatalf("expected unsafe decisions to fail verification: %#v", report)
	}
}

func TestBehavioralVerificationReportsMissingTokenAsUnverified(t *testing.T) {
	testSetHome(t, t.TempDir())
	t.Setenv("RAMPART_TOKEN", "")
	report := runBehavioralVerification(context.Background(), "policy", "http://127.0.0.1:1", 50*time.Millisecond)
	if report.Summary.Unverified != 5 || report.Summary.Failed != 0 {
		t.Fatalf("unexpected summary: %#v", report.Summary)
	}
	for _, check := range report.Checks {
		if check.Status != verificationUnverified || !strings.Contains(check.Message, "token") {
			t.Fatalf("unexpected check: %#v", check)
		}
	}
}

func TestBehavioralVerificationUsesEnvironmentToken(t *testing.T) {
	testSetHome(t, t.TempDir())
	t.Setenv("RAMPART_TOKEN", "environment-verification-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer environment-verification-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		var body struct {
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		decision := "deny"
		if body.Params["command"] == "pwd" {
			decision = "allow"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": decision == "allow", "decision": decision})
	}))
	defer server.Close()

	report := runBehavioralVerification(context.Background(), "policy", server.URL, time.Second)
	if report.Summary.Passed != 5 {
		t.Fatalf("environment-backed verification did not pass: %#v", report)
	}
}

func TestVerifyCodexHooksInstalled(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	command, commandWindows := currentCodexHookCommands()
	if err := installCodexHooks(hooksPath, command, commandWindows, false); err != nil {
		t.Fatal(err)
	}
	check := verifyCodexHooksInstalled()
	if check.Status != verificationPass {
		t.Fatalf("unexpected check: %#v", check)
	}
}

func TestVerifyCodexHookAdapterBlocksCanary(t *testing.T) {
	testSetHome(t, t.TempDir())
	check := verifyCodexHookAdapter(context.Background())
	if check.Status != verificationPass {
		t.Fatalf("unexpected check: %#v", check)
	}
}

func TestVerifyGeminiHooksAndAdapterBlockCanary(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	if err := installGeminiHooks(filepath.Join(home, ".gemini", "settings.json"), currentGeminiHookCommand(), false); err != nil {
		t.Fatal(err)
	}
	if check := verifyGeminiHooksInstalled(); check.Status != verificationPass {
		t.Fatalf("unexpected installation check: %#v", check)
	}
	if check := verifyGeminiHookAdapter(context.Background()); check.Status != verificationPass {
		t.Fatalf("unexpected adapter check: %#v", check)
	}
}

func TestVerifyCopilotHooksAndAdapterBlockCanary(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	path := filepath.Join(home, ".copilot", "hooks", copilotRampartHookFile)
	bashCommand, powershellCommand := currentCopilotHookCommands()
	if err := installCopilotHooks(path, bashCommand, powershellCommand, false); err != nil {
		t.Fatal(err)
	}
	if check := verifyCopilotHooksInstalled(); check.Status != verificationPass {
		t.Fatalf("unexpected installation check: %#v", check)
	}
	if check := verifyCopilotHookAdapter(context.Background()); check.Status != verificationPass {
		t.Fatalf("unexpected adapter check: %#v", check)
	}
}

func TestVerifyCursorHooksAndAdapterBlockCanary(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	if err := installCursorHooks(cursorHooksPath(home), currentCursorHookCommand(), false); err != nil {
		t.Fatal(err)
	}
	if check := verifyCursorHooksInstalled(); check.Status != verificationPass {
		t.Fatalf("unexpected installation check: %#v", check)
	}
	if check := verifyCursorHookAdapter(context.Background()); check.Status != verificationPass {
		t.Fatalf("unexpected adapter check: %#v", check)
	}
}

func TestVerifyClaudeAndClineAdaptersBlockCanary(t *testing.T) {
	testSetHome(t, t.TempDir())
	for _, target := range []string{"claude-code", "cline"} {
		if check := verifyNativeHookAdapter(context.Background(), target); check.Status != verificationPass {
			t.Fatalf("%s adapter check: %#v", target, check)
		}
	}
}

func TestVerifyOpenClawPluginLiveParsesGatewayPayload(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := ocplugin.Extract(pluginDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "openclaw.json"), []byte(`{"plugins":{"allow":["rampart"],"entries":{"rampart":{"enabled":true}}},"tools":{"exec":{"mode":"full"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	shim := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "get" ]; then
  case "$3" in
    tools.exec) printf '%s\n' '{"mode":"full"}' ;;
    plugins.entries.rampart.config) printf '%s\n' '{"failOpen":false,"failOpenTools":null,"serveUrl":"http://localhost:9090","approvalTimeoutMs":120000}' ;;
    *) exit 1 ;;
  esac
  exit 0
fi
printf '%s\n' '[state-migrations] Legacy state migration notes:'
printf '%s\n' '- Left plugin install index in place because shared SQLite state has conflicting plugin install metadata for: rampart'
printf '%s\n' '{"result":{"schema":"rampart.plugin.verify.v1","safeCanaries":true,"ok":true,"checks":[{"id":"routine-command","expected":"allow","actual":"allow","pass":true},{"id":"destructive-command","expected":"deny","actual":"deny","pass":true},{"id":"external-deployment","expected":"ask","actual":"ask","pass":true},{"id":"cross-conversation-message","expected":"ask","actual":"ask","pass":true},{"id":"credential-shell-read","expected":"deny","actual":"deny","pass":true},{"id":"opaque-interpreter","expected":"ask","actual":"ask","pass":true}]}}'
`
	if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	t.Setenv("RAMPART_OPENCLAW_BIN", bin)

	check := verifyOpenClawPluginLive(context.Background(), time.Second)
	if check.Status != verificationPass {
		t.Fatalf("unexpected check: %#v", check)
	}
}

func TestVerifyOpenClawManagedConfigRejectsDrift(t *testing.T) {
	skipOnWindows(t, "test uses POSIX OpenClaw shims")
	tests := []struct {
		name         string
		askValue     string
		pluginConfig string
		want         string
	}{
		{
			name:         "exec approval ownership",
			askValue:     `"on-miss"`,
			pluginConfig: `{"failOpen":false,"failOpenTools":null,"serveUrl":"http://localhost:9090","approvalTimeoutMs":120000}`,
			want:         "tools.exec.ask",
		},
		{
			name:         "fail-open plugin",
			askValue:     `"off"`,
			pluginConfig: `{"failOpen":true,"failOpenTools":null,"serveUrl":"http://localhost:9090","approvalTimeoutMs":120000}`,
			want:         "failOpen",
		},
		{
			name:         "approval timeout",
			askValue:     `"off"`,
			pluginConfig: `{"failOpen":false,"failOpenTools":null,"serveUrl":"http://localhost:9090","approvalTimeoutMs":1000}`,
			want:         "approvalTimeoutMs",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			stateDir := t.TempDir()
			t.Setenv("OPENCLAW_STATE_DIR", stateDir)
			config := []byte(`{"tools":{"exec":{"ask":` + testCase.askValue + `}}}`)
			if err := os.WriteFile(filepath.Join(stateDir, "openclaw.json"), config, 0o600); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(t.TempDir(), "openclaw")
			shim := "#!/bin/sh\ncase \"$3\" in\n" +
				"  tools.exec) printf '%s\\n' '{\"ask\":" + testCase.askValue + "}' ;;\n" +
				"  plugins.entries.rampart.config) printf '%s\\n' '" + testCase.pluginConfig + "' ;;\n" +
				"  *) exit 1 ;;\nesac\n"
			if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
				t.Fatal(err)
			}
			err := verifyOpenClawManagedConfig(context.Background(), bin)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want %q drift", err, testCase.want)
			}
		})
	}
}

func TestVerifyOpenClawManagedConfigAcceptsCanonicalExecModes(t *testing.T) {
	skipOnWindows(t, "test uses POSIX OpenClaw shims")
	for _, mode := range []string{"deny", "allowlist", "ask", "auto", "full"} {
		t.Run(mode, func(t *testing.T) {
			stateDir := t.TempDir()
			t.Setenv("OPENCLAW_STATE_DIR", stateDir)
			if err := os.WriteFile(filepath.Join(stateDir, "openclaw.json"), []byte(`{"tools":{"exec":{"mode":"`+mode+`","timeout":30}}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(t.TempDir(), "openclaw")
			shim := "#!/bin/sh\ncase \"$3\" in\n" +
				"  tools.exec) printf '%s\\n' '{\"mode\":\"" + mode + "\",\"timeout\":30}' ;;\n" +
				"  plugins.entries.rampart.config) printf '%s\\n' '{\"failOpen\":false,\"failOpenTools\":null,\"serveUrl\":\"http://localhost:9090\",\"approvalTimeoutMs\":120000}' ;;\n" +
				"  *) exit 1 ;;\nesac\n"
			if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := verifyOpenClawManagedConfig(context.Background(), bin); err != nil {
				t.Fatalf("verify canonical mode: %v", err)
			}
		})
	}
}

func TestVerifyOpenClawManagedConfigRejectsInvalidCanonicalExecMode(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	stateDir := t.TempDir()
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	if err := os.WriteFile(filepath.Join(stateDir, "openclaw.json"), []byte(`{"tools":{"exec":{"mode":"future-unknown"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	shim := `#!/bin/sh
case "$3" in
  plugins.entries.rampart.config) printf '%s\n' '{"failOpen":false,"failOpenTools":null,"serveUrl":"http://localhost:9090","approvalTimeoutMs":120000}' ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenClawManagedConfig(context.Background(), bin); err == nil || !strings.Contains(err.Error(), "tools.exec.mode") {
		t.Fatalf("error = %v, want canonical mode drift", err)
	}
}

func TestVerifyOpenClawManagedConfigRejectsActiveConfigMismatch(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	stateDir := t.TempDir()
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	if err := os.WriteFile(filepath.Join(stateDir, "openclaw.json"), []byte(`{"tools":{"exec":{"mode":"auto"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	shim := `#!/bin/sh
case "$3" in
  tools.exec) printf '%s\n' '{"mode":"full"}' ;;
  plugins.entries.rampart.config) printf '%s\n' '{"failOpen":false,"failOpenTools":null,"serveUrl":"http://localhost:9090","approvalTimeoutMs":120000}' ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(bin, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenClawManagedConfig(context.Background(), bin); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("error = %v, want active-config mismatch", err)
	}
}

func TestValidatePluginVerificationResultRejectsEmptyProof(t *testing.T) {
	err := validatePluginVerificationResult(map[string]any{
		"schema": "rampart.plugin.verify.v1", "safeCanaries": true, "ok": true, "checks": []any{},
	})
	if err == nil {
		t.Fatal("empty self-reported proof must not pass verification")
	}
}

func installVerificationToken(t *testing.T, token string) {
	t.Helper()
	t.Setenv("RAMPART_TOKEN", "")
	home := t.TempDir()
	testSetHome(t, home)
	dir := filepath.Join(home, ".rampart")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
}
