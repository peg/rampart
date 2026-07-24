// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
)

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

func TestVerifyOpenClawPluginLiveParsesGatewayPayload(t *testing.T) {
	skipOnWindows(t, "test uses a POSIX OpenClaw shim")
	stateDir := t.TempDir()
	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "openclaw.plugin.json"), []byte(`{"version":"1.3.0","activation":{"onStartup":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundled, err := ocplugin.PluginFS.ReadFile("index.js")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "index.js"), bundled, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "openclaw.json"), []byte(`{"plugins":{"allow":["rampart"],"entries":{"rampart":{"enabled":true}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "openclaw")
	shim := `#!/bin/sh
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
