// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"github.com/peg/rampart/internal/proxy"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"

	hermesplugin "github.com/peg/rampart/internal/plugin/hermes"
)

func TestHermesUsesCommonStaticAssuranceStatus(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	hermesHome := filepath.Join(home, ".hermes")
	if err := hermesplugin.Extract(filepath.Join(hermesHome, "plugins", "rampart")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hermesHome, "config.yaml"), []byte("plugins:\n  enabled: [rampart]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(time.Now().UTC()), "hermes")
	if !ok {
		t.Fatal("Hermes assurance status missing")
	}
	if !status.Installed || !status.Configured || status.AssuranceLevel != assuranceConfigured {
		t.Fatalf("Hermes assurance status = %#v", status)
	}
	if status.VerificationCommand != "rampart doctor" || status.RecommendedCommand != "rampart doctor" {
		t.Fatalf("Hermes static verification guidance = %#v", status)
	}
}

func TestVerificationReceiptPromotesConfiguredIntegration(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)

	checkedAt := time.Now().UTC().Truncate(time.Second)
	report := passingAssuranceReport("codex", checkedAt)
	if err := writeVerificationReceipt(report); err != nil {
		t.Fatalf("writeVerificationReceipt: %v", err)
	}

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(checkedAt.Add(time.Minute)), "codex")
	if !ok {
		t.Fatal("Codex assurance status missing")
	}
	if status.AssuranceLevel != assuranceAdapterVerified || !status.Configured {
		t.Fatalf("Codex assurance status = %#v", status)
	}
	if status.RecommendedCommand != "rampart verify codex" || status.EvidenceSource != "local_verification_receipt" {
		t.Fatalf("Codex evidence guidance = %#v", status)
	}
	if status.CheckedAt == nil || !status.CheckedAt.Equal(checkedAt) || status.StaleReason != "" {
		t.Fatalf("Codex evidence metadata = %#v", status)
	}
}

func TestVerificationReceiptInvalidatesAfterConfigurationChange(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)

	checkedAt := time.Now().UTC().Truncate(time.Second)
	if err := writeVerificationReceipt(passingAssuranceReport("codex", checkedAt)); err != nil {
		t.Fatalf("writeVerificationReceipt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "hooks.json"), []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(checkedAt.Add(time.Minute)), "codex")
	if !ok {
		t.Fatal("Codex assurance status missing")
	}
	if status.AssuranceLevel == assuranceAdapterVerified || status.StaleReason != "integration environment changed since verification" {
		t.Fatalf("stale Codex assurance status = %#v", status)
	}
}

func TestOpenClawReceiptInvalidatesOwnedConfigurationDrift(t *testing.T) {
	for _, tc := range []struct {
		name, file, before, after string
	}{
		{"fail open", "plugins.json", `"failOpen":false`, `"failOpen":true `},
		{"plugin disabled", "plugins.json", `"enabled":true`, `"enabled":null`},
		{"policy timeout", "plugins.json", `"timeoutMs":3000`, `"timeoutMs":4000`},
		{"approval timeout", "plugins.json", `"approvalTimeoutMs":120000`, `"approvalTimeoutMs":240000`},
		{"plugin endpoint", "plugins.json", `localhost:9090`, `localhost:9999`},
		{"malformed plugin setting", "plugins.json", `"failOpen":false`, `"failOpen":"bad"`},
		{"exec mode", "tools.json", `"full"`, `"auto"`},
		{"invalid exec mode", "tools.json", `"full"`, `"oops"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			stateDir := installOpenClawAssuranceFixture(t, home)
			now := time.Now().UTC().Truncate(time.Second)
			if err := writeVerificationReceipt(passingAssuranceReport("openclaw", now)); err != nil {
				t.Fatal(err)
			}
			status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(now), "openclaw")
			if !ok || status.AssuranceLevel != assuranceHostVerified {
				t.Fatalf("initial assurance = %#v, found=%t", status, ok)
			}
			path := filepath.Join(stateDir, tc.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.Replace(data, []byte(tc.before), []byte(tc.after), 1)
			if bytes.Equal(data, changed) || len(data) != len(changed) {
				t.Fatal("fixture must change content without changing file size")
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			status, ok = findAssuranceStatus(collectIntegrationAssuranceStatuses(now.Add(time.Minute)), "openclaw")
			if !ok || status.AssuranceLevel == assuranceHostVerified || status.StaleReason != "integration environment changed since verification" {
				t.Fatalf("drifted assurance = %#v, found=%t", status, ok)
			}
		})
	}
}

func TestOpenClawReceiptInvalidatesPluginContentDrift(t *testing.T) {
	home := t.TempDir()
	stateDir := installOpenClawAssuranceFixture(t, home)
	now := time.Now().UTC().Truncate(time.Second)
	if err := writeVerificationReceipt(passingAssuranceReport("openclaw", now)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, openclawPluginDir, "index.js")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("\n// modified installation\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("modify plugin: write=%v close=%v", writeErr, closeErr)
	}
	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(now.Add(time.Minute)), "openclaw")
	if !ok || status.AssuranceLevel == assuranceHostVerified || status.StaleReason != "integration environment changed since verification" {
		t.Fatalf("modified plugin assurance = %#v, found=%t", status, ok)
	}
}

func TestOpenClawReceiptIgnoresUnrelatedConfiguration(t *testing.T) {
	home := t.TempDir()
	stateDir := installOpenClawAssuranceFixture(t, home)
	now := time.Now().UTC().Truncate(time.Second)
	if err := writeVerificationReceipt(passingAssuranceReport("openclaw", now)); err != nil {
		t.Fatal(err)
	}
	// A provider include is deliberately unreadable as JSON. Status must not
	// traverse it, nor fingerprint provider values or another plugin's settings.
	if err := os.WriteFile(filepath.Join(stateDir, "providers.json"), []byte("synthetic-private-provider-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "plugins.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"other-plugin":{"enabled":false}`), []byte(`"other-plugin":{"enabled":true}`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(now.Add(time.Minute)), "openclaw")
	if !ok || status.AssuranceLevel != assuranceHostVerified || status.StaleReason != "" {
		t.Fatalf("unrelated configuration invalidated assurance: %#v, found=%t", status, ok)
	}
	receiptPath, err := verificationReceiptPath("openclaw")
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{home, "private-provider", "provider-token", "other-plugin"} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatalf("receipt retained configuration detail %q", private)
		}
	}
}

func installOpenClawAssuranceFixture(t *testing.T, home string) string {
	t.Helper()
	testSetHome(t, home)
	testSetOpenClawBinary(t, home)
	oldClient := rampartHTTPClient
	rampartHTTPClient = &http.Client{Transport: redirectTestTransport(func(req *http.Request) (*http.Response, error) { return statusTestHealthResponse(req, "enforce"), nil })}
	t.Cleanup(func() { rampartHTTPClient = oldClient })
	stateDir := filepath.Join(home, ".openclaw")
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	t.Setenv("OPENCLAW_CONFIG_PATH", filepath.Join(stateDir, "openclaw.json"))
	if err := ocplugin.Extract(filepath.Join(stateDir, openclawPluginDir)); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"openclaw.json":  `{"tools":{"$include":"tools.json"},"plugins":{"$include":"plugins.json"},"models":{"$include":"providers.json"}}`,
		"tools.json":     `{"exec":{"mode":"full"}}`,
		"plugins.json":   `{"allow":["rampart"],"entries":{"rampart":{"config":{"enabled":true,"failOpen":false,"failOpenTools":[],"timeoutMs":3000,"approvalTimeoutMs":120000,"serveUrl":"http://localhost:9090"}},"other-plugin":{"enabled":false}}}`,
		"providers.json": `{"credential":"synthetic-provider-token"}`,
	} {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return stateDir
}

func TestVerificationReceiptInvalidatesAfterPolicyChange(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)
	policyDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policyDir, "guard.yaml")
	if err := os.WriteFile(policyPath, []byte("version: \"1\"\ndefault_action: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	checkedAt := time.Now().UTC().Truncate(time.Second)
	if err := writeVerificationReceipt(passingAssuranceReport("codex", checkedAt)); err != nil {
		t.Fatalf("writeVerificationReceipt: %v", err)
	}
	if err := os.WriteFile(policyPath, []byte("version: \"1\"\ndefault_action: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(checkedAt.Add(time.Minute)), "codex")
	if !ok || status.StaleReason != "integration environment changed since verification" {
		t.Fatalf("policy-mutated assurance status = %#v, found=%t", status, ok)
	}
}

func TestLocalAdapterReceiptDoesNotDependOnPolicyEndpoint(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)

	checkedAt := time.Now().UTC().Truncate(time.Second)
	report := passingAssuranceReport("codex", checkedAt)
	report.policyEndpoint = "http://127.0.0.1:19090"
	if err := writeVerificationReceipt(report); err != nil {
		t.Fatalf("writeVerificationReceipt: %v", err)
	}

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(checkedAt.Add(time.Minute)), "codex")
	if !ok || status.StaleReason != "" || status.AssuranceLevel != assuranceAdapterVerified || status.Runtime != nil {
		t.Fatalf("local adapter assurance depends on HTTP: %#v, found=%t", status, ok)
	}
}

func TestVerificationReceiptExpires(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)

	now := time.Now().UTC().Truncate(time.Second)
	if err := writeVerificationReceipt(passingAssuranceReport("codex", now.Add(-8*24*time.Hour))); err != nil {
		t.Fatalf("writeVerificationReceipt: %v", err)
	}

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(now), "codex")
	if !ok || status.StaleReason != "verification evidence expired" || status.AssuranceLevel != assuranceConfigured {
		t.Fatalf("expired assurance status = %#v, found=%t", status, ok)
	}
}

func TestVerificationReceiptExcludesCheckDetails(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)

	report := passingAssuranceReport("codex", time.Now().UTC().Truncate(time.Second))
	report.Checks[0].Actual = "/Users/example/private-key"
	report.Checks[0].Expected = "sensitive expected value"
	report.Checks[0].Message = "secret message"
	report.Checks[0].Hint = "secret hint"
	if err := writeVerificationReceipt(report); err != nil {
		t.Fatalf("writeVerificationReceipt: %v", err)
	}
	path, err := verificationReceiptPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-key", "sensitive expected", "secret message", "secret hint"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("verification receipt retained sensitive check detail %q: %s", forbidden, data)
		}
	}
}

func TestVerificationReceiptRefusesSymlinkTarget(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)
	verificationDir := filepath.Join(home, ".rampart", "verification")
	if err := os.MkdirAll(verificationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(verificationDir, "codex.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := writeVerificationReceipt(passingAssuranceReport("codex", time.Now().UTC()))
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("writeVerificationReceipt symlink error = %v", err)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "unchanged" {
		t.Fatalf("receipt write changed symlink target: data=%q err=%v", data, readErr)
	}
}

func TestAssuranceLevelMatchesVerificationBoundary(t *testing.T) {
	now := time.Now().UTC()
	if got := passingAssuranceReport("openclaw", now).Assurance; got != assuranceHostVerified {
		t.Fatalf("OpenClaw assurance = %q, want %q", got, assuranceHostVerified)
	}
	if got := passingAssuranceReport("claude-code", now).Assurance; got != assuranceAdapterVerified {
		t.Fatalf("Claude Code assurance = %q, want %q", got, assuranceAdapterVerified)
	}
	if got := passingAssuranceReport("policy", now).Assurance; got != assurancePolicyVerified {
		t.Fatalf("policy assurance = %q, want %q", got, assurancePolicyVerified)
	}
	failing := passingAssuranceReport("openclaw", now)
	failing.Checks[0].Status = verificationFail
	failing = summarizeVerification(failing)
	if failing.Assurance != assuranceDegraded {
		t.Fatalf("failed assurance = %q, want %q", failing.Assurance, assuranceDegraded)
	}
}

func installCodexAssuranceFixture(t *testing.T, home string) {
	t.Helper()
	path := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	command, commandWindows := currentCodexHookCommands()
	if err := installCodexHooks(path, command, commandWindows, false); err != nil {
		t.Fatal(err)
	}
}

func passingAssuranceReport(target string, checkedAt time.Time) verificationReport {
	report := verificationReport{
		SchemaVersion: verifyJSONSchemaVersion,
		GeneratedAt:   checkedAt.UTC().Format(time.RFC3339),
		Target:        target,
		SafeCanaries:  true,
		Checks: []verificationCheck{
			{ID: "configuration", Name: "Configuration", Status: verificationPass, Message: "configured"},
			{ID: "behavior", Name: "Behavior", Status: verificationPass, Message: "blocked"},
		},
	}
	if driver, ok := findIntegrationDriver(target); ok && driver.ServiceRequired {
		endpoint, _ := integrationServiceEndpoint(driver)
		report.Runtime = &serviceRuntimeObservation{Endpoint: endpoint, RuntimeIdentity: proxy.RuntimeIdentity{InstanceID: "test-service-instance-0001", Version: "1.9.0", Commit: "test-commit", Mode: "enforce"}}
	}
	return summarizeVerification(report)
}

func findAssuranceStatus(statuses []integrationAssuranceStatus, id string) (integrationAssuranceStatus, bool) {
	for _, status := range statuses {
		if status.ID == id {
			return status, true
		}
	}
	return integrationAssuranceStatus{}, false
}
