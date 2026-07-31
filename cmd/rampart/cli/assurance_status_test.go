// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerificationReceiptPromotesConfiguredIntegration(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)

	checkedAt := time.Now().UTC().Truncate(time.Second)
	report := passingAssuranceReport("codex", checkedAt)
	if err := writeVerificationReceipt(report); err != nil {
		t.Fatalf("writeVerificationReceipt: %v", err)
	}

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(checkedAt.Add(time.Minute), false), "codex")
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

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(checkedAt.Add(time.Minute), false), "codex")
	if !ok {
		t.Fatal("Codex assurance status missing")
	}
	if status.AssuranceLevel == assuranceAdapterVerified || status.StaleReason != "integration environment changed since verification" {
		t.Fatalf("stale Codex assurance status = %#v", status)
	}
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

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(checkedAt.Add(time.Minute), false), "codex")
	if !ok || status.StaleReason != "integration environment changed since verification" {
		t.Fatalf("policy-mutated assurance status = %#v, found=%t", status, ok)
	}
}

func TestVerificationReceiptInvalidatesWhenPolicyEndpointChanges(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	installCodexAssuranceFixture(t, home)

	checkedAt := time.Now().UTC().Truncate(time.Second)
	report := passingAssuranceReport("codex", checkedAt)
	report.policyEndpoint = "http://127.0.0.1:19090"
	if err := writeVerificationReceipt(report); err != nil {
		t.Fatalf("writeVerificationReceipt: %v", err)
	}

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(checkedAt.Add(time.Minute), false), "codex")
	if !ok || status.StaleReason != "integration environment changed since verification" {
		t.Fatalf("endpoint-mutated assurance status = %#v, found=%t", status, ok)
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

	status, ok := findAssuranceStatus(collectIntegrationAssuranceStatuses(now, false), "codex")
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
	return summarizeVerification(verificationReport{
		SchemaVersion: verifyJSONSchemaVersion,
		GeneratedAt:   checkedAt.UTC().Format(time.RFC3339),
		Target:        target,
		SafeCanaries:  true,
		Checks: []verificationCheck{
			{ID: "configuration", Name: "Configuration", Status: verificationPass, Message: "configured"},
			{ID: "behavior", Name: "Behavior", Status: verificationPass, Message: "blocked"},
		},
	})
}

func findAssuranceStatus(statuses []integrationAssuranceStatus, id string) (integrationAssuranceStatus, bool) {
	for _, status := range statuses {
		if status.ID == id {
			return status, true
		}
	}
	return integrationAssuranceStatus{}, false
}
