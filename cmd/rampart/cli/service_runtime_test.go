// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/proxy"
)

func TestServiceReceiptRejectsReplacementAndModeChange(t *testing.T) {
	for _, field := range []string{"instance", "build", "mode", "unavailable"} {
		t.Run(field, func(t *testing.T) {
			home := t.TempDir()
			installOpenClawAssuranceFixture(t, home)
			now := time.Now().UTC().Truncate(time.Second)
			report := passingAssuranceReport("openclaw", now)
			if err := writeVerificationReceipt(report); err != nil {
				t.Fatal(err)
			}
			before, _ := findAssuranceStatus(collectIntegrationAssuranceStatuses(now), "openclaw")
			if before.AssuranceLevel != assuranceHostVerified {
				t.Fatalf("initial evidence: %#v", before)
			}
			// A healthy global/default endpoint cannot rescue the host's endpoint.
			t.Setenv("RAMPART_URL", "http://127.0.0.1:19999")
			rampartHTTPClient = &http.Client{Transport: redirectTestTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != "localhost:9090" {
					t.Errorf("probed unrelated endpoint %s", req.URL.Host)
				}
				if field == "unavailable" {
					return nil, io.EOF
				}
				response := statusTestHealthResponse(req, "enforce")
				body, _ := io.ReadAll(response.Body)
				switch field {
				case "instance":
					body = bytes.ReplaceAll(body, []byte("test-service-instance-0001"), []byte("test-service-instance-0002"))
				case "build":
					body = bytes.ReplaceAll(body, []byte("test-commit"), []byte("other-commit"))
				case "mode":
					body = bytes.ReplaceAll(body, []byte("enforce"), []byte("monitor"))
				}
				response.Body = io.NopCloser(bytes.NewReader(body))
				return response, nil
			})}
			after, _ := findAssuranceStatus(collectIntegrationAssuranceStatuses(now), "openclaw")
			if after.AssuranceLevel == assuranceHostVerified || after.StaleReason == "" {
				t.Fatalf("stale runtime promoted: %#v", after)
			}
		})
	}
}

func TestLegacyReceiptDoesNotAcquireRuntimeEvidence(t *testing.T) {
	home := t.TempDir()
	installOpenClawAssuranceFixture(t, home)
	now := time.Now().UTC().Truncate(time.Second)
	report := passingAssuranceReport("openclaw", now)
	report.policyEndpoint = report.Runtime.Endpoint
	report.Runtime = nil
	if err := writeVerificationReceipt(report); err != nil {
		t.Fatal(err)
	}
	status, _ := findAssuranceStatus(collectIntegrationAssuranceStatuses(now), "openclaw")
	if status.AssuranceLevel != assuranceConfigured || status.StaleReason != "verification receipt lacks runtime identity" || status.Runtime != nil {
		t.Fatalf("legacy receipt: %#v", status)
	}
}

func TestVerificationRejectsRuntimeChangeDuringCanaries(t *testing.T) {
	for _, change := range []string{"instance", "mode"} {
		t.Run(change, func(t *testing.T) {
			installVerificationToken(t, "verification-token")
			probes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/healthz" {
					probes++
					identity := proxy.RuntimeIdentity{InstanceID: "test-service-instance-0001", Version: "test", Commit: "test-commit", Mode: "enforce"}
					if probes > 1 {
						if change == "instance" {
							identity.InstanceID = "test-service-instance-0002"
						} else {
							identity.Mode = "monitor"
						}
					}
					uptime := 1
					_ = json.NewEncoder(w).Encode(proxy.HealthResponse{RuntimeIdentity: identity, Service: "rampart", Status: "ok", UptimeSeconds: &uptime})
					return
				}
				var request struct {
					Params map[string]any `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				decision := "deny"
				if request.Params["command"] == "pwd" {
					decision = "allow"
				}
				_ = json.NewEncoder(w).Encode(preflightResponse{Allowed: decision == "allow", Decision: decision})
			}))
			defer server.Close()
			report := runBehavioralVerification(context.Background(), "policy", server.URL, time.Second)
			if report.Runtime != nil || report.Summary.Failed != 1 || report.Summary.Passed != 5 || probes != 2 {
				t.Fatalf("changed runtime report: %#v probes=%d", report, probes)
			}
		})
	}
}

func TestVerificationOverrideCannotReplaceHostEndpoint(t *testing.T) {
	installOpenClawAssuranceFixture(t, t.TempDir())
	report := runBehavioralVerification(context.Background(), "openclaw", "http://127.0.0.1:19999", time.Second)
	if report.Runtime != nil || report.Summary.Unverified != 1 || len(report.Checks) != 1 || !strings.Contains(report.Checks[0].Hint, "differs") {
		t.Fatalf("mismatched override: %#v", report)
	}
}

func TestReuseReportsLegacyAndRefusesNonEnforcingServiceWithoutMutation(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	path := filepath.Join(home, ".rampart", "token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const canary = "synthetic-private-token"
	if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"enforce", "monitor", "disabled"} {
		var output bytes.Buffer
		observed := serviceRuntimeObservation{Endpoint: "https://example.invalid", RuntimeIdentity: proxy.RuntimeIdentity{Version: "1.9.1", Mode: mode}}
		err := reportReusableServe(&output, observed)
		if (err == nil) != (mode == "enforce") {
			t.Fatalf("mode=%s error=%v", mode, err)
		}
		if !strings.Contains(output.String(), "1.9.1") || !strings.Contains(output.String(), mode) || !strings.Contains(output.String(), "ownership unproven") || strings.Contains(output.String(), canary) {
			t.Fatalf("reuse output: %s", output.String())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != canary {
		t.Fatal("reuse modified the existing token")
	}
}
