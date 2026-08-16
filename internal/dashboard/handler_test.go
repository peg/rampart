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

package dashboard

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestHandlerServesIndex(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Rampart Dashboard") {
		t.Fatalf("response does not contain dashboard title")
	}
}

func TestHandlerSetsSecurityHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	assertHeader := func(key, want string) {
		t.Helper()
		if got := rr.Header().Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}

	assertHeader("X-Frame-Options", "DENY")
	assertHeader("X-Content-Type-Options", "nosniff")
	assertHeader("Referrer-Policy", "no-referrer")
	assertHeader("Cache-Control", "no-store")

	// CSP should use nonce-based policy (no unsafe-inline).
	csp := rr.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP should use nonce, not unsafe-inline: %s", csp)
	}
	if !strings.Contains(csp, "nonce-") {
		t.Fatalf("CSP should contain nonce: %s", csp)
	}
	if !strings.Contains(csp, "object-src 'none'") {
		t.Fatalf("CSP should contain object-src 'none': %s", csp)
	}
	if !strings.Contains(csp, "base-uri 'self'") {
		t.Fatalf("CSP should contain base-uri 'self': %s", csp)
	}
}

func TestHandlerNonceUnique(t *testing.T) {
	// Two requests should get different nonces.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	rr1 := httptest.NewRecorder()
	Handler().ServeHTTP(rr1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rr2 := httptest.NewRecorder()
	Handler().ServeHTTP(rr2, req2)

	csp1 := rr1.Header().Get("Content-Security-Policy")
	csp2 := rr2.Header().Get("Content-Security-Policy")
	if csp1 == csp2 {
		t.Fatalf("two requests should get different nonces, both got: %s", csp1)
	}
}

func TestHandlerNonceInHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, `<script nonce="`) {
		t.Fatal("HTML should contain script tags with nonce attribute")
	}
	if !strings.Contains(body, `<style nonce="`) {
		t.Fatal("HTML should contain style tags with nonce attribute")
	}
}

func TestHandlerHasNoCSPBlockedInlineAttributes(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, req)

	// A nonce authorizes the style and script elements, but it does not
	// authorize style attributes or inline event handlers. Keep those out of
	// both the static markup and dynamically rendered HTML templates.
	inlineAttribute := regexp.MustCompile(`(?i)\s(?:style|on[a-z][a-z0-9_-]*)\s*=`)
	if match := inlineAttribute.FindString(rr.Body.String()); match != "" {
		t.Fatalf("dashboard contains CSP-blocked inline attribute %q", match)
	}
}

func TestHandlerIncludesAuthUXForApprovalsAPI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "API token") {
		t.Fatalf("response does not include token input prompt")
	}
	if !strings.Contains(body, "rampart serve") {
		t.Fatalf("response does not include serve guidance message")
	}
}

func TestHandlerSeparatesPendingApprovalFromFutureRunAuthority(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	body := rr.Body.String()
	for _, want := range []string{
		"Approve Pending",
		"Allow Future",
		"Approve Selected",
		"Future calls will still require approval.",
		`aria-expanded="true"`,
		"Admin scope required",
		"Invalid or expired token",
		"function handleAuthFailure(status)",
		"function resetProtectedState()",
		"function assertAuthEpoch(epoch)",
		"handleAPIControlError",
		"assertAuthEpoch(requestEpoch)",
		"const generation=++pollGeneration",
		"if(generation!==pollGeneration)return",
		"const operationEpoch=authEpoch",
		"if(operationEpoch===authEpoch)",
		"policyTestButton.disabled=false",
		"clearTimeout(denialRefreshTimer)",
		"if(connected&&requestEpoch===authEpoch)loadRecentDenials()",
		"if(streamEpoch!==authEpoch)return",
		"if(handleAuthFailure(r.status))return",
		"switchTab('active')",
		"document.getElementById('main-content').classList.remove('visible')",
		"Approvals changed",
		"action,scope,ids,resolved_by:'dashboard'",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response does not contain explicit approval-scope UX %q", want)
		}
	}
	if strings.Contains(body, "__auth__") || strings.Contains(body, "__admin__") {
		t.Fatal("response exposes internal authentication sentinels")
	}
}

func TestHandlerIncludesDashboardRuntimeSafetyContracts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, req)
	body := rr.Body.String()

	for _, want := range []string{
		"async function bulkAction(action)",
		"if(operationEpoch!==authEpoch)return",
		"document.getElementById('decision-bar').innerHTML=''",
		"document.getElementById('heatmap-bars').innerHTML=''",
		"document.getElementById('rules-empty').style.display='block'",
		"reloadHint.textContent='';reloadHint.classList.remove('visible')",
		`document.querySelector('.tab-btn[data-tab="history"]')`,
		"api('/v1/status')",
		"data-rule-name=",
		"encodeURIComponent(ruleName)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response does not contain dashboard runtime contract %q", want)
		}
	}
	if strings.Contains(body, "api('/v1/policy')") {
		t.Fatal("policy card calls removed /v1/policy route instead of /v1/status")
	}
}
