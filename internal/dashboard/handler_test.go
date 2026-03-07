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
