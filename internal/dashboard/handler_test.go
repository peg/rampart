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
	assertHeader("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; connect-src 'self'")
	assertHeader("Referrer-Policy", "no-referrer")
	assertHeader("Cache-Control", "no-store")
}

func TestHandlerIncludesAuthUXForApprovalsAPI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Bearer token for /v1 API") {
		t.Fatalf("response does not include token input prompt")
	}
	if !strings.Contains(body, "unauthorized (set token)") {
		t.Fatalf("response does not include unauthorized guidance message")
	}
}
