// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/token"
)

func TestExtractBearerTokenRestrictsQueryAuthenticationToSSE(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		header string
		want   string
	}{
		{name: "header on API", method: http.MethodPost, path: "/v1/tool/exec?token=query", header: "Bearer header", want: "header"},
		{name: "query rejected on API", method: http.MethodGet, path: "/v1/approvals?token=query", want: ""},
		{name: "query accepted on SSE", method: http.MethodGet, path: "/v1/events/stream?token=query", want: "query"},
		{name: "query accepted on SSE probe", method: http.MethodHead, path: "/v1/events/stream?token=query", want: "query"},
		{name: "query rejected for SSE mutation", method: http.MethodPost, path: "/v1/events/stream?token=query", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			if got := extractBearerToken(req); got != tt.want {
				t.Fatalf("extractBearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMetricsRequireAdminScope(t *testing.T) {
	store, err := token.NewStore(filepath.Join(t.TempDir(), "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	agentToken, _, err := store.Create("codex", "", "", []string{token.ScopeEval}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(nil, nil, WithToken("admin-token"), WithTokenStore(store), WithMetrics(true))
	handler := srv.handler()

	for _, tt := range []struct {
		name   string
		token  string
		status int
	}{
		{name: "missing", status: http.StatusUnauthorized},
		{name: "agent scoped", token: agentToken, status: http.StatusForbidden},
		{name: "admin", token: "admin-token", status: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.status {
				t.Fatalf("status = %d, want %d", rr.Code, tt.status)
			}
		})
	}
}

func TestEvaluationEndpointsRequireEvalScope(t *testing.T) {
	store, err := token.NewStore(filepath.Join(t.TempDir(), "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	evalToken, _, err := store.Create("eval-agent", "", "", []string{token.ScopeEval}, nil)
	if err != nil {
		t.Fatal(err)
	}
	adminOnlyToken, _, err := store.Create("admin-agent", "", "", []string{token.ScopeAdmin}, nil)
	if err != nil {
		t.Fatal(err)
	}
	combinedToken, _, err := store.Create("combined-agent", "", "", []string{token.ScopeEval, token.ScopeAdmin}, nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := New(nil, nil, WithToken("admin-token"), WithTokenStore(store), WithMode("disabled"))
	t.Cleanup(srv.approvals.Close)
	handler := srv.handler()

	for _, endpoint := range []string{"/v1/tool/exec", "/v1/preflight/exec"} {
		for _, test := range []struct {
			name   string
			bearer string
			status int
		}{
			{name: "eval token", bearer: evalToken, status: http.StatusOK},
			{name: "local admin", bearer: "admin-token", status: http.StatusOK},
			{name: "admin-only agent token", bearer: adminOnlyToken, status: http.StatusForbidden},
			{name: "combined token", bearer: combinedToken, status: http.StatusOK},
			{name: "invalid token", bearer: "invalid-token", status: http.StatusUnauthorized},
			{name: "missing token", status: http.StatusUnauthorized},
		} {
			t.Run(endpoint+"/"+test.name, func(t *testing.T) {
				body := `{"agent":"untrusted","session":"scope-test","params":{"command":"true"}}`
				req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
				if test.bearer != "" {
					req.Header.Set("Authorization", "Bearer "+test.bearer)
				}
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				if rr.Code != test.status {
					t.Fatalf("status = %d, want %d; body = %s", rr.Code, test.status, rr.Body.String())
				}
			})
		}
	}
}

func TestDecodeJSONBodyRejectsAdditionalValues(t *testing.T) {
	for _, tt := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "single value", body: `{"value":1}`},
		{name: "trailing whitespace", body: "{\"value\":1}\n\t"},
		{name: "second object", body: `{"value":1}{"value":2}`, wantErr: true},
		{name: "trailing garbage", body: `{"value":1}garbage`, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var value map[string]any
			err := decodeJSONBody(strings.NewReader(tt.body), &value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeJSONBody() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
