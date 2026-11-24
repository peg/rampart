// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/signing"
)

const approvalLinkTestKey = "0123456789abcdef0123456789abcdef"

func newApprovalLinkServer(t *testing.T) (*Server, *signing.Signer, *mockSink) {
	t.Helper()
	signer := signing.NewSigner([]byte(approvalLinkTestKey))
	sink := &mockSink{}
	srv := New(buildApprovalEngine(t), sink, WithToken("secret-token"), WithMode("enforce"), WithSigner(signer))
	return srv, signer, sink
}

func signedResolvePath(t *testing.T, signer *signing.Signer, req *approval.Request) string {
	t.Helper()
	parsed, err := url.Parse(signer.SignURL("http://localhost", req.ID, req.ExpiresAt.UTC()))
	require.NoError(t, err)
	return parsed.RequestURI()
}

func serve(srv *Server, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	return rr
}

func postApprovalForm(srv *Server, path, form string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return serve(srv, req)
}

func assertApprovalPageHeaders(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	h := rr.Header()
	assert.Equal(t, "text/html; charset=utf-8", h.Get("Content-Type"))
	assert.Equal(t, "no-store", h.Get("Cache-Control"))
	assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	csp := h.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'none'", "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'", "style-src 'sha256-"} {
		assert.Contains(t, csp, directive)
	}
	assert.NotContains(t, csp, "script-src")
	assert.NotContains(t, rr.Body.String(), "<script")
	// The style hash must cover the exact rendered bytes or browsers drop it.
	body := rr.Body.String()
	start, end := strings.Index(body, "<style>"), strings.Index(body, "</style>")
	if assert.True(t, start >= 0 && end > start, "page has one inline style") {
		assert.Contains(t, csp, "'"+cspHash(body[start+len("<style>"):end])+"'")
	}
}

func TestApprovalLinkGET_RendersPageWithoutResolving(t *testing.T) {
	srv, signer, sink := newApprovalLinkServer(t)
	pending, err := srv.approvals.Create(engine.ToolCall{
		Tool:   "exec",
		Agent:  `<img src=x onerror=alert(1)>`,
		Params: map[string]any{"command": `echo "</code><script>alert(1)</script>" token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`},
	}, engine.Decision{Message: `<b>bold</b>`})
	require.NoError(t, err)
	path := signedResolvePath(t, signer, pending)

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rr := serve(srv, httptest.NewRequest(method, path, nil))
		require.Equal(t, http.StatusOK, rr.Code, method)
		assertApprovalPageHeaders(t, rr)
	}

	rr := serve(srv, httptest.NewRequest(http.MethodGet, path, nil))
	body := rr.Body.String()
	assert.Contains(t, body, `name="decision" value="approve"`)
	assert.Contains(t, body, `name="decision" value="deny"`)
	assert.Contains(t, body, `method="post"`)
	assert.Contains(t, body, `action="resolve?exp=`)
	assert.Contains(t, body, `name="viewport"`)
	// Agent-controlled strings are escaped, never rendered as markup.
	assert.NotContains(t, body, "<img")
	assert.NotContains(t, body, "<script>alert")
	assert.NotContains(t, body, "<b>bold</b>")
	assert.Contains(t, body, "&lt;img src=x onerror=alert(1)&gt;")
	// Credential material goes through the approval-store redaction.
	assert.NotContains(t, body, "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	unchanged, ok := srv.approvals.Get(pending.ID)
	require.True(t, ok)
	assert.Equal(t, approval.StatusPending, unchanged.Status, "GET must never resolve an approval")
	assert.Empty(t, sink.snapshot(), "GET must not write an approval resolution audit event")
}

func TestApprovalLinkGET_NamesMCPTool(t *testing.T) {
	srv, signer, _ := newApprovalLinkServer(t)
	pending, err := srv.approvals.Create(engine.ToolCall{
		Tool:   "mcp",
		Params: map[string]any{"mcp_method": "tools/call", "mcp_tool": `delete_repo<script>`},
	}, engine.Decision{})
	require.NoError(t, err)

	body := serve(srv, httptest.NewRequest(http.MethodGet, signedResolvePath(t, signer, pending), nil)).Body.String()
	assert.Contains(t, body, "<dt>MCP tool</dt><dd><code>delete_repo&lt;script&gt;</code></dd>")

	plain, err := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	require.NoError(t, err)
	body = serve(srv, httptest.NewRequest(http.MethodGet, signedResolvePath(t, signer, plain), nil)).Body.String()
	assert.NotContains(t, body, "MCP tool")
}

func TestApprovalLinkGET_InvalidLinksLeakNothing(t *testing.T) {
	srv, signer, _ := newApprovalLinkServer(t)
	pending, err := srv.approvals.Create(engine.ToolCall{Tool: "exec", Agent: "secret-agent-name"}, engine.Decision{})
	require.NoError(t, err)
	unknownPath := signer.SignURL("", "01UNKNOWNAPPROVALID0000000", time.Now().Add(time.Hour))
	expiredPath := signer.SignURL("", pending.ID, time.Now().Add(-time.Minute))

	cases := map[string]struct {
		srv    *Server
		path   string
		status int
	}{
		"forged":         {srv, fmt.Sprintf("/v1/approvals/%s/resolve?sig=forged&exp=9999999999", pending.ID), http.StatusForbidden},
		"missing":        {srv, fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID), http.StatusForbidden},
		"bad exp":        {srv, fmt.Sprintf("/v1/approvals/%s/resolve?sig=x&exp=soon", pending.ID), http.StatusForbidden},
		"expired":        {srv, expiredPath, http.StatusForbidden},
		"forged unknown": {srv, "/v1/approvals/01UNKNOWNAPPROVALID0000000/resolve?sig=forged&exp=9999999999", http.StatusForbidden},
		"signed unknown": {srv, unknownPath, http.StatusNotFound},
		"no signer": {
			New(buildApprovalEngine(t), nil, WithToken("secret-token"), WithMode("enforce")),
			signedResolvePath(t, signer, pending), http.StatusForbidden,
		},
	}
	var genericBody string
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rr := serve(tc.srv, httptest.NewRequest(http.MethodGet, tc.path, nil))
			assert.Equal(t, tc.status, rr.Code)
			assertApprovalPageHeaders(t, rr)
			body := rr.Body.String()
			assert.NotContains(t, body, "secret-agent-name")
			assert.NotContains(t, body, pending.ID)
			assert.NotContains(t, body, "<form")
			if genericBody == "" {
				genericBody = body
			}
			assert.Equal(t, genericBody, body, "every unusable link renders the same generic page")
		})
	}
	unchanged, _ := srv.approvals.Get(pending.ID)
	assert.Equal(t, approval.StatusPending, unchanged.Status)
}

func TestApprovalLinkFormPOST_ResolvesOnceAsSignedLink(t *testing.T) {
	for _, tc := range []struct {
		decision string
		status   approval.Status
		heading  string
	}{
		{"approve", approval.StatusApproved, "Approved"},
		{"deny", approval.StatusDenied, "Denied"},
	} {
		t.Run(tc.decision, func(t *testing.T) {
			srv, signer, sink := newApprovalLinkServer(t)
			pending, err := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
			require.NoError(t, err)
			path := signedResolvePath(t, signer, pending)

			rr := postApprovalForm(srv, path, "decision="+tc.decision)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assertApprovalPageHeaders(t, rr)
			assert.Contains(t, rr.Body.String(), "<h1>"+tc.heading+"</h1>")

			resolved, ok := srv.approvals.Get(pending.ID)
			require.True(t, ok)
			assert.Equal(t, tc.status, resolved.Status)
			assert.Equal(t, "signed-link", resolved.ResolvedBy)
			assert.False(t, resolved.Persisted)
			events := sink.snapshot()
			require.Len(t, events, 1)
			assert.Equal(t, "signed-link", events[0].Request["resolved_by"])

			// Reuse returns the terminal already-resolved page, for both the
			// form and a later tap on the link.
			again := postApprovalForm(srv, path, "decision=approve")
			assert.Equal(t, http.StatusGone, again.Code)
			assert.Contains(t, again.Body.String(), "Already")
			tap := serve(srv, httptest.NewRequest(http.MethodGet, path, nil))
			assert.Equal(t, http.StatusGone, tap.Code)
			assert.NotContains(t, tap.Body.String(), "<form")
			final, _ := srv.approvals.Get(pending.ID)
			assert.Equal(t, tc.status, final.Status, "second use must not change the decision")
			assert.Len(t, sink.snapshot(), 1)
		})
	}
}

func TestApprovalLinkFormPOST_RejectsExtraFieldsAndBadSignature(t *testing.T) {
	srv, signer, sink := newApprovalLinkServer(t)
	pending, err := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	require.NoError(t, err)
	path := signedResolvePath(t, signer, pending)

	for _, form := range []string{
		"decision=approve&persist=true",
		"decision=approve&resolved_by=admin",
		"decision=approve&decision=deny",
		"decision=yes",
		"",
	} {
		rr := postApprovalForm(srv, path, form)
		assert.Equal(t, http.StatusBadRequest, rr.Code, form)
		assertApprovalPageHeaders(t, rr)
	}
	// persist in the query string is not a form field either.
	rr := postApprovalForm(srv, path+"&persist=true", "decision=approve")
	require.Equal(t, http.StatusOK, rr.Code)
	resolved, _ := srv.approvals.Get(pending.ID)
	assert.False(t, resolved.Persisted)

	other, err := srv.approvals.Create(engine.ToolCall{Tool: "exec", Params: map[string]any{"command": "other"}}, engine.Decision{})
	require.NoError(t, err)
	forged := postApprovalForm(srv, fmt.Sprintf("/v1/approvals/%s/resolve?sig=forged&exp=9999999999", other.ID), "decision=approve")
	assert.Equal(t, http.StatusUnauthorized, forged.Code)
	assert.NotContains(t, forged.Body.String(), other.ID)
	// A valid signature for one approval cannot resolve another.
	crossSigned := strings.Replace(path, pending.ID, other.ID, 1)
	cross := postApprovalForm(srv, crossSigned, "decision=approve")
	assert.Equal(t, http.StatusUnauthorized, cross.Code)
	still, _ := srv.approvals.Get(other.ID)
	assert.Equal(t, approval.StatusPending, still.Status)
	assert.Len(t, sink.snapshot(), 1)
}

func TestApprovalLinkFormPOST_RequiresSignature(t *testing.T) {
	srv, _, _ := newApprovalLinkServer(t)
	pending, err := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	require.NoError(t, err)
	path := fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID)

	// An unsigned cross-site form post has no bearer header and is rejected
	// exactly as before.
	rr := postApprovalForm(srv, path, "decision=approve")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Bearer-authenticated callers still need a JSON body; the form decoder is
	// only reachable through a valid signature.
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("decision=approve"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer secret-token")
	bearer := serve(srv, req)
	assert.Equal(t, http.StatusBadRequest, bearer.Code)
	assert.Equal(t, "application/json", bearer.Header().Get("Content-Type"))
	still, _ := srv.approvals.Get(pending.ID)
	assert.Equal(t, approval.StatusPending, still.Status)
}

func TestApprovalLinkJSONAPIUnchanged(t *testing.T) {
	srv, signer, _ := newApprovalLinkServer(t)
	pending, err := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	require.NoError(t, err)
	path := signedResolvePath(t, signer, pending)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return serve(srv, req)
	}
	persist := post(`{"approved":true,"persist":true}`)
	assert.Equal(t, http.StatusForbidden, persist.Code)
	assert.Equal(t, `{"error":"persist=true requires admin token authentication, not a signed approval URL"}`+"\n", persist.Body.String())

	ok := post(`{"approved":true}`)
	assert.Equal(t, http.StatusOK, ok.Code)
	assert.Equal(t, "application/json", ok.Header().Get("Content-Type"))
	assert.Equal(t, fmt.Sprintf(`{"approved":true,"id":%q,"persisted":false,"status":"approved"}`+"\n", pending.ID), ok.Body.String())

	gone := post(`{"approved":true}`)
	assert.Equal(t, http.StatusGone, gone.Code)
	assert.Equal(t, `{"error":"approval already resolved; URL cannot be reused"}`+"\n", gone.Body.String())

	forgedReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/approvals/%s/resolve?sig=forged&exp=9999999999", pending.ID), strings.NewReader(`{"approved":true}`))
	forgedReq.Header.Set("Content-Type", "application/json")
	forged := serve(srv, forgedReq)
	assert.Equal(t, http.StatusUnauthorized, forged.Code)
	assert.Equal(t, `{"error":"invalid or expired signature"}`+"\n", forged.Body.String())
}
