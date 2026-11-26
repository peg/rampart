// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/notify"
)

// The signed resolve URL in approval notifications is opened by people from
// chat and mail clients, which issue GET requests and frequently prefetch or
// unfurl links. GET therefore only renders a confirmation page; the decision
// is a separate form POST to the same signed path.

//go:embed approvalpage/page.html approvalpage/page.css
var approvalPageFS embed.FS

var (
	approvalPageTemplate = template.Must(template.ParseFS(approvalPageFS, "approvalpage/page.html"))
	approvalPageCSS      = mustReadApprovalPageFile("approvalpage/page.css")
	approvalPageCSP      = "default-src 'none'; style-src '" + cspHash(approvalPageCSS) + "'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)

func mustReadApprovalPageFile(name string) string {
	data, err := approvalPageFS.ReadFile(name)
	if err != nil {
		panic("proxy: missing embedded approval page asset " + name)
	}
	return string(data)
}

func cspHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

type approvalPageView struct {
	CSS     template.CSS
	Heading string
	Detail  string
	Pending bool
	Tool    string
	MCPTool string
	Command string
	Agent   string
	Message string
	Expires string
	Review  string
	Action  string
}

const approvalLinkUnavailable = "This approval link is invalid, has expired, or is no longer available."

// validSignedApprovalLink reports whether the request carries a valid,
// unexpired signature for id. It never consults the approval store, so an
// unsigned caller learns nothing about which approval IDs exist.
func (s *Server) validSignedApprovalLink(r *http.Request, id string) (int64, string, bool) {
	if s.signer == nil {
		return 0, "", false
	}
	sig := r.URL.Query().Get("sig")
	exp, err := strconv.ParseInt(r.URL.Query().Get("exp"), 10, 64)
	if sig == "" || err != nil || !s.signer.ValidateSignature(id, sig, exp) {
		return 0, "", false
	}
	return exp, sig, true
}

// handleApprovalLinkPage renders the confirmation page for a signed approval
// link. It must never change approval state.
func (s *Server) handleApprovalLinkPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	exp, sig, ok := s.validSignedApprovalLink(r, id)
	if !ok {
		writeApprovalPage(w, http.StatusForbidden, approvalPageView{Heading: "Link unavailable", Detail: approvalLinkUnavailable})
		return
	}
	req, found := s.approvals.Get(id)
	if !found {
		writeApprovalPage(w, http.StatusNotFound, approvalPageView{Heading: "Link unavailable", Detail: approvalLinkUnavailable})
		return
	}
	if req.Status != approval.StatusPending || !time.Now().Before(req.ExpiresAt) {
		writeApprovalPage(w, http.StatusGone, approvalTerminalView(req.Status))
		return
	}

	review := approval.ReviewCall(req.Call)
	summary := approval.SummarizeCall(req.Call)
	action := "resolve?" + url.Values{"sig": {sig}, "exp": {strconv.FormatInt(exp, 10)}}.Encode()
	writeApprovalPage(w, http.StatusOK, approvalPageView{
		Heading: "Approval requested",
		Pending: true,
		Tool:    review.Tool,
		MCPTool: summary.MCPTool,
		Command: summary.Target,
		Agent:   review.Agent,
		Message: notify.SanitizeCommand(req.Decision.Message),
		Expires: req.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		Review:  review.DisplayText,
		Action:  action,
	})
}

func approvalTerminalView(status approval.Status) approvalPageView {
	switch status {
	case approval.StatusApproved:
		return approvalPageView{Heading: "Already approved", Detail: "This request was already approved. The link cannot be reused."}
	case approval.StatusDenied:
		return approvalPageView{Heading: "Already denied", Detail: "This request was already denied. The link cannot be reused."}
	default:
		return approvalPageView{Heading: "Request expired", Detail: "This request expired before a decision was made."}
	}
}

func writeApprovalPage(w http.ResponseWriter, status int, view approvalPageView) {
	view.CSS = template.CSS(approvalPageCSS)
	var buf bytes.Buffer
	if err := approvalPageTemplate.Execute(&buf, view); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render approval page")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", approvalPageCSP)
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// isApprovalFormPost reports whether a resolve POST came from the approval
// page form rather than a JSON API client.
func isApprovalFormPost(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/x-www-form-urlencoded"
}

// decodeApprovalForm accepts exactly one field, decision=approve|deny. Any
// other field, including persist, is rejected so the form cannot request
// anything the signed link is not entitled to.
func decodeApprovalForm(r *http.Request) (bool, error) {
	if err := r.ParseForm(); err != nil {
		return false, err
	}
	if len(r.PostForm) != 1 || len(r.PostForm["decision"]) != 1 {
		return false, errors.New("form must contain exactly one decision")
	}
	switch r.PostForm.Get("decision") {
	case "approve":
		return true, nil
	case "deny":
		return false, nil
	default:
		return false, errors.New("decision must be approve or deny")
	}
}
