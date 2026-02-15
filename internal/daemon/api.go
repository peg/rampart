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

package daemon

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/dashboard"
	"github.com/peg/rampart/internal/signing"
)

// API serves HTTP endpoints for the daemon's approval management.
type API struct {
	approvals *approval.Store
	token     string
	logger    *slog.Logger
	signer    *signing.Signer
}

// NewAPI creates a new daemon API handler.
// If token is non-empty, all endpoints require Bearer auth.
func NewAPI(approvals *approval.Store, token string, logger *slog.Logger, signer *signing.Signer) *API {
	return &API{approvals: approvals, token: token, logger: logger, signer: signer}
}

// Handler returns the HTTP handler for the daemon API.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/approvals", a.handleList)
	mux.HandleFunc("POST /v1/approvals/{id}/resolve", a.handleResolve)
	mux.Handle("/", dashboard.Handler())
	return http.MaxBytesHandler(mux, 1<<20) // 1MB limit
}

func (a *API) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if a.token == "" {
		return true // No auth configured.
	}
	auth := r.Header.Get("Authorization")
	expected := "Bearer " + a.token
	if auth == "" || subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	return true
}

func (a *API) handleList(w http.ResponseWriter, r *http.Request) {
	if !a.checkAuth(w, r) {
		return
	}
	pending := a.approvals.List()
	items := make([]map[string]any, 0, len(pending))

	for _, req := range pending {
		items = append(items, map[string]any{
			"id":         req.ID,
			"tool":       req.Call.Tool,
			"command":    req.Call.Command(),
			"agent":      req.Call.Agent,
			"session":    req.Call.Session,
			"message":    req.Decision.Message,
			"status":     req.Status.String(),
			"created_at": req.CreatedAt.Format(time.RFC3339),
			"expires_at": req.ExpiresAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"approvals": items})
}

type resolveReq struct {
	Approved   bool   `json:"approved"`
	ResolvedBy string `json:"resolved_by"`
}

func (a *API) handleResolve(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Allow access via either Bearer token or valid HMAC signature.
	if a.signer != nil {
		sig := r.URL.Query().Get("sig")
		expRaw := r.URL.Query().Get("exp")
		if sig != "" && expRaw != "" {
			exp, err := strconv.ParseInt(expRaw, 10, 64)
			if err != nil || !a.signer.ValidateSignature(id, sig, exp) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired signature"})
				return
			}
			// Signature valid — skip Bearer auth.
			goto authorized
		}
	}
	if !a.checkAuth(w, r) {
		return
	}
authorized:

	var req resolveReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid body: %v", err),
		})
		return
	}

	if req.ResolvedBy == "" {
		req.ResolvedBy = "api"
	}

	if err := a.approvals.Resolve(id, req.Approved, req.ResolvedBy); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	a.logger.Info("daemon-api: approval resolved",
		"id", id,
		"approved", req.Approved,
		"resolved_by", req.ResolvedBy,
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"approved": req.Approved,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
