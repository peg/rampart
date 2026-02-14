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
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/signing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleResolve_AllowsUnsignedWhenSignerNotConfigured(t *testing.T) {
	store := approval.NewStore()
	t.Cleanup(store.Close)

	pending := store.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	api := NewAPI(store, "", slog.Default(), nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+pending.ID+"/resolve", bytes.NewBufferString(`{"approved":true,"resolved_by":"test"}`))
	req.SetPathValue("id", pending.ID)
	w := httptest.NewRecorder()

	api.handleResolve(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleResolve_RejectsInvalidSignature(t *testing.T) {
	store := approval.NewStore()
	t.Cleanup(store.Close)

	pending := store.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	signer := signing.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	api := NewAPI(store, "", slog.Default(), signer)

	exp := time.Now().Add(5 * time.Minute).Unix()
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+pending.ID+"/resolve?sig=bad&exp="+strconv.FormatInt(exp, 10), bytes.NewBufferString(`{"approved":true,"resolved_by":"test"}`))
	req.SetPathValue("id", pending.ID)
	w := httptest.NewRecorder()

	api.handleResolve(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleResolve_AllowsValidSignature(t *testing.T) {
	store := approval.NewStore()
	t.Cleanup(store.Close)

	pending := store.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	signer := signing.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	api := NewAPI(store, "", slog.Default(), signer)

	expiresAt := time.Now().Add(5 * time.Minute).UTC()
	signedURL := signer.SignURL("http://localhost:9091", pending.ID, expiresAt)
	signedReq, err := http.NewRequest(http.MethodPost, signedURL, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+pending.ID+"/resolve?"+signedReq.URL.RawQuery, bytes.NewBufferString(`{"approved":true,"resolved_by":"test"}`))
	req.SetPathValue("id", pending.ID)
	w := httptest.NewRecorder()

	api.handleResolve(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, pending.ID, resp["id"])
}

func TestHandleResolve_RejectsExpiredSignature(t *testing.T) {
	store := approval.NewStore()
	t.Cleanup(store.Close)

	pending := store.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	signer := signing.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	api := NewAPI(store, "", slog.Default(), signer)

	expiresAt := time.Now().Add(-1 * time.Minute).UTC()
	signedURL := signer.SignURL("http://localhost:9091", pending.ID, expiresAt)
	signedReq, err := http.NewRequest(http.MethodPost, signedURL, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+pending.ID+"/resolve?"+signedReq.URL.RawQuery, bytes.NewBufferString(`{"approved":true,"resolved_by":"test"}`))
	req.SetPathValue("id", pending.ID)
	w := httptest.NewRecorder()

	api.handleResolve(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
