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

package proxy

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/peg/rampart/internal/token"
)

// authIdentity represents the authenticated caller's identity.
type authIdentity struct {
	// IsAdmin is true if the caller used the admin bearer token.
	IsAdmin bool

	// Agent is the agent name from a per-agent token, or empty for admin.
	Agent string

	// Policy is the policy profile bound to the token, or empty for global.
	Policy string

	// Token is the matched per-agent token, or nil for admin auth.
	Token *token.Token
}

// HasScope returns true if the identity has the given scope.
// Admin identities have all scopes.
func (a authIdentity) HasScope(scope string) bool {
	if a.IsAdmin {
		return true
	}
	if a.Token != nil {
		return a.Token.HasScope(scope)
	}
	return false
}

// extractBearerToken extracts the bearer token from the Authorization header
// or the "token" query parameter.
func extractBearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth != "" {
		tok := strings.TrimPrefix(auth, "Bearer ")
		if tok != auth {
			return tok
		}
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

// identify resolves a request to an authIdentity.
// It checks the admin token first, then per-agent tokens.
// Returns nil if no valid auth is found.
func (s *Server) identify(r *http.Request) *authIdentity {
	bearer := extractBearerToken(r)
	if bearer == "" {
		return nil
	}

	// Check admin token first (constant time).
	if s.token != "" && subtle.ConstantTimeCompare([]byte(bearer), []byte(s.token)) == 1 {
		return &authIdentity{IsAdmin: true}
	}

	// Check per-agent tokens.
	if s.tokenStore != nil {
		if tok, ok := s.tokenStore.Lookup(bearer); ok {
			return &authIdentity{
				Agent:  tok.Agent,
				Policy: tok.Policy,
				Token:  &tok,
			}
		}
	}

	return nil
}

// checkAuthIdentity validates auth and returns the identity. Writes 401 on failure.
func (s *Server) checkAuthIdentity(w http.ResponseWriter, r *http.Request) *authIdentity {
	id := s.identify(r)
	if id == nil {
		writeError(w, http.StatusUnauthorized, "invalid or missing authorization token")
		return nil
	}
	return id
}

// checkAdminAuth validates auth and requires admin scope. Writes 401/403 on failure.
func (s *Server) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	id := s.identify(r)
	if id == nil {
		writeError(w, http.StatusUnauthorized, "invalid or missing authorization token")
		return false
	}
	if !id.HasScope(token.ScopeAdmin) {
		writeError(w, http.StatusForbidden, "this endpoint requires admin scope — agent tokens cannot perform mutations")
		return false
	}
	return true
}
