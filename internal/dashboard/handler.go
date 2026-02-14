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
	"io/fs"
	"net/http"
)

// Handler serves the embedded dashboard static files.
// Handler returns an HTTP handler that serves the embedded approval dashboard.
//
// Security model: The dashboard UI itself is served without authentication.
// It displays pending approval requests (tool name, command, agent, timestamps).
// All mutating actions (approve/deny) require a Bearer token, which the user
// enters in the dashboard's token field and is stored in localStorage.
//
// If you need to restrict read access to the dashboard, place it behind a
// reverse proxy with authentication, or bind the listen address to localhost.
func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("dashboard: failed to build embedded fs")
	}
	return securityHeaders(http.FileServer(http.FS(sub)))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; connect-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
