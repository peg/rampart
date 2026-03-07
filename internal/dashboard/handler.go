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
	"crypto/rand"
	"encoding/base64"
	"io/fs"
	"net/http"
	"strings"
)

// Handler serves the embedded dashboard static files.
// Handler returns an HTTP handler that serves the embedded approval dashboard.
//
// Security model: The dashboard UI (HTML/CSS/JS) itself is served without
// authentication and does not embed secrets. Sensitive approval data is fetched
// at runtime from /v1 APIs.
//
// Read and mutating API actions require a Bearer token, which the user enters
// in the dashboard token field and is stored in localStorage.
//
// If you need to restrict read access to the dashboard, place it behind a
// reverse proxy with authentication, or bind the listen address to localhost.
// indexHTML holds the raw dashboard HTML, loaded once at init.
// On each request we inject a fresh nonce into <script> and <style> tags.
var indexHTML string

func init() {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		panic("dashboard: failed to read embedded index.html")
	}
	indexHTML = string(data)
}

func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("dashboard: failed to build embedded fs")
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For the root/index path, serve nonce-injected HTML.
		if r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "" {
			serveIndexWithNonce(w, r)
			return
		}
		// All other static assets served normally with security headers.
		securityHeadersStatic(w)
		fileServer.ServeHTTP(w, r)
	})
}

func serveIndexWithNonce(w http.ResponseWriter, _ *http.Request) {
	nonce := generateNonce()

	// Inject nonce into inline <script> and <style> tags.
	html := strings.ReplaceAll(indexHTML, "<script>", `<script nonce="`+nonce+`">`)
	html = strings.ReplaceAll(html, "<style>", `<style nonce="`+nonce+`">`)

	csp := "default-src 'self'; " +
		"script-src 'nonce-" + nonce + "' 'self'; " +
		"style-src 'nonce-" + nonce + "' 'self' https://fonts.googleapis.com; " +
		"font-src https://fonts.gstatic.com; " +
		"connect-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'"

	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func securityHeadersStatic(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: this should never happen, but don't panic in a request handler.
		return "fallback-nonce"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
