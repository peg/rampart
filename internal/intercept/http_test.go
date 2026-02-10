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

package intercept

import (
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
)

func TestHTTPInterceptor_EvaluateFetch(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		url    string
		want   engine.Action
	}{
		{
			name: "blocked domain denied",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-evil
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          domain_matches: ["*.evil.com"]
        message: "Blocked domain"
`,
			url:  "https://malware.evil.com/payload",
			want: engine.ActionDeny,
		},
		{
			name: "allowed domain passes",
			policy: `
version: "1"
default_action: deny
policies:
  - name: allow-github
    match:
      tool: fetch
    rules:
      - action: allow
        when:
          domain_matches: ["*.github.com"]
`,
			url:  "https://api.github.com/repos",
			want: engine.ActionAllow,
		},
		{
			name: "exfil domain denied — ngrok",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-exfil
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          domain_matches:
            - "*.ngrok.io"
            - "*.ngrok-free.app"
            - "*.requestbin.com"
            - "*.webhook.site"
`,
			url:  "https://abc123.ngrok-free.app/exfil",
			want: engine.ActionDeny,
		},
		{
			name: "URL pattern matching with double glob",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-url
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          url_matches: ["**pastebin.com**"]
`,
			url:  "https://pastebin.com/raw/abc123",
			want: engine.ActionDeny,
		},
		{
			name: "domain glob .ru blocked",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-ru
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          domain_matches: ["*.ru"]
`,
			url:  "https://sketchy.ru/data",
			want: engine.ActionDeny,
		},
		{
			name: "localhost allowed with default allow",
			policy: `
version: "1"
default_action: allow
policies: []
`,
			url:  "http://localhost:3000/api",
			want: engine.ActionAllow,
		},
		{
			name: "invalid URL does not crash",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-evil
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          domain_matches: ["*.evil.com"]
`,
			url:  "not-a-valid-url",
			want: engine.ActionAllow,
		},
		{
			name: "default deny no matching rule",
			policy: `
version: "1"
default_action: deny
policies: []
`,
			url:  "https://example.com",
			want: engine.ActionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := setupHTTPInterceptor(t, tt.policy)
			got := interceptor.EvaluateFetch("main", "s1", tt.url)
			assert.Equal(t, tt.want, got.Action, "url: %s", tt.url)
		})
	}
}

func TestHTTPInterceptor_URLMetadata(t *testing.T) {
	interceptor := &HTTPInterceptor{}
	call := interceptor.toolCall("main", "s1", "https://api.github.com:443/repos/test")

	assert.Equal(t, "api.github.com", call.Params["domain"])
	assert.Equal(t, "https", call.Params["scheme"])
	assert.Equal(t, "/repos/test", call.Params["path"])
	assert.Equal(t, "https://api.github.com:443/repos/test", call.Params["url"])
}

func TestHTTPInterceptor_InvalidURL(t *testing.T) {
	interceptor := &HTTPInterceptor{}
	call := interceptor.toolCall("main", "s1", "not-a-url")

	assert.Equal(t, "", call.Params["domain"])
	assert.Equal(t, "fetch", call.Tool)
}

func setupHTTPInterceptor(t *testing.T, policy string) *HTTPInterceptor {
	t.Helper()
	return NewHTTPInterceptor(setupEngine(t, policy))
}
