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

func TestFilesystemInterceptor_EvaluateRead(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		path   string
		want   engine.Action
	}{
		{
			name: "credential file denied",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-creds
    match:
      tool: read
    rules:
      - action: deny
        when:
          path_matches: ["**/.ssh/id_*"]
        message: "Credential access blocked"
`,
			path: "/home/user/.ssh/id_rsa",
			want: engine.ActionDeny,
		},
		{
			name: "source file allowed",
			policy: `
version: "1"
default_action: deny
policies:
  - name: allow-source
    match:
      tool: read
    rules:
      - action: allow
        when:
          path_matches: ["**/*.go"]
`,
			path: "/project/main.go",
			want: engine.ActionAllow,
		},
		{
			name: "dotenv file denied",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-env
    match:
      tool: read
    rules:
      - action: deny
        when:
          path_matches: ["**/.env"]
`,
			path: "/app/.env",
			want: engine.ActionDeny,
		},
		{
			name: "default deny no matching rule",
			policy: `
version: "1"
default_action: deny
policies: []
`,
			path: "/anything",
			want: engine.ActionDeny,
		},
		{
			name: "path_not_matches exclusion",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-logs
    match:
      tool: read
    rules:
      - action: deny
        when:
          path_matches: ["**/*.log"]
          path_not_matches: ["**/app.log"]
`,
			path: "/var/log/app.log",
			want: engine.ActionAllow,
		},
		{
			name: "path normalization cleans traversal",
			policy: `
version: "1"
default_action: deny
policies:
  - name: allow-go
    match:
      tool: read
    rules:
      - action: allow
        when:
          path_matches: ["**/*.go"]
`,
			path: "./foo/../bar/baz.go",
			want: engine.ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := setupFilesystemInterceptor(t, tt.policy)
			got := interceptor.EvaluateRead("main", "s1", tt.path)
			assert.Equal(t, tt.want, got.Action, "path: %s", tt.path)
		})
	}
}

func TestFilesystemInterceptor_EvaluateWrite(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		path   string
		want   engine.Action
	}{
		{
			name: "write to /etc denied",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-etc
    match:
      tool: write
    rules:
      - action: deny
        when:
          path_matches: ["/etc/**"]
        message: "System path write blocked"
`,
			path: "/etc/passwd",
			want: engine.ActionDeny,
		},
		{
			name: "write to project dir allowed",
			policy: `
version: "1"
default_action: deny
policies:
  - name: allow-project
    match:
      tool: write
    rules:
      - action: allow
        when:
          path_matches: ["/home/user/project/**"]
`,
			path: "/home/user/project/main.go",
			want: engine.ActionAllow,
		},
		{
			name: "write to .ssh denied",
			policy: `
version: "1"
default_action: allow
policies:
  - name: block-ssh
    match:
      tool: write
    rules:
      - action: deny
        when:
          path_matches: ["**/.ssh/**"]
`,
			path: "/home/user/.ssh/authorized_keys",
			want: engine.ActionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := setupFilesystemInterceptor(t, tt.policy)
			got := interceptor.EvaluateWrite("main", "s1", tt.path, "content")
			assert.Equal(t, tt.want, got.Action, "path: %s", tt.path)
		})
	}
}

func TestFilesystemInterceptor_ContentLength(t *testing.T) {
	interceptor := &FilesystemInterceptor{}
	call := interceptor.toolCall("main", "s1", "write", "/tmp/test.txt",
		map[string]any{"content_length": 42})

	got, ok := call.Params["content_length"].(int)
	assert.True(t, ok, "content_length should be int")
	assert.Equal(t, 42, got)
}

func TestFilesystemInterceptor_PathMetadata(t *testing.T) {
	interceptor := &FilesystemInterceptor{}
	call := interceptor.toolCall("main", "s1", "read", "/home/user/project/src/main.go", nil)

	assert.Equal(t, "/home/user/project/src/main.go", call.Params["path"])
	assert.Equal(t, "/home/user/project/src", call.Params["dir"])
	assert.Equal(t, ".go", call.Params["ext"])
	assert.Equal(t, "main.go", call.Params["filename"])
}

func setupFilesystemInterceptor(t *testing.T, policy string) *FilesystemInterceptor {
	t.Helper()
	eng := setupEngine(t, policy)
	return NewFilesystemInterceptor(eng)
}
