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

package cli

import (
	"testing"

	"github.com/peg/rampart/internal/engine"
)

func TestSanitizeCommand(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "MySQL password with single quotes",
			input:    "mysql -u root -p'secretpassword' -h localhost",
			expected: "mysql -u root [REDACTED] -h localhost",
		},
		{
			name:     "MySQL password with double quotes",
			input:    `mysql -u root -p"secretpassword" -h localhost`,
			expected: "mysql -u root [REDACTED] -h localhost",
		},
		{
			name:     "MySQL password without quotes",
			input:    "mysql -u root -psecretpassword -h localhost",
			expected: "mysql -u root [REDACTED] -h localhost",
		},
		{
			name:     "Long form password with equals",
			input:    "command --password=mysecretpassword --host localhost",
			expected: "command [REDACTED] --host localhost",
		},
		{
			name:     "Long form password with space",
			input:    "command --password mysecretpassword --host localhost",
			expected: "command [REDACTED] --host localhost",
		},
		{
			name:     "Authorization Bearer header",
			input:    "curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9' http://api.example.com",
			expected: "curl -H '[REDACTED]' http://api.example.com",
		},
		{
			name:     "Authorization Basic header",
			input:    "curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' http://api.example.com",
			expected: "curl -H '[REDACTED]' http://api.example.com",
		},
		{
			name:     "AWS access key ID",
			input:    "aws s3 ls --profile AKIAIOSFODNN7EXAMPLE",
			expected: "aws s3 ls --profile [REDACTED]",
		},
		{
			name:     "GitHub personal access token",
			input:    "git clone https://ghp_1234567890123456789012345678901234567890@github.com/user/repo.git",
			expected: "git clone https://[REDACTED]@github.com/user/repo.git",
		},
		{
			name:     "GitHub OAuth token",
			input:    "curl -H 'Authorization: token gho_16C7e42F292c6912E7710c838347Ae178B4a' https://api.github.com",
			expected: "curl -H 'Authorization: token [REDACTED]' https://api.github.com",
		},
		{
			name:     "GitHub server token",
			input:    "export GITHUB_TOKEN=ghs_16C7e42F292c6912E7710c838347Ae178B4a",
			expected: "export GITHUB_TOKEN=[REDACTED]",
		},
		{
			name:     "Slack bot token",
			input:    "curl -X POST -H 'Authorization: Bearer xoxb-1234567890-1234567890123-abcdefghijk' https://slack.com/api/chat.postMessage",
			expected: "curl -X POST -H '[REDACTED]' https://slack.com/api/chat.postMessage",
		},
		{
			name:     "Slack user token",
			input:    "export SLACK_TOKEN=xoxp-1234567890-1234567890123-1234567890123-abcdefghijklmnopqrstuvwxyz123456",
			expected: "export SLACK_TOKEN=[REDACTED]",
		},
		{
			name:     "OpenAI API key",
			input:    "curl -H 'Authorization: Bearer sk-1234567890abcdefghijklmnopqrstuvwxyz' https://api.openai.com",
			expected: "curl -H '[REDACTED]' https://api.openai.com",
		},
		{
			name:     "Base64 encoded secret after keyword",
			input:    "config set secret=dGhpc2lzYXZlcnlsb25nc2VjcmV0dmFsdWV0aGF0c2hvdWxkYmVyZWRhY3RlZA==",
			expected: "config set [REDACTED]",
		},
		{
			name:     "Base64 encoded token after keyword",
			input:    "auth token: dGhpc2lzYXZlcnlsb25nc2VjcmV0dmFsdWV0aGF0c2hvdWxkYmVyZWRhY3RlZA==",
			expected: "auth [REDACTED]",
		},
		{
			name:     "Mixed credentials in single command",
			input:    "mysql -u root -p'dbpass' && export API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz",
			expected: "mysql -u root [REDACTED] && export API_KEY=[REDACTED]",
		},
		{
			name:     "No credentials to sanitize",
			input:    "ls -la /home/user",
			expected: "ls -la /home/user",
		},
		{
			name:     "Empty command",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := sanitizeCommand(tc.input)
			if result != tc.expected {
				t.Errorf("sanitizeCommand(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestSanitizeCommand_AllPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "quoted auth bearer", input: "curl -H 'Authorization: Bearer abc123' https://api.example.com", expected: "curl -H '[REDACTED]' https://api.example.com"},
		{name: "mysql single quote", input: "mysql -uroot -p'secret' db", expected: "mysql -uroot [REDACTED] db"},
		{name: "mysql double quote", input: `mysql -uroot -p"secret" db`, expected: "mysql -uroot [REDACTED] db"},
		{name: "mysql unquoted", input: "mysql -uroot -psecret db", expected: "mysql -uroot [REDACTED] db"},
		{name: "password equals", input: "cmd --password=topsecret --flag", expected: "cmd [REDACTED] --flag"},
		{name: "password arg", input: "cmd --password topsecret --flag", expected: "cmd [REDACTED] --flag"},
		{name: "github ghp", input: "token=ghp_1234567890123456789012345678901234567890", expected: "token=[REDACTED]"},
		{name: "github gho", input: "token=gho_abcdef123456", expected: "token=[REDACTED]"},
		{name: "github ghs", input: "token=ghs_abcdef123456", expected: "token=[REDACTED]"},
		{name: "slack xoxb", input: "token=xoxb-111-222-abc", expected: "token=[REDACTED]"},
		{name: "slack xoxp", input: "token=xoxp-111-222-abc", expected: "token=[REDACTED]"},
		{name: "openai key", input: "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456", expected: "export OPENAI_API_KEY=[REDACTED]"},
		{name: "aws access key", input: "aws configure set profile AKIA1234567890ABCDEF", expected: "aws configure set profile [REDACTED]"},
		{name: "unquoted auth header", input: "curl -H Authorization: Bearer abc123 https://example.com", expected: "curl -H Authorization: Bearer [REDACTED] https://example.com"},
		{name: "keyword base64 token", input: "env token=dGhpc2lzYXZlcnlsb25nc2VjcmV0dmFsdWV0aGF0c2hvdWxkYmVyZWRhY3RlZA==", expected: "env [REDACTED]"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeCommand(tc.input)
			if got != tc.expected {
				t.Fatalf("sanitizeCommand(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestExtractCommand(t *testing.T) {
	tests := []struct {
		name string
		call engine.ToolCall
		want string
	}{
		{
			name: "exec command",
			call: engine.ToolCall{Tool: "exec", Params: map[string]any{"command": "go test ./..."}},
			want: "go test ./...",
		},
		{
			name: "read path",
			call: engine.ToolCall{Tool: "read", Params: map[string]any{"path": "/tmp/in.txt"}},
			want: "/tmp/in.txt",
		},
		{
			name: "write path",
			call: engine.ToolCall{Tool: "write", Params: map[string]any{"path": "/tmp/out.txt"}},
			want: "/tmp/out.txt",
		},
		{
			name: "read file_path fallback",
			call: engine.ToolCall{Tool: "read", Params: map[string]any{"file_path": "/tmp/fallback-read.txt"}},
			want: "/tmp/fallback-read.txt",
		},
		{
			name: "write file_path fallback",
			call: engine.ToolCall{Tool: "write", Params: map[string]any{"file_path": "/tmp/fallback-write.txt"}},
			want: "/tmp/fallback-write.txt",
		},
		{
			name: "fetch url",
			call: engine.ToolCall{Tool: "fetch", Params: map[string]any{"url": "https://example.com"}},
			want: "https://example.com",
		},
		{
			name: "unknown tool",
			call: engine.ToolCall{Tool: "other", Params: map[string]any{"path": "/tmp/x"}},
			want: "",
		},
		{
			name: "missing params",
			call: engine.ToolCall{Tool: "exec", Params: map[string]any{}},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractCommand(tc.call)
			if got != tc.want {
				t.Fatalf("extractCommand() = %q, want %q", got, tc.want)
			}
		})
	}
}
