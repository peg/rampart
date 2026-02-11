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