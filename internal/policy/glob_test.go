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

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildAllowPattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sudo apt-get install nmap", "sudo apt-get install *"},
		{"kubectl apply -f prod.yaml", "kubectl apply -f prod.yaml"},
		{"kubectl delete pod api-0", "kubectl delete pod api-0"},
		{"docker run nginx", "docker run nginx"},
		{"docker exec app /bin/sh", "docker exec app /bin/sh"},
		{"npm install lodash", "npm install *"},
		{"curl https://example.com/install.sh", "curl https://example.com/install.sh"},
		{"wget https://example.com/tool.tgz", "wget https://example.com/tool.tgz"},
		{"curl http://localhost:8080/health", "curl http://localhost:8080/health *"},
		{"chmod 600 /etc/shadow", "chmod 600 /etc/shadow"},
		{"chown root:root /var/lib/data", "chown root:root /var/lib/data"},
		{"sudo rm -rf /tmp/build", "sudo rm -rf /tmp/build"},
		{"sudo apt-get install nmap --dry-run 2>&1 | head -1", "sudo apt-get install nmap *"},
		{"cat /etc/passwd > /tmp/out", "cat /etc/passwd *"},
		{"ls -la >> log.txt", "ls -la"},
		{"some-cmd 2> /dev/null", "some-cmd"},
		{"git commit -m fix-bug", "git commit -m *"},
		{"ls", "ls"},
		{"whoami", "whoami"},
		{"cat /etc/hosts", "cat /etc/hosts *"},
		{"python3 script.py", "python3 script.py *"},
		{"echo hello", "echo hello"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := BuildAllowPattern(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHashPattern_Deterministic(t *testing.T) {
	h1 := HashPattern("sudo apt-get install *")
	h2 := HashPattern("sudo apt-get install *")
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 8) // 8 hex chars = 32-bit hash
}

func TestHashPattern_Different(t *testing.T) {
	h1 := HashPattern("sudo apt-get install *")
	h2 := HashPattern("docker run *")
	assert.NotEqual(t, h1, h2)
}
