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

package engine

import (
	"strings"
	"testing"
)

func TestStripPrivilegeWrapper(t *testing.T) {
	cases := map[string]string{
		"sudo rm -rf /":               "rm -rf /",
		"sudo -u root rm -rf /":       "rm -rf /",
		"sudo -E -H rm x":             "rm x",
		"sudo --user=root rm x":       "rm x",
		"sudo -- rm x":                "rm x",
		"/usr/bin/sudo -g wheel rm x": "rm x",
		"doas -u root rm x":           "rm x",
		"pkexec --user root rm x":     "rm x",
		"sudo -nu root rm x":          "rm x",
		"sudo -iu root rm x":          "rm x",
		"sudo -nuroot rm x":           "rm x",
		"doas -nu root rm x":          "rm x",
		"sudo -R /srv rm x":           "rm x",
		"sudo -C3 rm x":               "rm x",
		"sudo -l":                     "sudo -l",
		"rm x":                        "rm x",
	}
	for in, want := range cases {
		got := strings.Join(stripPrivilegeWrapper(strings.Fields(in)), " ")
		if got != want {
			t.Errorf("stripPrivilegeWrapper(%q) = %q, want %q", in, got, want)
		}
	}
}

// Allow rules must not look through a change of identity.
func TestPrivilegeWrapperDoesNotWidenAllow(t *testing.T) {
	got := unwrapExecutors(strings.Fields("sudo rm x"), false)
	if strings.Join(got, " ") != "sudo rm x" {
		t.Fatalf("granting unwrap looked through sudo: %v", got)
	}
}
