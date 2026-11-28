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

// Package policies embeds the default policy YAML profiles.
package policies

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"runtime"
)

//go:embed standard.yaml windows.yaml macos.yaml paranoid.yaml yolo.yaml block-prompt-injection.yaml research-agent.yaml mcp-server.yaml openclaw.yaml guard.yaml production-guard.yaml
var FS embed.FS

// ProfileNames lists the available built-in policy profiles.
var ProfileNames = []string{"standard", "paranoid", "yolo", "block-prompt-injection", "research-agent", "mcp-server", "openclaw", "guard", "production-guard"}

// osRules names the file whose rules the standard profile gains on each OS.
var osRules = map[string]string{"windows": "windows.yaml", "darwin": "macos.yaml"}

// Profile returns the embedded policy YAML for a named profile. The standard
// profile includes the rules for the host OS.
func Profile(name string) ([]byte, error) {
	return ProfileFor(name, HostOS())
}

// ProfileFor returns a profile as Profile would on goos.
func ProfileFor(name, goos string) ([]byte, error) {
	for _, p := range ProfileNames {
		if p != name {
			continue
		}
		data, err := FS.ReadFile(name + ".yaml")
		if err != nil || name != "standard" || osRules[goos] == "" {
			return data, err
		}
		extra, err := FS.ReadFile(osRules[goos])
		if err != nil {
			return nil, err
		}
		// Both files end in their policies list, so the OS rules join it.
		_, rules, ok := bytes.Cut(extra, []byte("\npolicies:\n"))
		if !ok {
			return nil, fmt.Errorf("%s has no policies list", osRules[goos])
		}
		return append(append(data, '\n'), rules...), nil
	}
	return nil, fmt.Errorf("unknown profile %q", name)
}

// HostOS is runtime.GOOS, except that WSL counts as Windows: an agent there
// can still run powershell.exe and cmd.exe.
func HostOS() string {
	if runtime.GOOS == "linux" && os.Getenv("WSL_DISTRO_NAME") != "" {
		return "windows"
	}
	return runtime.GOOS
}
