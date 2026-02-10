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
	"embed"
	"fmt"
)

//go:embed standard.yaml paranoid.yaml yolo.yaml
var FS embed.FS

// ProfileNames lists the available built-in policy profiles.
var ProfileNames = []string{"standard", "paranoid", "yolo"}

// Profile returns the embedded policy YAML for a named profile.
func Profile(name string) ([]byte, error) {
	for _, p := range ProfileNames {
		if p == name {
			return FS.ReadFile(name + ".yaml")
		}
	}
	return nil, fmt.Errorf("unknown profile %q", name)
}
