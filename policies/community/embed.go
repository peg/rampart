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

// Package community embeds the community policy YAML files shipped with
// each release. These are served directly from the binary for offline
// support, avoiding network round-trips and SHA256 mismatches caused by
// line-ending differences across platforms.
package community

import "embed"

//go:embed *.yaml
var FS embed.FS
