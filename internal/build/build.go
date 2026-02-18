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

// Package build provides version and build metadata.
//
// Values are injected at compile time via ldflags:
//
//	go build -ldflags "-X .../build.versionFromLDFlags=v0.1.0"
//
// When installed via `go install`, the module version is read from the
// embedded build info as a fallback.
package build

import "runtime/debug"

// Version is the semantic version. Set by ldflags at build time.
// Falls back to the module version embedded by `go install`.
var Version = func() string {
	if versionFromLDFlags != "dev" {
		return versionFromLDFlags
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return "dev"
}()

// versionFromLDFlags holds the raw ldflag-injected value before fallback.
var versionFromLDFlags = "dev"

// Commit is the short git commit hash. Set by ldflags at build time.
var Commit = "unknown"

// Date is the UTC build timestamp. Set by ldflags at build time.
var Date = "unknown"
