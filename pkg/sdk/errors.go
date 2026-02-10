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

// Package sdk provides the public API for integrating Rampart into
// agent runtimes.
//
// The SDK wraps tool functions with policy enforcement. When a wrapped
// function is called, Rampart evaluates the call against loaded policies
// and either allows it to proceed or returns an error.
//
// Basic usage:
//
//	engine := sdk.NewEngine("rampart.yaml")
//	safeExec := engine.Wrap("exec", unsafeExec)
//	result, err := safeExec(ctx, map[string]any{"command": "git push"})
//	// If denied: err is *ErrDenied
package sdk

import "fmt"

// ErrDenied is returned when a tool call is blocked by policy.
// It contains the policy name and a human-readable reason.
type ErrDenied struct {
	// Tool is the tool that was blocked (e.g., "exec").
	Tool string

	// Policy is the name of the policy that triggered the denial.
	Policy string

	// Message is a human-readable reason for the denial.
	Message string
}

// Error implements the error interface.
func (e *ErrDenied) Error() string {
	if e.Policy != "" {
		return fmt.Sprintf("rampart: denied %q by policy %q: %s", e.Tool, e.Policy, e.Message)
	}
	return fmt.Sprintf("rampart: denied %q: %s", e.Tool, e.Message)
}
