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
	"fmt"
	"net/url"
	"time"

	"github.com/peg/rampart/internal/engine"
)

const (
	diagnosticToolNames    = "exec, read, write, edit, fetch, web_fetch, http, browser"
	diagnosticToolFlagHelp = "Tool type: " + diagnosticToolNames
)

// newDiagnosticToolCall maps the CLI's single argument to the same canonical
// ToolCall shape for test and explain diagnostics.
func newDiagnosticToolCall(tool, argument, agent, session string, timestamp time.Time) (engine.ToolCall, error) {
	arguments := make(map[string]any)
	call := engine.ToolCall{
		Agent:     agent,
		Session:   session,
		Tool:      tool,
		Params:    arguments,
		Input:     arguments,
		Timestamp: timestamp,
	}

	switch tool {
	case "exec":
		call.Params["command"] = argument
	case "read", "write", "edit":
		call.Params["path"] = argument
	case "fetch", "web_fetch", "http", "browser":
		call.Params["url"] = argument
		if parsed, err := url.Parse(argument); err == nil && parsed.Host != "" {
			call.Params["domain"] = parsed.Hostname()
			call.Params["scheme"] = parsed.Scheme
			call.Params["path"] = parsed.Path
		}
	default:
		return engine.ToolCall{}, fmt.Errorf("unsupported tool %q (supported: %s)", tool, diagnosticToolNames)
	}

	return call, nil
}
