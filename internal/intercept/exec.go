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

package intercept

import (
	"strings"
	"time"

	"github.com/peg/rampart/internal/engine"
)

// ExecInterceptor evaluates exec commands through the policy engine.
type ExecInterceptor struct {
	engine *engine.Engine
}

// NewExecInterceptor creates an ExecInterceptor backed by the given engine.
func NewExecInterceptor(engine *engine.Engine) *ExecInterceptor {
	return &ExecInterceptor{engine: engine}
}

// Evaluate checks a shell command for an agent/session using exec policies.
func (i *ExecInterceptor) Evaluate(agent, session, command string) engine.Decision {
	call := i.toolCall(agent, session, command)
	return i.engine.Evaluate(call)
}

// toolCall builds a normalized exec ToolCall from input.
func (i *ExecInterceptor) toolCall(agent, session, command string) engine.ToolCall {
	normalized := strings.TrimSpace(command)
	binary := extractBinary(normalized)

	return engine.ToolCall{
		Agent:     agent,
		Session:   session,
		Tool:      "exec",
		Params:    map[string]any{"command": normalized, "binary": binary},
		Timestamp: time.Now(),
	}
}

// extractBinary returns the first token from a command string.
func extractBinary(command string) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
