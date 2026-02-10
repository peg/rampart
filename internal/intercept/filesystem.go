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
	"path/filepath"
	"time"

	"github.com/peg/rampart/internal/engine"
)

// FilesystemInterceptor evaluates file read/write operations through the
// policy engine. It normalizes file paths and extracts metadata (directory,
// extension, filename) for policy matching.
type FilesystemInterceptor struct {
	engine *engine.Engine
}

// NewFilesystemInterceptor creates a FilesystemInterceptor backed by the given engine.
func NewFilesystemInterceptor(engine *engine.Engine) *FilesystemInterceptor {
	return &FilesystemInterceptor{engine: engine}
}

// EvaluateRead checks a file read operation against policies.
func (i *FilesystemInterceptor) EvaluateRead(agent, session, path string) engine.Decision {
	call := i.toolCall(agent, session, "read", path, nil)
	return i.engine.Evaluate(call)
}

// EvaluateWrite checks a file write operation against policies.
func (i *FilesystemInterceptor) EvaluateWrite(agent, session, path, content string) engine.Decision {
	extra := map[string]any{"content_length": len(content)}
	call := i.toolCall(agent, session, "write", path, extra)
	return i.engine.Evaluate(call)
}

// toolCall builds a normalized ToolCall from a file operation.
func (i *FilesystemInterceptor) toolCall(
	agent, session, tool, path string,
	extra map[string]any,
) engine.ToolCall {
	cleaned := filepath.Clean(path)

	params := map[string]any{
		"path":     cleaned,
		"dir":      filepath.Dir(cleaned),
		"ext":      filepath.Ext(cleaned),
		"filename": filepath.Base(cleaned),
	}

	for k, v := range extra {
		params[k] = v
	}

	return engine.ToolCall{
		Agent:     agent,
		Session:   session,
		Tool:      tool,
		Params:    params,
		Timestamp: time.Now(),
	}
}
