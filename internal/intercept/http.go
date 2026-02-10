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
	"net/url"
	"time"

	"github.com/peg/rampart/internal/engine"
)

// HTTPInterceptor evaluates HTTP/fetch operations through the policy engine.
// It parses URLs and extracts domain, scheme, and path for policy matching.
type HTTPInterceptor struct {
	engine *engine.Engine
}

// NewHTTPInterceptor creates an HTTPInterceptor backed by the given engine.
func NewHTTPInterceptor(engine *engine.Engine) *HTTPInterceptor {
	return &HTTPInterceptor{engine: engine}
}

// EvaluateFetch checks an HTTP fetch operation against policies.
func (i *HTTPInterceptor) EvaluateFetch(agent, session, rawURL string) engine.Decision {
	call := i.toolCall(agent, session, rawURL)
	return i.engine.Evaluate(call)
}

// toolCall builds a normalized ToolCall from an HTTP URL.
func (i *HTTPInterceptor) toolCall(agent, session, rawURL string) engine.ToolCall {
	params := map[string]any{"url": rawURL}

	parsed, err := url.Parse(rawURL)
	if err == nil && parsed.Host != "" {
		params["domain"] = parsed.Hostname()
		params["scheme"] = parsed.Scheme
		params["path"] = parsed.Path
	} else {
		params["domain"] = ""
		params["scheme"] = ""
		params["path"] = ""
	}

	return engine.ToolCall{
		Agent:     agent,
		Session:   session,
		Tool:      "fetch",
		Params:    params,
		Timestamp: time.Now(),
	}
}
