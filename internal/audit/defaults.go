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

package audit

import (
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	hostContextOnce   sync.Once
	cachedHostContext HostContext
)

func applyEventDefaults(event Event) Event {
	if strings.TrimSpace(event.SchemaVersion) == "" {
		event.SchemaVersion = EventSchemaVersion
	}
	if event.ID == "" {
		event.ID = NewEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Host == nil {
		event.Host = &HostContext{}
	}
	host := defaultHostContext(*event.Host)
	event.Host = &host
	return event
}

func defaultHostContext(host HostContext) HostContext {
	defaults := localHostContext()
	if strings.TrimSpace(host.Hostname) == "" {
		host.Hostname = defaults.Hostname
	}
	if strings.TrimSpace(host.OS) == "" {
		host.OS = defaults.OS
	}
	if strings.TrimSpace(host.Arch) == "" {
		host.Arch = defaults.Arch
	}
	return host
}

func localHostContext() HostContext {
	hostContextOnce.Do(func() {
		hostname, err := os.Hostname()
		if err != nil || strings.TrimSpace(hostname) == "" {
			hostname = "unknown"
		}
		cachedHostContext = HostContext{
			Hostname: hostname,
			OS:       runtime.GOOS,
			Arch:     runtime.GOARCH,
		}
	})
	return cachedHostContext
}
