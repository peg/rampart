//go:build windows

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
	"fmt"
	"log/slog"
)

// SyslogSink is not supported on Windows.
type SyslogSink struct{}

// NewSyslogSink returns an error on Windows since log/syslog is not available.
func NewSyslogSink(addr string, cef bool, logger *slog.Logger) (*SyslogSink, error) {
	return nil, fmt.Errorf("syslog is not supported on Windows; use --cef for file-based SIEM output")
}

// Send is a no-op on Windows.
func (s *SyslogSink) Send(e Event) {}

// Close is a no-op on Windows.
func (s *SyslogSink) Close() error { return nil }
