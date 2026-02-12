//go:build !windows

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
	"encoding/json"
	"log/slog"
	"log/syslog"
	"sync"
)

// syslogSeverity maps decision actions to syslog priorities.
var syslogSeverity = map[string]syslog.Priority{
	"deny":  syslog.LOG_WARNING,
	"allow": syslog.LOG_INFO,
	"log":   syslog.LOG_NOTICE,
	"ask":   syslog.LOG_NOTICE,
}

// SyslogSink sends audit events to a syslog server.
// It implements a non-blocking, best-effort delivery model.
type SyslogSink struct {
	mu     sync.Mutex
	writer *syslog.Writer
	addr   string
	cef    bool
	logger *slog.Logger
}

// NewSyslogSink connects to a syslog server at addr (e.g. "localhost:514").
// If cef is true, messages are formatted as CEF; otherwise as JSON.
func NewSyslogSink(addr string, cef bool, logger *slog.Logger) (*SyslogSink, error) {
	if logger == nil {
		logger = slog.Default()
	}
	w, err := syslog.Dial("udp", addr, syslog.LOG_LOCAL0|syslog.LOG_INFO, "rampart")
	if err != nil {
		logger.Warn("syslog: connection failed, will retry on write", "addr", addr, "error", err)
		// Return the sink anyway — we'll try to reconnect on writes.
		return &SyslogSink{addr: addr, cef: cef, logger: logger}, nil
	}
	return &SyslogSink{writer: w, addr: addr, cef: cef, logger: logger}, nil
}

// Send formats and sends an event to syslog. Non-blocking: errors are logged, not returned.
func (s *SyslogSink) Send(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writer == nil {
		w, err := syslog.Dial("udp", s.addr, syslog.LOG_LOCAL0|syslog.LOG_INFO, "rampart")
		if err != nil {
			s.logger.Warn("syslog: reconnect failed", "addr", s.addr, "error", err)
			return
		}
		s.writer = w
	}

	var msg string
	if s.cef {
		msg = FormatCEF(e)
	} else {
		data, err := json.Marshal(e)
		if err != nil {
			s.logger.Warn("syslog: marshal event failed", "error", err)
			return
		}
		msg = string(data)
	}

	prio := syslogSeverity[e.Decision.Action]
	var err error
	switch prio {
	case syslog.LOG_WARNING:
		err = s.writer.Warning(msg)
	case syslog.LOG_NOTICE:
		err = s.writer.Notice(msg)
	default:
		err = s.writer.Info(msg)
	}
	if err != nil {
		s.logger.Warn("syslog: send failed", "error", err)
		// Close broken writer so we reconnect next time.
		_ = s.writer.Close()
		s.writer = nil
	}
}

// Close closes the syslog connection.
func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer != nil {
		return s.writer.Close()
	}
	return nil
}
