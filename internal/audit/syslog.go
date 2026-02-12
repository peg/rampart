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
	"fmt"
	"log/slog"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/peg/rampart/internal/build"
)

// CEFSeverity maps decision actions to CEF severity levels.
var CEFSeverity = map[string]int{
	"deny":  8,
	"ask":   5,
	"log":   3,
	"allow": 1,
}

// syslogSeverity maps decision actions to syslog priorities.
var syslogSeverity = map[string]syslog.Priority{
	"deny":  syslog.LOG_WARNING,
	"allow": syslog.LOG_INFO,
	"log":   syslog.LOG_NOTICE,
	"ask":   syslog.LOG_NOTICE,
}

// FormatCEF formats an audit event as a CEF string.
func FormatCEF(e Event) string {
	sev, ok := CEFSeverity[e.Decision.Action]
	if !ok {
		sev = 3
	}
	msg := e.Decision.Message
	if msg == "" {
		msg = e.Decision.Action + " " + e.Tool
	}

	// Build extension key-values.
	cmd := ""
	path := ""
	if e.Request != nil {
		if v, ok := e.Request["command"]; ok {
			cmd = fmt.Sprintf("%v", v)
		}
		if v, ok := e.Request["path"]; ok {
			path = fmt.Sprintf("%v", v)
		}
	}
	policyNames := strings.Join(e.Decision.MatchedPolicies, ",")

	// Escape CEF extension values (\ and =).
	esc := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `=`, `\=`)
		return s
	}
	// Escape CEF header pipes.
	escH := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `|`, `\|`)
		return s
	}

	return fmt.Sprintf("CEF:0|Rampart|PolicyEngine|%s|%s|%s|%d|src=%s cmd=%s path=%s policy=%s",
		escH(build.Version),
		escH(e.Decision.Action),
		escH(msg),
		sev,
		esc(e.Agent),
		esc(cmd),
		esc(path),
		esc(policyNames),
	)
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

// CEFFileSink writes CEF-formatted events to a file.
type CEFFileSink struct {
	mu     sync.Mutex
	file   *os.File
	path   string
	logger *slog.Logger
}

// NewCEFFileSink creates a CEF file sink at the given path.
func NewCEFFileSink(path string, logger *slog.Logger) (*CEFFileSink, error) {
	if logger == nil {
		logger = slog.Default()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create cef dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open cef file: %w", err)
	}
	return &CEFFileSink{file: f, path: path, logger: logger}, nil
}

// Send writes a CEF-formatted event line to the file.
func (c *CEFFileSink) Send(e Event) {
	line := FormatCEF(e) + "\n"
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.file.WriteString(line); err != nil {
		c.logger.Warn("cef: file write failed", "error", err)
	}
}

// Close closes the CEF file.
func (c *CEFFileSink) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.file.Close()
}

// MultiSink wraps the primary AuditSink and additional output sinks.
// It implements AuditSink and fans out events to syslog/CEF sinks.
type MultiSink struct {
	primary    AuditSink
	syslogSink *SyslogSink
	cefFile    *CEFFileSink
	ch         chan Event
	done       chan struct{}
	logger     *slog.Logger
}

// NewMultiSink creates a sink that writes to the primary sink synchronously
// and fans out to syslog/CEF sinks asynchronously via a buffered channel.
func NewMultiSink(primary AuditSink, syslogSink *SyslogSink, cefFile *CEFFileSink, logger *slog.Logger) *MultiSink {
	if logger == nil {
		logger = slog.Default()
	}
	m := &MultiSink{
		primary:    primary,
		syslogSink: syslogSink,
		cefFile:    cefFile,
		ch:         make(chan Event, 1024),
		done:       make(chan struct{}),
		logger:     logger,
	}
	go m.drain()
	return m
}

func (m *MultiSink) drain() {
	defer close(m.done)
	for e := range m.ch {
		if m.syslogSink != nil {
			m.syslogSink.Send(e)
		}
		if m.cefFile != nil {
			m.cefFile.Send(e)
		}
	}
}

// Write writes to the primary sink and enqueues to secondary sinks (non-blocking).
func (m *MultiSink) Write(event Event) error {
	err := m.primary.Write(event)
	// Non-blocking send to secondary sinks.
	select {
	case m.ch <- event:
	default:
		m.logger.Warn("audit: secondary sink channel full, dropping event", "id", event.ID)
	}
	return err
}

// Flush flushes the primary sink.
func (m *MultiSink) Flush() error {
	return m.primary.Flush()
}

// Close closes all sinks. Drains the async channel first.
func (m *MultiSink) Close() error {
	close(m.ch)
	<-m.done // wait for drain
	var errs []error
	if m.syslogSink != nil {
		if err := m.syslogSink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.cefFile != nil {
		if err := m.cefFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.primary.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("audit: close errors: %v", errs)
	}
	return nil
}
