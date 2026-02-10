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

import "log/slog"

// AuditSink writes tamper-evident audit events to a persistent store.
type AuditSink interface {
	Write(event Event) error
	Flush() error
	Close() error
}

const (
	defaultFsync                = true
	defaultRotateSize     int64 = 100 * 1024 * 1024
	defaultAnchorInterval       = 100
)

// SinkOption configures an AuditSink implementation.
type SinkOption func(*sinkConfig)

type sinkConfig struct {
	fsync          bool
	rotateSize     int64
	anchorInterval int
	logger         *slog.Logger
}

func defaultSinkConfig() sinkConfig {
	return sinkConfig{
		fsync:          defaultFsync,
		rotateSize:     defaultRotateSize,
		anchorInterval: defaultAnchorInterval,
	}
}

// WithFsync configures whether writes call fsync before returning.
func WithFsync(enabled bool) SinkOption {
	return func(cfg *sinkConfig) {
		cfg.fsync = enabled
	}
}

// WithRotateSize configures the maximum JSONL file size in bytes.
func WithRotateSize(size int64) SinkOption {
	return func(cfg *sinkConfig) {
		if size > 0 {
			cfg.rotateSize = size
		}
	}
}

// WithAnchorInterval configures how often chain anchors are written.
func WithAnchorInterval(events int) SinkOption {
	return func(cfg *sinkConfig) {
		if events > 0 {
			cfg.anchorInterval = events
		}
	}
}

// WithLogger configures the logger for audit operations.
// Defaults to slog.Default() if not set.
func WithLogger(logger *slog.Logger) SinkOption {
	return func(cfg *sinkConfig) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}
