// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/peg/rampart/internal/notify"
)

// NewRedactingLogger redacts messages, string/error/Stringer attributes, groups,
// and JSON map/slice values before formatting. Other attribute types retain the
// handler's normal representation. Wrap before adding attributes so With and
// WithGroup share this boundary. Audit events have a separate sink contract.
func NewRedactingLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	if _, ok := logger.Handler().(*redactingLogHandler); ok {
		return logger
	}
	return slog.New(&redactingLogHandler{inner: logger.Handler()})
}

type redactingLogHandler struct {
	inner          slog.Handler
	sensitiveGroup bool
}

func (h *redactingLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *redactingLogHandler) Handle(ctx context.Context, record slog.Record) error {
	redacted := slog.NewRecord(record.Time, record.Level, notify.SanitizeCommand(record.Message), record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		redacted.AddAttrs(h.redactAttr(attr))
		return true
	})
	return h.inner.Handle(ctx, redacted)
}

func (h *redactingLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, attr := range attrs {
		redacted[i] = h.redactAttr(attr)
	}
	return &redactingLogHandler{inner: h.inner.WithAttrs(redacted), sensitiveGroup: h.sensitiveGroup}
}

func (h *redactingLogHandler) WithGroup(name string) slog.Handler {
	return &redactingLogHandler{
		inner:          h.inner.WithGroup(notify.SanitizeCommand(name)),
		sensitiveGroup: h.sensitiveGroup || isSensitiveAuditKey(name),
	}
}

func (h *redactingLogHandler) redactAttr(attr slog.Attr) slog.Attr {
	if h.sensitiveGroup {
		return slog.String(notify.SanitizeCommand(attr.Key), redactedValue)
	}
	return redactLogAttr(attr)
}

func redactLogAttr(attr slog.Attr) slog.Attr {
	attr.Value = attr.Value.Resolve()
	sensitive := isSensitiveAuditKey(attr.Key)
	attr.Key = notify.SanitizeCommand(attr.Key)
	if sensitive {
		attr.Value = slog.StringValue(redactedValue)
		return attr
	}
	switch attr.Value.Kind() {
	case slog.KindString:
		attr.Value = slog.StringValue(notify.SanitizeCommand(attr.Value.String()))
	case slog.KindGroup:
		group := attr.Value.Group()
		redacted := make([]slog.Attr, len(group))
		for i, item := range group {
			redacted[i] = redactLogAttr(item)
		}
		attr.Value = slog.GroupValue(redacted...)
	case slog.KindAny:
		switch value := attr.Value.Any().(type) {
		case error:
			attr.Value = slog.StringValue(notify.SanitizeCommand(value.Error()))
		case fmt.Stringer:
			attr.Value = slog.StringValue(notify.SanitizeCommand(value.String()))
		default:
			attr.Value = slog.AnyValue(redactAuditValue(value))
		}
	}
	return attr
}
