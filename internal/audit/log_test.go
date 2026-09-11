// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactingLoggerPreservesStructuredAttributes(t *testing.T) {
	var output bytes.Buffer
	logger := NewRedactingLogger(slog.New(slog.NewJSONHandler(&output, nil)))
	require.Same(t, logger, NewRedactingLogger(logger), "shared constructors should not wrap twice")
	nested := map[string]any{"authorization": "synthetic-header", "count": 3, "path": "/workspace/file"}
	logger.With("session", "token=synthetic-session").WithGroup("request").Info("token=synthetic-message",
		"command", "echo --token='synthetic-command'",
		"password", "synthetic-password",
		"input", nested,
		"error", errors.New("token=synthetic-error"),
		slog.Group("result", slog.Bool("allowed", false), slog.Int("count", 3)),
	)
	for _, secret := range []string{"synthetic-header", "synthetic-session", "synthetic-message", "synthetic-command", "synthetic-password", "synthetic-error"} {
		require.NotContains(t, output.String(), secret)
	}
	var record struct {
		Message string `json:"msg"`
		Session string
		Request struct {
			Input struct {
				Authorization string
				Count         int
				Path          string
			}
			Result struct {
				Allowed bool
				Count   int
			}
		}
	}
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	require.True(t, strings.Contains(record.Message, redactedValue))
	require.Contains(t, record.Session, redactedValue)
	require.Equal(t, redactedValue, record.Request.Input.Authorization)
	require.Equal(t, 3, record.Request.Input.Count)
	require.Equal(t, "/workspace/file", record.Request.Input.Path)
	require.False(t, record.Request.Result.Allowed)
	require.Equal(t, 3, record.Request.Result.Count)
	require.Equal(t, "synthetic-header", nested["authorization"], "logging must not mutate authorization input")

	output.Reset()
	logger.WithGroup("token").With("value", "synthetic-group").Info("grouped diagnostic", "other", "synthetic-other")
	require.NotContains(t, output.String(), "synthetic-group")
	require.NotContains(t, output.String(), "synthetic-other")
}
