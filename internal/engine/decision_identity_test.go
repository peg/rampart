// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package engine

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkingDirectoryPreservesSuppliedBytes(t *testing.T) {
	const directory = " workspace "
	for _, call := range []ToolCall{
		{WorkDir: directory},
		{Params: map[string]any{"workdir": directory}},
		{Params: map[string]any{"cwd": directory}},
		{Input: map[string]any{"cwd": directory}},
	} {
		require.Equal(t, directory, call.WorkingDirectory())
	}
	call := ToolCall{WorkDir: " ", Params: map[string]any{"workdir": "\t", "cwd": directory}}
	require.Equal(t, directory, call.WorkingDirectory(), "absence checks must preserve the selected value")
}

func TestSecurityAliasesRequireExactValues(t *testing.T) {
	for _, field := range []string{"command", "path", "working directory"} {
		t.Run(field, func(t *testing.T) {
			values := map[string]any{"first": " note ", "second": " note "}
			require.NoError(t, validateStringAliases(field, []map[string]any{values}, "first", "second"))
			values["second"] = "note"
			require.ErrorContains(t, validateStringAliases(field, []map[string]any{values}, "first", "second"), "conflicting")
		})
	}
	require.ErrorContains(t, validateStringAliasesWithValues("working directory", []string{" workspace "}, []map[string]any{{"cwd": "workspace"}}, "cwd"), "conflicting")
}
