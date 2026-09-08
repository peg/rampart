// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/audit"
	"github.com/stretchr/testify/require"
)

func TestAuditRequiredWitnessDoesNotReportLocalSuccess(t *testing.T) {
	dir := t.TempDir()
	sink, err := audit.NewJSONLSink(dir, audit.WithFsync(false))
	require.NoError(t, err)
	require.NoError(t, sink.Write(audit.Event{Tool: "read"}))
	require.NoError(t, sink.Close())
	cfg := audit.WitnessConfig{Version: 1, ChainID: "cli-chain-identity", WitnessID: "cli-witness-identity", FileDirectory: t.TempDir()}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	config := filepath.Join(t.TempDir(), "witness.json")
	require.NoError(t, os.WriteFile(config, data, 0o600))
	for _, args := range [][]string{
		{"--audit-dir", dir, "--require-witness"},
		{"--audit-dir", dir, "--witness-config", config},
		{"--audit-dir", dir, "--witness-config", config, "--since", "2026-01-01"},
	} {
		cmd := newAuditVerifyCmd()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs(args)
		require.Error(t, cmd.Execute())
		require.NotContains(t, output.String(), "✓")
		require.NotContains(t, output.String(), `"verified":true`)
	}
	cmd := newAuditCmd(nil)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"witness", "publish", "--audit-dir", dir, "--config", config})
	require.NoError(t, cmd.Execute())
	require.Contains(t, output.String(), `"status":"witnessed_head"`)
	verify := newAuditVerifyCmd()
	output.Reset()
	verify.SetOut(&output)
	verify.SetErr(&output)
	verify.SetArgs([]string{"--audit-dir", dir, "--witness-config", config, "--require-witness"})
	require.NoError(t, verify.Execute())
	require.Contains(t, output.String(), `"verified":true`)
	for _, name := range []string{"status", "publish"} {
		cmd := newAuditCmd(nil)
		output.Reset()
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs([]string{"witness", name})
		err := cmd.Execute()
		if name == "status" {
			require.NoError(t, err)
			require.Contains(t, output.String(), `"status":"not_configured"`)
		} else {
			require.Error(t, err)
		}
		require.False(t, strings.Contains(output.String(), `"verified":true`))
	}
}
