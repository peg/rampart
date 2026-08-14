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

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMCPScanDisabled(t *testing.T) {
	if marker := os.Getenv("RAMPART_MCP_SCAN_TEST_CHILD"); marker != "" {
		require.NoError(t, os.WriteFile(marker, []byte("started"), 0o600))
		return
	}

	marker := filepath.Join(t.TempDir(), "child-started")
	t.Setenv("RAMPART_MCP_SCAN_TEST_CHILD", marker)

	cmd := NewRootCmd(context.Background(), io.Discard, io.Discard)
	cmd.SetArgs([]string{"mcp", "scan", "--", os.Args[0], "-test.run=^TestMCPScanDisabled$"})
	err := cmd.Execute()

	require.EqualError(t, err, mcpScanMigrationGuidance)
	require.Equal(t, 1, ExitCode(err))
	_, statErr := os.Stat(marker)
	require.ErrorIs(t, statErr, os.ErrNotExist, "mcp scan must not start the supplied command")
}
