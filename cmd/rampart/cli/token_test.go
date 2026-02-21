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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenShow_PrintsPersistedToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const want = "rampart_test_token_123"
	require.NoError(t, persistToken(want))

	stdout, _, err := runCLI(t, "token")
	require.NoError(t, err)
	assert.Equal(t, want, stdout)

	stdout, _, err = runCLI(t, "token", "show")
	require.NoError(t, err)
	assert.Equal(t, want, stdout)
}

func TestTokenRotateForce_GeneratesAndPersistsToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd(context.Background(), stdout, stderr)
	cmd.SetArgs([]string{"token", "rotate", "--force"})

	require.NoError(t, cmd.Execute())

	got := stdout.String()
	assert.Regexp(t, regexp.MustCompile(`^[a-f0-9]{64}\n$`), got)

	data, err := os.ReadFile(filepath.Join(home, ".rampart", "token"))
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(got), string(data))
}

func TestTokenRotateConfirmNo_DoesNotOverwrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, persistToken("existing-token"))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd(context.Background(), stdout, stderr)
	cmd.SetArgs([]string{"token", "rotate"})
	cmd.SetIn(bytes.NewBufferString("n\n"))

	require.NoError(t, cmd.Execute())

	assert.Equal(t, "Rotate token and overwrite ~/.rampart/token? [y/N]: ", stdout.String())
	tok, err := readPersistedToken()
	require.NoError(t, err)
	assert.Equal(t, "existing-token", tok)
}

func TestTokenRotateConfirmYes_Overwrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, persistToken("old-token"))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd(context.Background(), stdout, stderr)
	cmd.SetArgs([]string{"token", "rotate"})
	cmd.SetIn(bytes.NewBufferString("yes\n"))

	require.NoError(t, cmd.Execute())

	got := stdout.String()
	assert.Regexp(t, regexp.MustCompile(`^Rotate token and overwrite ~/.rampart/token\? \[y/N\]: [a-f0-9]{64}\n$`), got)
	tok, err := readPersistedToken()
	require.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`^[a-f0-9]{64}$`), tok)
	assert.NotEqual(t, "old-token", tok)
}
