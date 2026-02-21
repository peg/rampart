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
