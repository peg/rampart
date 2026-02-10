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

package intercept

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/peg/rampart/internal/engine"
)

// setupEngine creates a test engine from YAML policy text.
func setupEngine(t *testing.T, policy string) *engine.Engine {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	store := engine.NewFileStore(path)
	e, err := engine.New(store, nil)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	return e
}
