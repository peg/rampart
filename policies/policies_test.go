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

package policies

import (
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEmbeddedPoliciesParse(t *testing.T) {
	for _, profile := range ProfileNames {
		t.Run(profile, func(t *testing.T) {
			data, err := FS.ReadFile(profile + ".yaml")
			require.NoError(t, err, "read embedded %s.yaml", profile)
			require.NotEmpty(t, data)

			var cfg engine.Config
			err = yaml.Unmarshal(data, &cfg)
			require.NoError(t, err, "parse %s.yaml", profile)

			assert.Equal(t, "1", cfg.Version)
			assert.NotEmpty(t, cfg.Policies, "profile %s should have policies", profile)

			for _, p := range cfg.Policies {
				assert.NotEmpty(t, p.Name, "policy should have a name")
				assert.NotEmpty(t, p.Rules, "policy %s should have rules", p.Name)
			}
		})
	}
}
