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

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (s *JSONLSink) shouldAnchorLocked() bool {
	if s.anchorInterval <= 0 {
		return false
	}
	return s.eventCount%int64(s.anchorInterval) == 0
}

func (s *JSONLSink) writeAnchorLocked(event Event) error {
	anchor := ChainAnchor{
		EventID:    event.ID,
		Hash:       event.Hash,
		EventCount: s.eventCount,
		Timestamp:  time.Now().UTC(),
		File:       s.currentFile,
	}

	data, err := json.Marshal(anchor)
	if err != nil {
		return fmt.Errorf("audit: marshal anchor: %w", err)
	}

	path := filepath.Join(s.dir, anchorFilename)
	tmpPath := path + ".tmp"

	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("audit: write anchor tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("audit: replace anchor: %w", err)
	}

	s.logger.Info("audit: wrote chain anchor",
		"event_id", anchor.EventID,
		"event_count", anchor.EventCount,
		"file", anchor.File,
	)

	return nil
}
