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

// Package watch provides the live terminal dashboard for audit events.
package watch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/peg/rampart/internal/audit"
)

const defaultTailPoll = 250 * time.Millisecond

type tailerEvent struct {
	event audit.Event
	err   error
}

type fileTailer struct {
	path       string
	newWatcher func() (*fsnotify.Watcher, error)
	pollEvery  time.Duration
}

func newFileTailer(path string) *fileTailer {
	return &fileTailer{
		path:       path,
		newWatcher: fsnotify.NewWatcher,
		pollEvery:  defaultTailPoll,
	}
}

func (t *fileTailer) start(ctx context.Context) <-chan tailerEvent {
	out := make(chan tailerEvent, 128)

	go func() {
		defer close(out)
		if strings.TrimSpace(t.path) == "" {
			out <- tailerEvent{err: errors.New("watch: audit file path is empty")}
			return
		}

		dir := filepath.Dir(t.path)
		watcher, err := t.newWatcher()
		if err != nil {
			out <- tailerEvent{err: fmt.Errorf("watch: create file watcher: %w", err)}
			return
		}
		defer watcher.Close()

		if err := watcher.Add(dir); err != nil {
			out <- tailerEvent{err: fmt.Errorf("watch: watch parent directory %s: %w", dir, err)}
			return
		}

		_ = watcher.Add(t.path)

		offset := int64(0)
		offset = t.publishAvailable(out, offset)

		ticker := time.NewTicker(t.pollEvery)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				offset = t.publishAvailable(out, offset)
			case evt, ok := <-watcher.Events:
				if !ok {
					return
				}
				cleanName := filepath.Clean(evt.Name)
				cleanPath := filepath.Clean(t.path)

				// If a new .jsonl file is created in the dir, switch to it.
				if evt.Has(fsnotify.Create) && strings.HasSuffix(cleanName, ".jsonl") && cleanName != cleanPath {
					t.path = cleanName
					cleanPath = cleanName
					_ = watcher.Add(t.path)
					offset = 0
				}

				if cleanName != cleanPath {
					continue
				}
				if evt.Has(fsnotify.Create) {
					_ = watcher.Add(t.path)
					offset = 0
				}
				if evt.Has(fsnotify.Remove) || evt.Has(fsnotify.Rename) {
					offset = 0
					continue
				}
				if evt.Has(fsnotify.Write) || evt.Has(fsnotify.Create) || evt.Has(fsnotify.Chmod) {
					offset = t.publishAvailable(out, offset)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					continue
				}
				out <- tailerEvent{err: fmt.Errorf("watch: watcher error: %w", err)}
			}
		}
	}()

	return out
}

func (t *fileTailer) publishAvailable(out chan<- tailerEvent, offset int64) int64 {
	newEvents, newOffset, err := audit.ReadEventsFromOffset(t.path, offset)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		out <- tailerEvent{err: err}
		return offset
	}

	for _, event := range newEvents {
		out <- tailerEvent{event: event}
	}

	return newOffset
}
