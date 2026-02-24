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
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// spinFrames are the braille dot animation frames for the CLI spinner.
var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// cliSpinner shows an animated spinner for long-running operations.
// When stdout is not a terminal it prints a simple one-line message instead
// of animating, so CI logs and pipes stay clean.
type cliSpinner struct {
	w     io.Writer
	msg   string
	done  chan struct{}
	once  sync.Once
	isTTY bool
}

// newCliSpinner starts a spinner writing to w with the given message.
// On non-TTY outputs it prints "<msg>..." immediately and is silent on Stop.
func newCliSpinner(w io.Writer, msg string) *cliSpinner {
	s := &cliSpinner{
		w:     w,
		msg:   msg,
		done:  make(chan struct{}),
		isTTY: isTerminal(os.Stdout),
	}
	if s.isTTY {
		go func() {
			ticker := time.NewTicker(80 * time.Millisecond)
			defer ticker.Stop()
			i := 0
			for {
				select {
				case <-s.done:
					return
				case <-ticker.C:
					fmt.Fprintf(s.w, "\r%s %s", spinFrames[i%len(spinFrames)], s.msg)
					i++
				}
			}
		}()
	} else {
		fmt.Fprintf(w, "%s...\n", msg)
	}
	return s
}

// Stop ends the spinner and prints a success message.
func (s *cliSpinner) Stop(successMsg string) {
	s.once.Do(func() {
		if s.isTTY {
			close(s.done)
			time.Sleep(50 * time.Millisecond)
			// Overwrite spinner line (%-70s clears any remaining chars).
			fmt.Fprintf(s.w, "\r✓ %-70s\n", successMsg)
		} else {
			fmt.Fprintf(s.w, "✓ %s\n", successMsg)
		}
	})
}

// Fail ends the spinner and prints an error message.
func (s *cliSpinner) Fail(errMsg string) {
	s.once.Do(func() {
		if s.isTTY {
			close(s.done)
			time.Sleep(50 * time.Millisecond)
			fmt.Fprintf(s.w, "\r✗ %-70s\n", errMsg)
		} else {
			fmt.Fprintf(s.w, "✗ %s\n", errMsg)
		}
	})
}
