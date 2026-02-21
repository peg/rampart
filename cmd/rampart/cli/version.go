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
	"runtime"

	"github.com/peg/rampart/internal/build"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build and runtime version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeVersion(cmd.OutOrStdout())
		},
	}
}

func writeVersion(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "rampart %s (%s) built %s\nGo %s\n", build.Version, build.Commit, build.Date, runtime.Version()); err != nil {
		return fmt.Errorf("cli: write version output: %w", err)
	}
	return nil
}
