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

	"github.com/spf13/cobra"
)

func newTokenShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Print the current bearer token for rampart serve",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printPersistedToken(cmd)
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the current bearer token for rampart serve",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printPersistedToken(cmd)
		},
	})

	return cmd
}

func printPersistedToken(cmd *cobra.Command) error {
	tok, err := readPersistedToken()
	if err != nil || tok == "" {
		return fmt.Errorf("no token found - run 'rampart serve' to generate one")
	}
	fmt.Fprintln(cmd.OutOrStdout(), tok)
	return nil
}
