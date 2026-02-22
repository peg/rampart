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
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

func newTokenShowCmd() *cobra.Command {
	var force bool
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

	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Generate and persist a new bearer token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !force {
				ok, err := confirmTokenRotate(cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				if !ok {
					return nil
				}
			}

			token, err := generateServeToken()
			if err != nil {
				return err
			}
			if err := persistToken(token); err != nil {
				return fmt.Errorf("rotate token: persist token: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), token)
			return nil
		},
	}
	rotateCmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")
	cmd.AddCommand(rotateCmd)

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

func generateServeToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rotate token: generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func confirmTokenRotate(in io.Reader, out io.Writer) (bool, error) {
	fmt.Fprint(out, "Rotate token and overwrite ~/.rampart/token? [y/N]: ")
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("rotate token: read confirmation: %w", err)
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes", nil
}
