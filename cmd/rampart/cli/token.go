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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/peg/rampart/internal/token"
	"github.com/spf13/cobra"
)

func newTokenShowCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage authentication tokens",
		Long: `Manage authentication tokens for the Rampart proxy.

Without a subcommand, prints the current admin bearer token.

Per-agent tokens allow different AI agents to have different policy
enforcement levels. Agent tokens are eval-only by default (cannot
self-approve or mutate policies).`,
		// Bare "rampart token" shows help instead of dumping admin token.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the current admin bearer token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printPersistedToken(cmd)
		},
	})

	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Generate and persist a new admin bearer token",
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

			tok, err := generateServeToken()
			if err != nil {
				return err
			}
			if err := persistToken(tok); err != nil {
				return fmt.Errorf("rotate token: persist token: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), tok)
			return nil
		},
	}
	rotateCmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")
	cmd.AddCommand(rotateCmd)

	// Per-agent token management subcommands.
	cmd.AddCommand(newTokenCreateCmd())
	cmd.AddCommand(newTokenListCmd())
	cmd.AddCommand(newTokenRevokeCmd())
	cmd.AddCommand(newTokenInfoCmd())

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

// ---------------------------------------------------------------------------
// Per-agent token commands
// ---------------------------------------------------------------------------

func newTokenCreateCmd() *cobra.Command {
	var (
		agent   string
		policy  string
		note    string
		scopes  []string
		expires string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new per-agent token",
		Long: `Creates a new authentication token bound to a specific agent.

The full token is printed once at creation time — save it, as it cannot
be retrieved later. By default, tokens have eval-only scope (can submit
tool calls but cannot approve requests or reload policies).

Examples:
  rampart token create --agent codex
  rampart token create --agent codex --policy paranoid --note "CI restricted"
  rampart token create --agent claude-code --expires 30d
  rampart token create --agent admin-bot --scope eval --scope admin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			storePath, err := token.DefaultStorePath()
			if err != nil {
				return err
			}
			store, err := token.NewStore(storePath)
			if err != nil {
				return err
			}

			var expiresAt *time.Time
			if expires != "" {
				dur, err := parseDuration(expires)
				if err != nil {
					return fmt.Errorf("invalid --expires: %w", err)
				}
				t := time.Now().Add(dur)
				expiresAt = &t
			}

			plaintext, tok, err := store.Create(agent, policy, note, scopes, expiresAt)
			if err != nil {
				return err
			}

			if jsonOut {
				// Include plaintext token in JSON output (only time it's shown).
				out := struct {
					Token  string       `json:"token"`
					Agent  string       `json:"agent"`
					Policy string       `json:"policy,omitempty"`
					Scopes []string     `json:"scopes"`
					Expires *time.Time  `json:"expires_at,omitempty"`
					Note   string       `json:"note,omitempty"`
				}{
					Token:  plaintext,
					Agent:  tok.Agent,
					Policy: tok.Policy,
					Scopes: tok.Scopes,
					Expires: tok.ExpiresAt,
					Note:   tok.Note,
				}
				data, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "✓ Token created")
			fmt.Fprintln(w)
			fmt.Fprintf(w, "  Token:   %s\n", plaintext)
			fmt.Fprintf(w, "  Agent:   %s\n", tok.Agent)
			if tok.Policy != "" {
				fmt.Fprintf(w, "  Policy:  %s\n", tok.Policy)
			}
			fmt.Fprintf(w, "  Scopes:  %s\n", strings.Join(tok.Scopes, ", "))
			if tok.ExpiresAt != nil {
				fmt.Fprintf(w, "  Expires: %s\n", tok.ExpiresAt.Format(time.RFC3339))
			}
			if tok.Note != "" {
				fmt.Fprintf(w, "  Note:    %s\n", tok.Note)
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  ⚠ Save this token — it cannot be retrieved later.")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  Usage:")
			fmt.Fprintf(w, "    export RAMPART_TOKEN=%s\n", plaintext)
			fmt.Fprintf(w, "    curl -X POST -H 'Authorization: Bearer %s' http://127.0.0.1:9090/v1/tool/exec -d '{\"command\":\"echo hello\"}'\n", plaintext)

			return nil
		},
	}

	cmd.Flags().StringVar(&agent, "agent", "", "Agent name (required, e.g., codex, claude-code, openclaw)")
	cmd.Flags().StringVar(&policy, "policy", "", "Policy profile to apply (e.g., paranoid, standard); empty = global policies")
	cmd.Flags().StringVar(&note, "note", "", "Human-readable note")
	cmd.Flags().StringSliceVar(&scopes, "scope", nil, "Token scopes (eval, admin); default: eval only")
	cmd.Flags().StringVar(&expires, "expires", "", "Token expiry (e.g., 24h, 7d, 30d)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	_ = cmd.MarkFlagRequired("agent")

	return cmd
}

func newTokenListCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List per-agent tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			storePath, err := token.DefaultStorePath()
			if err != nil {
				return err
			}
			store, err := token.NewStore(storePath)
			if err != nil {
				return err
			}

			tokens := store.List()
			if len(tokens) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No per-agent tokens found. Create one with: rampart token create --agent <name>")
				return nil
			}

			if jsonOut {
				type maskedToken struct {
					ID        string     `json:"id"`
					Agent     string     `json:"agent"`
					Policy    string     `json:"policy,omitempty"`
					Scopes    []string   `json:"scopes"`
					CreatedAt time.Time  `json:"created_at"`
					ExpiresAt *time.Time `json:"expires_at,omitempty"`
					Note      string     `json:"note,omitempty"`
					Revoked   bool       `json:"revoked,omitempty"`
					Status    string     `json:"status"`
				}
				masked := make([]maskedToken, len(tokens))
				for i, t := range tokens {
					masked[i] = maskedToken{
						ID:        t.MaskedID(),
						Agent:     t.Agent,
						Policy:    t.Policy,
						Scopes:    t.Scopes,
						CreatedAt: t.CreatedAt,
						ExpiresAt: t.ExpiresAt,
						Note:      t.Note,
						Revoked:   t.Revoked,
						Status:    tokenStatus(t),
					}
				}
				data, err := json.MarshalIndent(masked, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-28s %-16s %-12s %-10s %s\n", "TOKEN", "AGENT", "POLICY", "SCOPES", "STATUS")
			for _, t := range tokens {
				policy := t.Policy
				if policy == "" {
					policy = "(global)"
				}
				fmt.Fprintf(w, "%-28s %-16s %-12s %-10s %s\n",
					t.MaskedID(),
					t.Agent,
					policy,
					strings.Join(t.Scopes, ","),
					tokenStatus(t),
				)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	return cmd
}

func newTokenRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <token-id-or-prefix>",
		Short: "Revoke a per-agent token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			storePath, err := token.DefaultStorePath()
			if err != nil {
				return err
			}
			store, err := token.NewStore(storePath)
			if err != nil {
				return err
			}

			n, err := store.Revoke(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Revoked %d token(s)\n", n)
			return nil
		},
	}
}

func newTokenInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <token-id-or-prefix>",
		Short: "Show per-agent token details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			storePath, err := token.DefaultStorePath()
			if err != nil {
				return err
			}
			store, err := token.NewStore(storePath)
			if err != nil {
				return err
			}

			matches := store.FindByPrefix(args[0])
			if len(matches) == 0 {
				return fmt.Errorf("no token matching prefix %q", args[0])
			}
			if len(matches) > 1 {
				return fmt.Errorf("prefix %q matches %d tokens — be more specific", args[0], len(matches))
			}

			t := matches[0]
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "  Token:   %s\n", t.MaskedID())
			fmt.Fprintf(w, "  Agent:   %s\n", t.Agent)
			policy := t.Policy
			if policy == "" {
				policy = "(global)"
			}
			fmt.Fprintf(w, "  Policy:  %s\n", policy)
			fmt.Fprintf(w, "  Scopes:  %s\n", strings.Join(t.Scopes, ", "))
			fmt.Fprintf(w, "  Created: %s\n", t.CreatedAt.Format(time.RFC3339))
			if t.ExpiresAt != nil {
				fmt.Fprintf(w, "  Expires: %s\n", t.ExpiresAt.Format(time.RFC3339))
			}
			if t.Note != "" {
				fmt.Fprintf(w, "  Note:    %s\n", t.Note)
			}
			fmt.Fprintf(w, "  Status:  %s\n", tokenStatus(t))
			return nil
		},
	}
}

func tokenStatus(t token.Token) string {
	if t.Revoked {
		return "revoked"
	}
	if t.IsExpired() {
		return "expired"
	}
	return "active"
}

// parseDuration is defined in report.go — reused here for --expires flag.
