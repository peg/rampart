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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func newApproveCmd(_ *rootOptions) *cobra.Command {
	var proxyAddr string
	var proxyToken string

	cmd := &cobra.Command{
		Use:   "approve <approval-id>",
		Short: "Approve a pending tool call",
		Long: `Approve a pending tool call that matched a require_approval policy rule.

The approval ID is displayed in the proxy logs, the watch TUI, and
the 'rampart pending' command output.

Example:
  rampart pending                    # list pending approvals
  rampart approve 01HGW1...         # approve a specific request
  rampart deny 01HGW1...            # deny a specific request`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return resolveApproval(cmd, proxyAddr, proxyToken, args[0], true)
		},
	}

	cmd.Flags().StringVar(&proxyAddr, "api", "http://127.0.0.1:9091", "Rampart API address (proxy or daemon)")
	cmd.Flags().StringVar(&proxyToken, "token", "", "Proxy auth token (or set RAMPART_TOKEN)")

	return cmd
}

func newDenyCmd(_ *rootOptions) *cobra.Command {
	var proxyAddr string
	var proxyToken string

	cmd := &cobra.Command{
		Use:   "deny <approval-id>",
		Short: "Deny a pending tool call",
		Long:  `Deny a pending tool call that matched a require_approval policy rule.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return resolveApproval(cmd, proxyAddr, proxyToken, args[0], false)
		},
	}

	cmd.Flags().StringVar(&proxyAddr, "api", "http://127.0.0.1:9091", "Rampart API address (proxy or daemon)")
	cmd.Flags().StringVar(&proxyToken, "token", "", "Proxy auth token (or set RAMPART_TOKEN)")

	return cmd
}

func newPendingCmd(_ *rootOptions) *cobra.Command {
	var proxyAddr string
	var proxyToken string

	cmd := &cobra.Command{
		Use:   "pending",
		Short: "List pending approval requests",
		Long: `Show all tool calls waiting for human approval.

These are tool calls that matched a require_approval policy rule and
are blocked until someone approves or denies them (or they expire).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return listPending(cmd, proxyAddr, proxyToken)
		},
	}

	cmd.Flags().StringVar(&proxyAddr, "api", "http://127.0.0.1:9091", "Rampart API address (proxy or daemon)")
	cmd.Flags().StringVar(&proxyToken, "token", "", "Proxy auth token (or set RAMPART_TOKEN)")

	return cmd
}

func resolveToken(token string) string {
	if token != "" {
		return token
	}
	return os.Getenv("RAMPART_TOKEN")
}

func resolveAddr(addr string) string {
	if env := os.Getenv("RAMPART_API"); env != "" && addr == "http://127.0.0.1:9091" {
		return env
	}
	return addr
}

func resolveApproval(cmd *cobra.Command, addr, token, id string, approved bool) error {
	token = resolveToken(token)
	if token == "" {
		return fmt.Errorf("proxy auth token required (--token or RAMPART_TOKEN)")
	}

	body, _ := json.Marshal(map[string]any{
		"approved":    approved,
		"resolved_by": "cli",
	})

	url := fmt.Sprintf("%s/v1/approvals/%s/resolve", strings.TrimRight(addr, "/"), id)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to proxy at %s: %w", addr, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy returned %d: %s", resp.StatusCode, string(respBody))
	}

	action := "approved"
	if !approved {
		action = "denied"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Approval %s %s\n", id[:8], action)
	return nil
}

func listPending(cmd *cobra.Command, addr, token string) error {
	token = resolveToken(token)
	if token == "" {
		return fmt.Errorf("proxy auth token required (--token or RAMPART_TOKEN)")
	}

	url := fmt.Sprintf("%s/v1/approvals", strings.TrimRight(addr, "/"))
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to proxy at %s: %w", addr, err)
	}
	defer resp.Body.Close()

	var result struct {
		Approvals []struct {
			ID        string `json:"id"`
			Tool      string `json:"tool"`
			Command   string `json:"command"`
			Agent     string `json:"agent"`
			Message   string `json:"message"`
			Status    string `json:"status"`
			CreatedAt string `json:"created_at"`
			ExpiresAt string `json:"expires_at"`
		} `json:"approvals"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Approvals) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No pending approvals.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tTOOL\tCOMMAND\tAGENT\tEXPIRES\tMESSAGE\n")

	for _, a := range result.Approvals {
		short := a.ID[:8]
		expires, _ := time.Parse(time.RFC3339, a.ExpiresAt)
		remaining := time.Until(expires).Truncate(time.Second)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			short, a.Tool, truncate(a.Command, 40), a.Agent, remaining, a.Message)
	}

	return w.Flush()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
