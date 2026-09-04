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
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"
)

func newApproveCmd(_ *rootOptions) *cobra.Command {
	var proxyAddr string
	var proxyToken string

	cmd := &cobra.Command{
		Use:   "approve <approval-id>",
		Short: "Approve a pending tool call",
		Long: `Approve a pending tool call that matched an ask policy rule.

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

	cmd.Flags().StringVar(&proxyAddr, "api", "", "Rampart API address (proxy or daemon)")
	cmd.Flags().StringVar(&proxyToken, "token", "", "Proxy auth token (or set RAMPART_TOKEN)")

	return cmd
}

func newDenyCmd(_ *rootOptions) *cobra.Command {
	var proxyAddr string
	var proxyToken string

	cmd := &cobra.Command{
		Use:   "deny <approval-id>",
		Short: "Deny a pending tool call",
		Long:  `Deny a pending tool call that matched an ask policy rule.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return resolveApproval(cmd, proxyAddr, proxyToken, args[0], false)
		},
	}

	cmd.Flags().StringVar(&proxyAddr, "api", "", "Rampart API address (proxy or daemon)")
	cmd.Flags().StringVar(&proxyToken, "token", "", "Proxy auth token (or set RAMPART_TOKEN)")

	return cmd
}

func newPendingCmd(_ *rootOptions) *cobra.Command {
	var details bool
	var proxyAddr string
	var proxyToken string

	cmd := &cobra.Command{
		Use:   "pending",
		Short: "List pending approval requests",
		Long: `Show all tool calls waiting for human approval.

These are tool calls that matched an ask policy rule and
are blocked until someone approves or denies them (or they expire).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return listPendingDetails(cmd, proxyAddr, proxyToken, details)
		},
	}

	cmd.Flags().StringVar(&proxyAddr, "api", "", "Rampart API address (proxy or daemon)")
	cmd.Flags().StringVar(&proxyToken, "token", "", "Proxy auth token (or set RAMPART_TOKEN)")

	cmd.Flags().BoolVar(&details, "details", false, "Show the complete redacted action and full approval IDs")

	return cmd
}

func resolveAddr(addr string) (string, error) {
	if addr == "" {
		if env := strings.TrimSpace(os.Getenv("RAMPART_API")); env != "" {
			return strings.TrimRight(env, "/"), nil
		}
		if cfg, err := loadUserConfig(); err == nil && cfg.APIAddr != "" {
			return cfg.APIAddr, nil
		} else if err != nil {
			return "", err
		}
	}
	return resolveServeURLStrict(addr, fmt.Sprintf("http://localhost:%d", defaultServePort))
}

func resolveApproval(cmd *cobra.Command, addr, token, id string, approved bool) error {
	resolvedAddr, err := resolveAddr(addr)
	if err != nil {
		return fmt.Errorf("resolve approval API address: %w", err)
	}
	token, _, err = resolveTokenForEndpoint(resolvedAddr, token)
	if err != nil {
		return fmt.Errorf("resolve approval API credentials: %w", err)
	}
	if token == "" {
		return fmt.Errorf("proxy auth token required (--token or RAMPART_TOKEN)")
	}

	body, _ := json.Marshal(map[string]any{
		"approved":    approved,
		"resolved_by": "cli",
	})

	url := fmt.Sprintf("%s/v1/approvals/%s/resolve", strings.TrimRight(resolvedAddr, "/"), id)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := rampartHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to proxy at %s: %w", resolvedAddr, err)
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
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Approval %s %s\n", safeApprovalTerminal(id), action)
	return nil
}

func listPending(cmd *cobra.Command, addr, token string) error {
	return listPendingDetails(cmd, addr, token, false)
}

func listPendingDetails(cmd *cobra.Command, addr, token string, details bool) error {
	resolvedAddr, err := resolveAddr(addr)
	if err != nil {
		return fmt.Errorf("resolve approval API address: %w", err)
	}
	token, _, err = resolveTokenForEndpoint(resolvedAddr, token)
	if err != nil {
		return fmt.Errorf("resolve approval API credentials: %w", err)
	}
	if token == "" {
		return fmt.Errorf("proxy auth token required (--token or RAMPART_TOKEN)")
	}

	url := fmt.Sprintf("%s/v1/approvals", strings.TrimRight(resolvedAddr, "/"))
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := rampartHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to proxy at %s: %w", resolvedAddr, err)
	}
	defer resp.Body.Close()

	var result struct {
		Approvals []struct {
			Action    json.RawMessage `json:"action"`
			ID        string          `json:"id"`
			Tool      string          `json:"tool"`
			Command   string          `json:"command"`
			Agent     string          `json:"agent"`
			Message   string          `json:"message"`
			Status    string          `json:"status"`
			CreatedAt string          `json:"created_at"`
			ExpiresAt string          `json:"expires_at"`
		} `json:"approvals"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Approvals) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No pending approvals.")
		return nil
	}

	if details {
		for _, a := range result.Approvals {
			fmt.Fprintf(cmd.OutOrStdout(), "Approval %s\n", safeApprovalTerminal(a.ID))
			if len(a.Action) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "Complete action unavailable: update the Rampart service before approving.")
				continue
			}
			var formatted bytes.Buffer
			if err := json.Indent(&formatted, a.Action, "", "  "); err != nil {
				return fmt.Errorf("invalid action review: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), safeApprovalJSONTerminal(formatted.String()))
		}
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tTOOL\tCOMMAND\tAGENT\tEXPIRES\tMESSAGE\n")

	for _, a := range result.Approvals {
		short := a.ID
		if len(short) > 8 {
			short = short[:8]
		}
		expires, _ := time.Parse(time.RFC3339, a.ExpiresAt)
		remaining := time.Until(expires).Truncate(time.Second)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			safeApprovalTerminal(short), safeApprovalTerminal(a.Tool), safeApprovalTerminal(truncate(a.Command, 40)), safeApprovalTerminal(a.Agent), remaining, safeApprovalTerminal(a.Message))
	}

	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Review complete actions before approval: rampart pending --details")
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// Terminal control characters and invisible direction controls are represented
// literally, so an action cannot erase its suffix or impersonate another row.
func safeApprovalTerminal(text string) string {
	quoted := strconv.QuoteToGraphic(sanitizeCommand(text))
	return quoted[1 : len(quoted)-1]
}

func safeApprovalJSONTerminal(text string) string {
	var out strings.Builder
	for _, r := range text {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r) {
			fmt.Fprintf(&out, "\\u%04x", r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}
