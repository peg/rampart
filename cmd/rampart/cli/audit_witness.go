// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/spf13/cobra"
)

func newAuditWitnessCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "witness", Short: "Publish and independently retrieve audit checkpoints"}
	var auditDir, configPath string
	cmd.PersistentFlags().StringVar(&auditDir, "audit-dir", "~/.rampart/audit", "Directory containing managed audit JSONL files")
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "Operator-owned witness configuration, retained independently of audit metadata")
	status := &cobra.Command{Use: "status", Short: "Retrieve the witness checkpoint and compare local history", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configPath == "" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(audit.WitnessResult{Status: "not_configured"})
			}
			return verifyConfiguredWitness(cmd, auditDir, configPath)
		}}
	var follow bool
	var interval, timeout time.Duration
	publish := &cobra.Command{Use: "publish", Short: "Publish a verified chain head outside the audit write path", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configPath == "" {
				return fmt.Errorf("audit witness: not_configured; --config is required")
			}
			if interval < time.Minute || timeout < time.Second || timeout > 10*time.Minute {
				return fmt.Errorf("audit witness: interval must be at least 1m and timeout must be between 1s and 10m")
			}
			witness, err := audit.LoadWitness(configPath)
			if err != nil {
				return err
			}
			dir, err := expandHome(auditDir)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			for {
				result, publishErr := publishWitnessWithRetry(ctx, witness, dir, timeout)
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
					return err
				}
				if !follow {
					return publishErr
				}
				// There is no event queue: the next bounded attempt takes a new
				// snapshot. Outages coalesce work and cannot back up local logging.
				timer := time.NewTimer(interval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
			}
		}}
	publish.Flags().BoolVar(&follow, "follow", false, "Keep publishing at a bounded cadence; local logging is independent")
	publish.Flags().DurationVar(&interval, "interval", time.Minute, "Delay between publication cycles (minimum 1m)")
	publish.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Deadline for each snapshot/publication attempt")
	cmd.AddCommand(status, publish)
	return cmd
}

func verifyConfiguredWitness(cmd *cobra.Command, auditDir, configPath string) error {
	witness, err := audit.LoadWitness(configPath)
	if err != nil {
		return err
	}
	dir, err := expandHome(auditDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
	defer cancel()
	result, verifyErr := witness.Verify(ctx, dir)
	if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
		return err
	}
	return verifyErr
}

func publishWitnessWithRetry(ctx context.Context, witness *audit.Witness, dir string, timeout time.Duration) (audit.WitnessResult, error) {
	var result audit.WitnessResult
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		result, err = witness.Publish(attemptCtx, dir)
		cancel()
		if err == nil || audit.WitnessCode(err) != "unavailable" || attempt == 2 {
			return result, err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result, ctx.Err()
		case <-timer.C:
		}
	}
	return result, err
}
