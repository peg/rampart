// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecuteRedactsFinalErrorOutput(t *testing.T) {
	const childEnv = "RAMPART_TEST_ROOT_ERROR_CHILD"
	const secret = "ghp_syntheticcredential1234567890123456789012"
	if mode := os.Getenv(childEnv); mode != "" {
		os.Args = []string{"rampart", secret}
		if mode == "serve" {
			home, err := os.UserHomeDir()
			if err != nil {
				t.Fatal(err)
			}
			os.Args = []string{"rampart", "serve", "--config", filepath.Join(home, secret), "--log-file", filepath.Join(home, "serve.log")}
		}
		err := Execute()
		// The error remains intact for callers and exit-status handling; only
		// its final presentation crosses the redaction boundary.
		if err == nil || !strings.Contains(err.Error(), secret) || ExitCode(err) != 1 {
			t.Fatal("Execute did not preserve the original error and exit status")
		}
		os.Exit(ExitCode(err))
	}
	for _, mode := range []string{"parse", "serve"} {
		t.Run(mode, func(t *testing.T) {
			home := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecuteRedactsFinalErrorOutput$")
			child.Env = append(os.Environ(), childEnv+"="+mode, "HOME="+home, "USERPROFILE="+home)
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("child exit: %v; output: %s", err, output)
			}
			if strings.Contains(string(output), secret) || !strings.Contains(string(output), "[REDACTED]") {
				t.Fatalf("final error was not redacted: %s", output)
			}
			if mode == "serve" {
				log, err := os.ReadFile(filepath.Join(home, "serve.log"))
				if err != nil || strings.Contains(string(log), secret) || !strings.Contains(string(log), "[REDACTED]") {
					t.Fatalf("managed error was not redacted: %s (%v)", log, err)
				}
			}
		})
	}
}
