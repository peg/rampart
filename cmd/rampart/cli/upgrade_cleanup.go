// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type serveCandidateCleanupDeps struct {
	processIdentity func(int) (bool, string, error)
	processStart    func(int) (string, error)
	stop            func(int) error
}

// Capture the newly started process before probing its health. A failed health
// proof gives no authority to stop whichever process happens to respond later.
func captureServeCandidateCleanup(homeDir func() (string, error), executable string, previousPID int, restartedAt time.Time) (func() error, error) {
	return captureServeCandidateCleanupWithDeps(homeDir, executable, previousPID, restartedAt, serveCandidateCleanupDeps{
		processIdentity: isRampartServeProcess,
		processStart:    serveProcessStart,
		stop:            stopServeProcess,
	})
}

func captureServeCandidateCleanupWithDeps(homeDir func() (string, error), executable string, previousPID int, restartedAt time.Time, deps serveCandidateCleanupDeps) (func() error, error) {
	home, err := homeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return nil, fmt.Errorf("cannot resolve private runtime state for candidate cleanup")
	}
	dir := filepath.Join(home, ".rampart")
	state, err := readPrivateServeStateForRestart(dir)
	if err != nil {
		return nil, fmt.Errorf("capture candidate runtime state: %w", err)
	}
	if state.PID <= 0 || state.PID == previousPID || !filepath.IsAbs(state.Executable) || !samePath(state.Executable, executable) || !runtimeIdentified(state.RuntimeIdentity) || state.Launch == nil {
		return nil, fmt.Errorf("candidate cleanup requires a fresh identified process for the installed executable")
	}
	started, err := time.Parse(time.RFC3339Nano, state.Started)
	if err != nil || started.Before(restartedAt) || started.After(time.Now().Add(5*time.Second)) {
		return nil, fmt.Errorf("candidate cleanup state does not identify this restart")
	}
	if _, err := validateLocalServeStateURL(state); err != nil {
		return nil, err
	}
	if err := state.Launch.validate(); err != nil {
		return nil, err
	}

	// Check the complete private record and kernel birth marker on both sides
	// of the existing executable/command ownership check. Reusing a PID, editing
	// launch settings, or replacing the runtime must not transfer stop authority.
	revalidate := func(expectedStart string) (string, error) {
		current, err := readPrivateServeStateForRestart(dir)
		if err != nil || !sameServeCandidateState(state, current) {
			return "", fmt.Errorf("candidate runtime state changed; refusing cleanup")
		}
		before, err := deps.processStart(state.PID)
		if err != nil || before == "" || (expectedStart != "" && before != expectedStart) {
			return "", fmt.Errorf("candidate process birth identity is unavailable or changed; refusing cleanup")
		}
		owned, _, err := deps.processIdentity(state.PID)
		if err != nil || !owned {
			return "", fmt.Errorf("candidate process is no longer Rampart-owned; refusing cleanup")
		}
		current, err = readPrivateServeStateForRestart(dir)
		if err != nil || !sameServeCandidateState(state, current) {
			return "", fmt.Errorf("candidate runtime state changed during ownership verification; refusing cleanup")
		}
		after, err := deps.processStart(state.PID)
		if err != nil || before != after {
			return "", fmt.Errorf("candidate process changed during ownership verification; refusing cleanup")
		}
		return before, nil
	}
	start, err := revalidate("")
	if err != nil {
		return nil, err
	}
	return func() error {
		if _, err := revalidate(start); err != nil {
			return err
		}
		return deps.stop(state.PID)
	}, nil
}

func sameServeCandidateState(a, b serveState) bool {
	aLaunch, bLaunch := a.Launch, b.Launch
	a.Launch, b.Launch = nil, nil
	return a == b && aLaunch != nil && bLaunch != nil && *aLaunch == *bLaunch
}

// Birth markers supplement the existing process command/executable check;
// health instance IDs alone do not authenticate an operating-system process.
func serveProcessStart(pid int) (string, error) {
	var start string
	switch runtime.GOOS {
	case "linux":
		stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if err != nil {
			return "", err
		}
		start = linuxProcessStart(stat)
	case "darwin":
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "lstart=")
		cmd.Env = setEnvValue(os.Environ(), "LC_ALL", "C")
		output, err := cmd.Output()
		if err != nil {
			return "", err
		}
		start = strings.TrimSpace(string(output))
	default:
		return "", fmt.Errorf("candidate process birth identity is unsupported on this platform")
	}
	if start == "" {
		return "", fmt.Errorf("candidate process birth identity is empty")
	}
	return start, nil
}
