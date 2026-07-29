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

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// setDetachAttrs configures the command to run in a new session (detached
// from the parent terminal) on Unix systems.
func setDetachAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// isRampartServeProcess authenticates a PID before stop sends a signal. PID
// files can outlive their process, and operating systems reuse numeric PIDs;
// checking only that a PID exists could terminate an unrelated user process.
func isRampartServeProcess(pid int) (bool, string, error) {
	pidArg := fmt.Sprintf("%d", pid)
	commOut, err := exec.Command("ps", "-p", pidArg, "-o", "comm=").CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, strings.TrimSpace(string(commOut)), nil
		}
		return false, "", err
	}
	argsOut, err := exec.Command("ps", "-p", pidArg, "-o", "args=").CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, strings.TrimSpace(string(argsOut)), nil
		}
		return false, "", err
	}

	comm := strings.TrimSpace(string(commOut))
	args := strings.TrimSpace(string(argsOut))
	return isRampartServeCommand(filepath.Base(comm), args), strings.TrimSpace(comm + " " + args), nil
}

func terminateRampartServeProcess(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}
