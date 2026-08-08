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

//go:build windows

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// setDetachAttrs detaches the background server from the invoking console.
// Without these flags, closing the terminal or pressing Ctrl+C can terminate a
// process that `rampart serve --background` reported as independently running.
func setDetachAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
}

type windowsProcessIdentity struct {
	Name        string
	CommandLine string
}

func windowsProcessInspectionScript(pid int) string {
	return fmt.Sprintf(
		`[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); $p = Get-CimInstance Win32_Process -Filter "ProcessId = %d" -ErrorAction Stop; if ($null -ne $p) { $p | Select-Object Name,CommandLine | ConvertTo-Json -Compress }`,
		pid,
	)
}

// isRampartServeProcess uses Win32_Process because os.FindProcess does not
// authenticate a PID and Get-Process does not reliably expose CommandLine.
func isRampartServeProcess(pid int) (bool, string, error) {
	out, err := exec.Command(
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		windowsProcessInspectionScript(pid),
	).CombinedOutput()
	if err != nil {
		return false, "", fmt.Errorf("inspect Windows process %d: %w: %s", pid, err, strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) == "" {
		return false, "process is no longer running", nil
	}

	var identity windowsProcessIdentity
	if err := json.Unmarshal(out, &identity); err != nil {
		return false, "", fmt.Errorf("decode Windows process %d: %w", pid, err)
	}
	description := strings.TrimSpace(identity.Name + " " + identity.CommandLine)
	return isRampartServeCommandForExecutable(identity.Name, identity.CommandLine, serveExecutableForPID(pid)), description, nil
}

func terminateRampartServeProcess(proc *os.Process) error {
	return proc.Kill()
}
