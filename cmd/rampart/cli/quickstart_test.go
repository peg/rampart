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
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDetectEnv_OpenClaw(t *testing.T) {
	t.Setenv("OPENCLAW_SERVICE_MARKER", "openclaw")
	if got := detectEnv(); got != "openclaw" {
		t.Errorf("expected openclaw, got %q", got)
	}
}

func TestDetectEnv_ClaudeCode(t *testing.T) {
	// Ensure OpenClaw marker is absent so Claude Code takes priority.
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")

	// Create a temp claude settings file
	tmp := t.TempDir()
	orig := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", orig)

	if err := os.MkdirAll(filepath.Join(tmp, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".claude", "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := detectEnv(); got != "claude-code" {
		t.Errorf("expected claude-code, got %q", got)
	}
}

func TestDetectEnv_None(t *testing.T) {
	// Ensure OpenClaw marker is absent.
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")

	tmp := t.TempDir()
	orig := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", orig)

	// Ensure 'claude' binary is not in PATH for this test.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	if got := detectEnv(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestDetectEnv_Cursor(t *testing.T) {
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")
	tmp := t.TempDir()
	orig := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", orig)

	// Ensure 'claude' binary is not found.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	// Create Cursor settings path.
	var cursorDir string
	if runtime.GOOS == "darwin" {
		cursorDir = filepath.Join(tmp, "Library", "Application Support", "Cursor", "User")
	} else {
		cursorDir = filepath.Join(tmp, ".config", "Cursor", "User")
	}
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cursorDir, "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := detectEnv(); got != "cursor" {
		t.Errorf("expected cursor, got %q", got)
	}
}

func TestDetectEnv_Windsurf(t *testing.T) {
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")
	tmp := t.TempDir()
	orig := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", orig)

	// Ensure 'claude' binary is not found and no Cursor settings exist.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	// Create Windsurf settings path.
	var windsurfDir string
	if runtime.GOOS == "darwin" {
		windsurfDir = filepath.Join(tmp, "Library", "Application Support", "Windsurf", "User")
	} else {
		windsurfDir = filepath.Join(tmp, ".config", "Windsurf", "User")
	}
	if err := os.MkdirAll(windsurfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(windsurfDir, "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := detectEnv(); got != "windsurf" {
		t.Errorf("expected windsurf, got %q", got)
	}
}

func TestDetectEnv_CursorBeatsWindsurf(t *testing.T) {
	// When both Cursor and Windsurf are installed, Cursor should win (checked first).
	t.Setenv("OPENCLAW_SERVICE_MARKER", "")
	tmp := t.TempDir()
	orig := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", orig)

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	// Create both settings files.
	var cursorDir, windsurfDir string
	if runtime.GOOS == "darwin" {
		cursorDir = filepath.Join(tmp, "Library", "Application Support", "Cursor", "User")
		windsurfDir = filepath.Join(tmp, "Library", "Application Support", "Windsurf", "User")
	} else {
		cursorDir = filepath.Join(tmp, ".config", "Cursor", "User")
		windsurfDir = filepath.Join(tmp, ".config", "Windsurf", "User")
	}
	for _, dir := range []string{cursorDir, windsurfDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if got := detectEnv(); got != "cursor" {
		t.Errorf("expected cursor (Cursor takes priority over Windsurf), got %q", got)
	}
}

func TestQuickstartCmd_Help(t *testing.T) {
	cmd := newQuickstartCmd()
	if cmd.Use != "quickstart" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}
	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}
}

func TestQuickstartCmd_Flags(t *testing.T) {
	cmd := newQuickstartCmd()

	envFlag := cmd.Flags().Lookup("env")
	if envFlag == nil {
		t.Fatal("--env flag not registered")
	}

	skipFlag := cmd.Flags().Lookup("skip-doctor")
	if skipFlag == nil {
		t.Fatal("--skip-doctor flag not registered")
	}
}
