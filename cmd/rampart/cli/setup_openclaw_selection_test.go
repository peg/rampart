// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetupOpenClawDefaultSelectionFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenClaw setup is unsupported on Windows")
	}
	originalDetect := detectOpenClawVersionForSetup
	originalPlugin := runSetupOpenClawPluginForSetup
	t.Cleanup(func() {
		detectOpenClawVersionForSetup = originalDetect
		runSetupOpenClawPluginForSetup = originalPlugin
	})
	runSetupOpenClawPluginForSetup = func(_, _ io.Writer) error {
		t.Fatal("native plugin setup must not run when version selection fails")
		return nil
	}

	for _, testCase := range []struct {
		name    string
		version string
		err     error
		want    string
	}{
		{name: "detection failure", err: errors.New("version command failed"), want: "version detection failed"},
		{name: "unparseable version", version: "development", want: "cannot safely compare"},
		{name: "legacy version", version: "2026.3.27", want: "native protection requires"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			detectOpenClawVersionForSetup = func() (string, error) { return testCase.version, testCase.err }
			cmd := newSetupOpenClawCmd(&rootOptions{})
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("setup error = %v, want %q", err, testCase.want)
			}
			for _, flag := range []string{"--shim-only", "--no-preload", "--patch-tools"} {
				if !strings.Contains(err.Error(), flag) {
					t.Fatalf("setup error %q lacks explicit legacy guidance %s", err, flag)
				}
			}
		})
	}
}

func TestSetupOpenClawDefaultSelectionUsesModernNativePlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenClaw setup is unsupported on Windows")
	}
	originalDetect := detectOpenClawVersionForSetup
	originalPlugin := runSetupOpenClawPluginForSetup
	t.Cleanup(func() {
		detectOpenClawVersionForSetup = originalDetect
		runSetupOpenClawPluginForSetup = originalPlugin
	})
	detectOpenClawVersionForSetup = func() (string, error) { return "2026.7.1-2", nil }
	pluginCalled := false
	runSetupOpenClawPluginForSetup = func(_, _ io.Writer) error {
		pluginCalled = true
		return nil
	}

	cmd := newSetupOpenClawCmd(&rootOptions{})
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup openclaw: %v", err)
	}
	if !pluginCalled || !strings.Contains(out.String(), "using native plugin integration") {
		t.Fatalf("modern default did not select native plugin: called=%v output=%q", pluginCalled, out.String())
	}
}

func TestSetupOpenClawExplicitLegacyFlagSkipsVersionSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenClaw setup is unsupported on Windows")
	}
	home := t.TempDir()
	testSetHome(t, home)
	shimPath := filepath.Join(home, ".local", "bin", "rampart-shim")
	if err := os.MkdirAll(filepath.Dir(shimPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shimPath, []byte("managed legacy fixture"), 0o700); err != nil {
		t.Fatal(err)
	}

	originalDetect := detectOpenClawVersionForSetup
	t.Cleanup(func() { detectOpenClawVersionForSetup = originalDetect })
	detectCalled := false
	detectOpenClawVersionForSetup = func() (string, error) {
		detectCalled = true
		return "", errors.New("must not be called")
	}

	cmd := newSetupOpenClawCmd(&rootOptions{})
	cmd.SetArgs([]string{"--patch-tools"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	_ = cmd.Execute()
	if detectCalled {
		t.Fatal("explicit legacy compatibility flag invoked automatic version selection")
	}
}
