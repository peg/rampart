// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	opencodeplugin "github.com/peg/rampart/internal/plugin/opencode"
	"github.com/peg/rampart/internal/securefile"
	"github.com/spf13/cobra"
)

func newSetupOpenCodeCmd() *cobra.Command {
	var remove bool
	cmd := &cobra.Command{
		Use:   "opencode",
		Short: "Install Rampart's experimental OpenCode policy plugin",
		Long: `Installs the dependency-free Rampart plugin as plugins/rampart.js in
$OPENCODE_CONFIG_DIR, or $XDG_CONFIG_HOME/opencode (normally ~/.config/opencode).
OpenCode discovers global JavaScript plugins without changing provider settings.

This integration currently supports Linux and macOS. Shell tool calls require
a supported POSIX shell (sh, bash, zsh, dash, or ksh).

The experimental plugin evaluates tool calls exposed through OpenCode's
pre-execution hook. Ask decisions refuse execution; native approval/resume is
not supported. This installer does not verify that OpenCode loaded the plugin.
Restart OpenCode after installation or removal.

Existing unrelated plugins and configuration remain untouched. A same-name
file without Rampart's ownership header is never replaced.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup opencode: resolve home: %w", err)
			}
			path := openCodePluginPath(home)
			if remove {
				removed, err := removeOpenCodePlugin(path)
				if err != nil {
					return err
				}
				if !removed {
					fmt.Fprintln(cmd.OutOrStdout(), "No Rampart OpenCode plugin found. Nothing to remove.")
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Removed Rampart OpenCode plugin from %s\n", path)
				fmt.Fprintln(cmd.OutOrStdout(), "Restart OpenCode to unload the removed plugin.")
				return nil
			}
			if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
				return fmt.Errorf("setup opencode: experimental integration supports Linux and macOS")
			}
			if err := installOpenCodePlugin(path, resolveRampartHookBinary()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed experimental Rampart OpenCode plugin at %s\n", path)
			fmt.Fprintln(cmd.OutOrStdout(), "Restart OpenCode to load it. Host loading has not been verified.")
			fmt.Fprintln(cmd.OutOrStdout(), "Ask decisions refuse execution; native approval/resume is not supported.")
			fmt.Fprintln(cmd.OutOrStdout(), "Uninstall: rampart setup opencode --remove")
			return nil
		},
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove only the Rampart-owned OpenCode plugin file")
	return cmd
}

func openCodeConfigDir(home string) string {
	// OpenCode reads this path directly; shell/environment expansion would bind
	// a plugin to a directory that the host does not actually discover.
	if configured := os.Getenv("OPENCODE_CONFIG_DIR"); configured != "" {
		return filepath.Clean(configured)
	}
	if configured := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(configured) {
		return filepath.Join(configured, "opencode")
	}
	return filepath.Join(home, ".config", "opencode")
}

func openCodePluginPath(home string) string {
	return filepath.Join(openCodeConfigDir(home), "plugins", "rampart.js")
}

// checkOpenCodePluginDirs avoids following a linked config root or plugin
// directory. It never removes, changes permissions on, or rewrites either.
func checkOpenCodePluginDirs(path string) error {
	pluginDir := filepath.Dir(path)
	for _, dir := range []string{filepath.Dir(pluginDir), pluginDir} {
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect OpenCode plugin directory %s: %w", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("refusing linked or non-directory OpenCode plugin directory %s", dir)
		}
	}
	return nil
}

func readOpenCodePlugin(path string) ([]byte, bool, error) {
	if err := checkOpenCodePluginDirs(path); err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect OpenCode plugin: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("refusing linked or non-regular OpenCode plugin file %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("read OpenCode plugin: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, fmt.Errorf("OpenCode plugin changed while inspecting %s", path)
	}
	if err := securefile.SingleLink(file); err != nil {
		return nil, false, fmt.Errorf("refusing hard-linked OpenCode plugin file %s: %w", path, err)
	}
	// Plugins are small text files. Avoid reading an arbitrary collision into
	// memory merely to determine whether it belongs to this integration.
	const maxPluginSize = 1 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxPluginSize+1))
	if err != nil {
		return nil, false, fmt.Errorf("read OpenCode plugin: %w", err)
	}
	if len(data) > maxPluginSize {
		return nil, false, fmt.Errorf("OpenCode plugin file exceeds ownership inspection limit")
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, current) {
		return nil, false, fmt.Errorf("OpenCode plugin changed while inspecting %s", path)
	}
	return data, true, nil
}

func installOpenCodePlugin(path, binary string) error {
	source, err := opencodeplugin.Render(binary)
	if err != nil {
		return fmt.Errorf("setup opencode: %w", err)
	}
	data, exists, err := readOpenCodePlugin(path)
	if err != nil {
		return fmt.Errorf("setup opencode: %w", err)
	}
	if exists && !opencodeplugin.Managed(data) {
		return fmt.Errorf("setup opencode: refusing to replace non-Rampart plugin file %s", path)
	}
	if err := atomicWritePrivateFile(path, source); err != nil {
		return fmt.Errorf("setup opencode: write plugin: %w", err)
	}
	return nil
}

func removeOpenCodePlugin(path string) (bool, error) {
	data, exists, err := readOpenCodePlugin(path)
	if err != nil || !exists {
		return false, err
	}
	if !opencodeplugin.Managed(data) {
		return false, fmt.Errorf("setup opencode: refusing to remove non-Rampart plugin file %s", path)
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("setup opencode: remove plugin: %w", err)
	}
	return true, nil
}

func openCodePluginConfiguredForHome(home string) bool {
	data, exists, err := readOpenCodePlugin(openCodePluginPath(home))
	if err != nil || !exists {
		return false
	}
	want, err := opencodeplugin.Render(resolveRampartHookBinary())
	return err == nil && bytes.Equal(data, want)
}
