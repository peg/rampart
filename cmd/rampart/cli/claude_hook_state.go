// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type claudeHookLoadAssessment struct {
	Blocked    bool
	Unverified bool
	Reason     string
}

type claudeHookControls struct {
	disableAllHooks       *bool
	disableAllHooksSource string
	allowManagedOnly      *bool
	allowManagedSource    string
}

var claudeManagedSettingsDirResolver = claudeManagedSettingsDir

func claudeHookLoadAssessmentForHome(home string) claudeHookLoadAssessment {
	workingDir, err := os.Getwd()
	if err != nil {
		return claudeHookLoadAssessment{Unverified: true, Reason: "could not resolve the current directory to inspect Claude project settings"}
	}
	return assessClaudeHookLoading(home, workingDir, claudeManagedSettingsDirResolver())
}

func assessClaudeHookLoading(home, workingDir, managedDir string) claudeHookLoadAssessment {
	managed, err := readClaudeManagedHookControls(managedDir)
	if err != nil {
		return claudeHookLoadAssessment{Unverified: true, Reason: err.Error()}
	}
	if managed.allowManagedOnly != nil && *managed.allowManagedOnly {
		return claudeHookLoadAssessment{
			Blocked: true,
			Reason:  fmt.Sprintf("%s sets allowManagedHooksOnly=true, so Claude Code will not load Rampart's user hook", managed.allowManagedSource),
		}
	}
	if managed.disableAllHooks != nil {
		if *managed.disableAllHooks {
			return claudeHookLoadAssessment{
				Blocked: true,
				Reason:  fmt.Sprintf("%s sets disableAllHooks=true", managed.disableAllHooksSource),
			}
		}
		// Managed scalar settings outrank user and project settings. An explicit
		// managed false therefore establishes that lower disableAllHooks values
		// do not suppress hooks.
		return claudeHookLoadAssessment{}
	}
	userSettingsPath := claudeSettingsPath(home)
	controls, _, readErr := readClaudeHookControlsFile(userSettingsPath, false)
	if readErr != nil {
		return claudeHookLoadAssessment{Unverified: true, Reason: readErr.Error()}
	}
	projectControls, assessment := readClaudeProjectHookControls(workingDir, userSettingsPath)
	if assessment.Unverified {
		return assessment
	}
	if projectControls.disableAllHooks != nil {
		controls.disableAllHooks = projectControls.disableAllHooks
		controls.disableAllHooksSource = projectControls.disableAllHooksSource
	}
	if controls.disableAllHooks != nil && *controls.disableAllHooks {
		return claudeHookLoadAssessment{
			Blocked: true,
			Reason:  fmt.Sprintf("%s sets disableAllHooks=true", controls.disableAllHooksSource),
		}
	}
	return claudeHookLoadAssessment{}
}

// readClaudeProjectHookControls walks the current directory and its parents,
// matching Claude Code's documented project-settings discovery. Local settings
// override shared settings within one directory. If multiple ancestor scopes
// explicitly conflict, Rampart reports unverified instead of guessing an
// undocumented precedence between nested project roots.
func readClaudeProjectHookControls(workingDir, userSettingsPath string) (claudeHookControls, claudeHookLoadAssessment) {
	var effective claudeHookControls
	dir, err := filepath.Abs(workingDir)
	if err != nil {
		return effective, claudeHookLoadAssessment{Unverified: true, Reason: "could not normalize the current directory to inspect Claude project settings"}
	}
	for {
		var scoped claudeHookControls
		for _, path := range []string{
			filepath.Join(dir, ".claude", "settings.json"),
			filepath.Join(dir, ".claude", "settings.local.json"),
		} {
			if samePath(path, userSettingsPath) {
				continue
			}
			fileControls, present, readErr := readClaudeHookControlsFile(path, false)
			if readErr != nil {
				return effective, claudeHookLoadAssessment{Unverified: true, Reason: readErr.Error()}
			}
			if present && fileControls.disableAllHooks != nil {
				scoped.disableAllHooks = fileControls.disableAllHooks
				scoped.disableAllHooksSource = fileControls.disableAllHooksSource
			}
		}
		if scoped.disableAllHooks != nil {
			if effective.disableAllHooks != nil && *effective.disableAllHooks != *scoped.disableAllHooks {
				return effective, claudeHookLoadAssessment{
					Unverified: true,
					Reason: fmt.Sprintf("conflicting disableAllHooks values in Claude project settings at %s and %s",
						effective.disableAllHooksSource, scoped.disableAllHooksSource),
				}
			}
			if effective.disableAllHooks == nil {
				effective = scoped
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return effective, claudeHookLoadAssessment{}
}

func readClaudeManagedHookControls(dir string) (claudeHookControls, error) {
	var merged claudeHookControls
	if strings.TrimSpace(dir) == "" {
		return merged, nil
	}
	base := filepath.Join(dir, "managed-settings.json")
	controls, _, err := readClaudeHookControlsFile(base, true)
	if err != nil {
		return merged, err
	}
	mergeClaudeHookControls(&merged, controls)

	dropInDir := filepath.Join(dir, "managed-settings.d")
	entries, err := os.ReadDir(dropInDir)
	if err != nil {
		if os.IsNotExist(err) {
			return merged, nil
		}
		return merged, fmt.Errorf("inspect Claude managed settings drop-ins at %s: %w", dropInDir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		path := filepath.Join(dropInDir, name)
		controls, _, readErr := readClaudeHookControlsFile(path, true)
		if readErr != nil {
			return merged, readErr
		}
		mergeClaudeHookControls(&merged, controls)
	}
	return merged, nil
}

func mergeClaudeHookControls(dst *claudeHookControls, src claudeHookControls) {
	if src.disableAllHooks != nil {
		dst.disableAllHooks = src.disableAllHooks
		dst.disableAllHooksSource = src.disableAllHooksSource
	}
	if src.allowManagedOnly != nil {
		dst.allowManagedOnly = src.allowManagedOnly
		dst.allowManagedSource = src.allowManagedSource
	}
}

func readClaudeHookControlsFile(path string, managed bool) (claudeHookControls, bool, error) {
	var controls claudeHookControls
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return controls, false, nil
		}
		return controls, false, fmt.Errorf("read Claude settings at %s: %w", path, err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(data, &settings); err != nil {
		return controls, true, fmt.Errorf("parse Claude settings at %s: %w", path, err)
	}
	if raw, ok := settings["disableAllHooks"]; ok {
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return controls, true, fmt.Errorf("invalid Claude setting disableAllHooks at %s: expected boolean", path)
		}
		controls.disableAllHooks = &value
		controls.disableAllHooksSource = path
	}
	if managed {
		if raw, ok := settings["allowManagedHooksOnly"]; ok {
			var value bool
			if err := json.Unmarshal(raw, &value); err != nil {
				return controls, true, fmt.Errorf("invalid Claude setting allowManagedHooksOnly at %s: expected boolean", path)
			}
			controls.allowManagedOnly = &value
			controls.allowManagedSource = path
		}
	}
	return controls, true, nil
}

func claudeManagedSettingsDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(string(os.PathSeparator), "Library", "Application Support", "ClaudeCode")
	case "linux":
		return filepath.Join(string(os.PathSeparator), "etc", "claude-code")
	case "windows":
		programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		return filepath.Join(programFiles, "ClaudeCode")
	default:
		return ""
	}
}
