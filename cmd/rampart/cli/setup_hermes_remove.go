// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	hermesplugin "github.com/peg/rampart/internal/plugin/hermes"
	"gopkg.in/yaml.v3"
)

func hermesPluginManaged(pluginDir string) bool {
	return hermesplugin.Managed(pluginDir)
}

func yamlMappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func yamlRemoveMappingKey(node *yaml.Node, key string) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value != key {
			continue
		}
		node.Content = append(node.Content[:i], node.Content[i+2:]...)
		return true
	}
	return false
}

func yamlRemoveSequenceValue(node *yaml.Node, value string) bool {
	if node == nil || node.Kind != yaml.SequenceNode {
		return false
	}
	changed := false
	kept := node.Content[:0]
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode && item.Value == value {
			changed = true
			continue
		}
		kept = append(kept, item)
	}
	node.Content = kept
	return changed
}

func yamlSequenceContains(node *yaml.Node, value string) bool {
	if node == nil || node.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode && item.Value == value {
			return true
		}
	}
	return false
}

func hermesConfigReferencesRampart(configPath string) (bool, error) {
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("setup hermes: read config %s: %w", configPath, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return false, fmt.Errorf("setup hermes: parse config %s: %w", configPath, err)
	}
	if len(document.Content) == 0 {
		return false, nil
	}
	plugins := yamlMappingValue(document.Content[0], "plugins")
	if plugins == nil {
		return false, nil
	}
	return yamlSequenceContains(yamlMappingValue(plugins, "enabled"), "rampart") ||
		yamlSequenceContains(yamlMappingValue(plugins, "disabled"), "rampart") ||
		yamlMappingValue(yamlMappingValue(plugins, "entries"), "rampart") != nil, nil
}

func removeHermesRampartConfig(configPath string) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("setup hermes: read config %s: %w", configPath, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return false, fmt.Errorf("setup hermes: parse config %s: %w", configPath, err)
	}
	if len(document.Content) == 0 {
		return false, nil
	}
	plugins := yamlMappingValue(document.Content[0], "plugins")
	if plugins == nil {
		return false, nil
	}
	changed := yamlRemoveSequenceValue(yamlMappingValue(plugins, "enabled"), "rampart")
	if yamlRemoveSequenceValue(yamlMappingValue(plugins, "disabled"), "rampart") {
		changed = true
	}
	if yamlRemoveMappingKey(yamlMappingValue(plugins, "entries"), "rampart") {
		changed = true
	}
	if !changed {
		return false, nil
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return false, fmt.Errorf("setup hermes: marshal config %s: %w", configPath, err)
	}
	if err := encoder.Close(); err != nil {
		return false, fmt.Errorf("setup hermes: finish config %s: %w", configPath, err)
	}
	if err := atomicWritePrivateFile(configPath, out.Bytes()); err != nil {
		return false, fmt.Errorf("setup hermes: write config %s: %w", configPath, err)
	}
	return true, nil
}

func removeHermesIntegration(pluginDir, hermesHome string) (bool, error) {
	pluginPresent := false
	if info, err := os.Lstat(pluginDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("setup hermes: refusing to remove symlinked plugin directory %s", pluginDir)
		}
		if !info.IsDir() {
			return false, fmt.Errorf("setup hermes: refusing to remove non-directory plugin path %s", pluginDir)
		}
		_, manifestErr := os.Stat(filepath.Join(pluginDir, "plugin.yaml"))
		_, runtimeErr := os.Stat(filepath.Join(pluginDir, "__init__.py"))
		if manifestErr != nil && !os.IsNotExist(manifestErr) {
			return false, fmt.Errorf("setup hermes: inspect plugin manifest: %w", manifestErr)
		}
		if runtimeErr != nil && !os.IsNotExist(runtimeErr) {
			return false, fmt.Errorf("setup hermes: inspect plugin runtime: %w", runtimeErr)
		}
		managedFilesPresent := manifestErr == nil || runtimeErr == nil
		if managedFilesPresent && !hermesPluginManaged(pluginDir) {
			return false, fmt.Errorf("setup hermes: refusing to remove non-Rampart plugin directory %s", pluginDir)
		}
		pluginPresent = managedFilesPresent
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("setup hermes: inspect plugin directory %s: %w", pluginDir, err)
	}

	configPath := filepath.Join(hermesHome, "config.yaml")
	if !pluginPresent {
		configured, err := hermesConfigReferencesRampart(configPath)
		if err != nil {
			return false, err
		}
		if configured {
			return false, fmt.Errorf("setup hermes: refusing to remove config-only plugin ID rampart without a positively owned Rampart plugin directory")
		}
		return false, nil
	}

	_, err := removeHermesRampartConfig(configPath)
	if err != nil {
		return false, err
	}
	for _, name := range []string{"__init__.py", "plugin.yaml"} {
		path := filepath.Join(pluginDir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("setup hermes: remove managed plugin file %s: %w", path, err)
		}
	}
	// Remove only compiled copies of Rampart's own module. Any other files in
	// the directory are user-owned and keep the directory from being removed.
	cacheDir := filepath.Join(pluginDir, "__pycache__")
	for _, pattern := range []string{"__init__.*.pyc", "__init__.pyc"} {
		matches, _ := filepath.Glob(filepath.Join(cacheDir, pattern))
		for _, match := range matches {
			_ = os.Remove(match)
		}
	}
	_ = os.Remove(cacheDir)
	_ = os.Remove(pluginDir)
	return true, nil
}
