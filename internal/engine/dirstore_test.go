// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirStore_LoadMultipleFiles(t *testing.T) {
	dir := t.TempDir()

	// Write two policy files.
	writeTestFile(t, filepath.Join(dir, "01-base.yaml"), `
version: "1"
default_action: deny
policies:
  - name: base-policy
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm *"]
        message: "no rm"
`)
	writeTestFile(t, filepath.Join(dir, "02-extra.yaml"), `
version: "1"
policies:
  - name: extra-policy
    match:
      tool: read
    rules:
      - action: allow
        when:
          default: true
`)

	store := NewDirStore(dir, nil)
	cfg, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, "deny", cfg.DefaultAction)
	assert.Len(t, cfg.Policies, 2)
	assert.Equal(t, "base-policy", cfg.Policies[0].Name)
	assert.Equal(t, "extra-policy", cfg.Policies[1].Name)
}

func TestDirStore_SortedOrder(t *testing.T) {
	dir := t.TempDir()

	// Write files in reverse order — should still load alphabetically.
	writeTestFile(t, filepath.Join(dir, "z-last.yaml"), `
version: "1"
policies:
  - name: z-policy
    match: {tool: exec}
    rules: [{action: allow, when: {default: true}}]
`)
	writeTestFile(t, filepath.Join(dir, "a-first.yaml"), `
version: "1"
policies:
  - name: a-policy
    match: {tool: exec}
    rules: [{action: allow, when: {default: true}}]
`)
	writeTestFile(t, filepath.Join(dir, "m-middle.yaml"), `
version: "1"
policies:
  - name: m-policy
    match: {tool: exec}
    rules: [{action: allow, when: {default: true}}]
`)

	store := NewDirStore(dir, nil)
	cfg, err := store.Load()
	require.NoError(t, err)
	require.Len(t, cfg.Policies, 3)
	assert.Equal(t, "a-policy", cfg.Policies[0].Name)
	assert.Equal(t, "m-policy", cfg.Policies[1].Name)
	assert.Equal(t, "z-policy", cfg.Policies[2].Name)
}

func TestDirStore_InvalidYAMLSkipped(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, filepath.Join(dir, "01-good.yaml"), `
version: "1"
default_action: allow
policies:
  - name: good-policy
    match: {tool: exec}
    rules: [{action: allow, when: {default: true}}]
`)
	writeTestFile(t, filepath.Join(dir, "02-bad.yaml"), `
this is not valid yaml: [[[
`)
	writeTestFile(t, filepath.Join(dir, "03-also-good.yaml"), `
version: "1"
policies:
  - name: also-good
    match: {tool: read}
    rules: [{action: allow, when: {default: true}}]
`)

	store := NewDirStore(dir, nil)
	cfg, err := store.Load()
	require.NoError(t, err)
	assert.Len(t, cfg.Policies, 2)
	assert.Equal(t, "good-policy", cfg.Policies[0].Name)
	assert.Equal(t, "also-good", cfg.Policies[1].Name)
}

func TestDirStore_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	store := NewDirStore(dir, nil)
	cfg, err := store.Load()
	require.NoError(t, err)
	assert.Empty(t, cfg.Policies)
}

func TestDirStore_NonexistentDir(t *testing.T) {
	store := NewDirStore("/tmp/rampart-nonexistent-dir-test-"+time.Now().Format("20060102150405"), nil)
	cfg, err := store.Load()
	require.NoError(t, err)
	assert.Empty(t, cfg.Policies)
}

func TestDirStore_DuplicatePolicyNamesSkipped(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, filepath.Join(dir, "01-first.yaml"), `
version: "1"
policies:
  - name: dupe-policy
    match: {tool: exec}
    rules: [{action: deny, when: {default: true}}]
`)
	writeTestFile(t, filepath.Join(dir, "02-second.yaml"), `
version: "1"
policies:
  - name: dupe-policy
    match: {tool: read}
    rules: [{action: allow, when: {default: true}}]
`)

	store := NewDirStore(dir, nil)
	cfg, err := store.Load()
	require.NoError(t, err)
	// First one wins.
	require.Len(t, cfg.Policies, 1)
	assert.Equal(t, "dupe-policy", cfg.Policies[0].Name)
}

func TestMultiStore_FileAndDir(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	mainFile := filepath.Join(dir, "rampart.yaml")
	writeTestFile(t, mainFile, `
version: "1"
default_action: deny
policies:
  - name: main-policy
    match: {tool: exec}
    rules:
      - action: deny
        when: {command_matches: ["rm *"]}
        message: "blocked"
`)
	writeTestFile(t, filepath.Join(policyDir, "auto-allowed.yaml"), `
version: "1"
policies:
  - name: auto-allow-git
    match: {tool: exec}
    rules:
      - action: allow
        when: {command_matches: ["git *"]}
`)

	store := NewMultiStore(mainFile, policyDir, nil)
	cfg, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, "deny", cfg.DefaultAction)
	assert.Len(t, cfg.Policies, 2)
	assert.Equal(t, "main-policy", cfg.Policies[0].Name)
	assert.Equal(t, "auto-allow-git", cfg.Policies[1].Name)
}

func TestMultiStore_DirOnly(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "policy.yaml"), `
version: "1"
default_action: allow
policies:
  - name: only-policy
    match: {tool: exec}
    rules: [{action: allow, when: {default: true}}]
`)

	store := NewMultiStore("", dir, nil)
	cfg, err := store.Load()
	require.NoError(t, err)
	assert.Len(t, cfg.Policies, 1)
}

func TestEngine_ReloadPicksUpNewRules(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	// No explicit exec policy — falls through to default deny.
	mainFile := filepath.Join(dir, "rampart.yaml")
	writeTestFile(t, mainFile, `
version: "1"
default_action: deny
policies:
  - name: base
    match: {tool: read}
    rules:
      - action: allow
        when: {default: true}
`)

	store := NewMultiStore(mainFile, policyDir, nil)
	eng, err := New(store, nil)
	require.NoError(t, err)

	// Should deny git commands (no exec policy, default deny).
	call := execCall("test", "git status")
	d := eng.Evaluate(call)
	assert.Equal(t, ActionDeny, d.Action)

	// Write auto-allowed rule.
	writeTestFile(t, filepath.Join(policyDir, "auto-allowed.yaml"), `
version: "1"
policies:
  - name: auto-allow-git
    match: {tool: exec}
    rules:
      - action: allow
        when: {command_matches: ["git *"]}
`)

	// Reload and verify.
	require.NoError(t, eng.Reload())
	d = eng.Evaluate(call)
	assert.Equal(t, ActionAllow, d.Action)
}

func TestEngine_PeriodicReload(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	// Use default_action: deny with NO explicit deny rules.
	// Tool calls with no matching rule fall through to default deny.
	// After reload, the auto-allow rule will match and allow.
	mainFile := filepath.Join(dir, "rampart.yaml")
	writeTestFile(t, mainFile, `
version: "1"
default_action: deny
policies:
  - name: base
    match: {tool: read}
    rules:
      - action: allow
        when: {default: true}
`)

	store := NewMultiStore(mainFile, policyDir, nil)
	eng, err := New(store, nil)
	require.NoError(t, err)

	// ls should be denied (no matching policy for exec, default deny).
	d := eng.Evaluate(execCall("test", "ls -la"))
	assert.Equal(t, ActionDeny, d.Action)

	// Start periodic reload with short interval.
	eng.StartPeriodicReload(100 * time.Millisecond)

	// Write auto-allowed rule.
	writeTestFile(t, filepath.Join(policyDir, "auto-allowed.yaml"), `
version: "1"
policies:
  - name: auto-allow-ls
    match: {tool: exec}
    rules:
      - action: allow
        when: {command_matches: ["ls *"]}
`)

	// Wait for reload to pick it up.
	assert.Eventually(t, func() bool {
		d := eng.Evaluate(execCall("test", "ls -la"))
		return d.Action == ActionAllow
	}, 2*time.Second, 50*time.Millisecond)

	eng.Stop()
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestMemoryStore_Load(t *testing.T) {
	t.Run("valid yaml", func(t *testing.T) {
		data := []byte(`
version: "1"
default_action: allow
policies:
  - name: test-policy
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
        message: "no rm -rf"
`)
		store := NewMemoryStore(data, "test:inline")
		cfg, err := store.Load()
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, "allow", cfg.DefaultAction)
		assert.Len(t, cfg.Policies, 1)
		assert.Equal(t, "test-policy", cfg.Policies[0].Name)
		assert.Equal(t, "test:inline", store.Path())
	})

	t.Run("invalid yaml returns error", func(t *testing.T) {
		store := NewMemoryStore([]byte("not: valid: yaml: :::"), "bad:yaml")
		_, err := store.Load()
		assert.Error(t, err)
	})

	t.Run("empty data returns empty config", func(t *testing.T) {
		store := NewMemoryStore([]byte(`version: "1"`), "empty")
		cfg, err := store.Load()
		require.NoError(t, err)
		assert.Empty(t, cfg.Policies)
	})
}

func TestMixedStore_Load(t *testing.T) {
	primaryYAML := []byte(`
version: "1"
default_action: deny
policies:
  - name: primary-policy
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm *"]
        message: "no rm"
`)

	t.Run("merges primary with directory files", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "extra.yaml"), `
version: "1"
policies:
  - name: extra-policy
    match:
      tool: read
    rules:
      - action: allow
        when:
          command_matches: ["*"]
        message: "allow all reads"
`)
		primary := NewMemoryStore(primaryYAML, "primary")
		store := NewMixedStore(primary, dir, nil)
		cfg, err := store.Load()
		require.NoError(t, err)
		assert.Equal(t, "deny", cfg.DefaultAction)
		assert.Len(t, cfg.Policies, 2)
		names := []string{cfg.Policies[0].Name, cfg.Policies[1].Name}
		assert.Contains(t, names, "primary-policy")
		assert.Contains(t, names, "extra-policy")
		assert.Contains(t, store.Path(), "primary")
	})

	t.Run("empty directory returns primary only", func(t *testing.T) {
		dir := t.TempDir()
		primary := NewMemoryStore(primaryYAML, "primary")
		store := NewMixedStore(primary, dir, nil)
		cfg, err := store.Load()
		require.NoError(t, err)
		assert.Len(t, cfg.Policies, 1)
		assert.Equal(t, "primary-policy", cfg.Policies[0].Name)
	})

	t.Run("nonexistent directory returns primary only", func(t *testing.T) {
		primary := NewMemoryStore(primaryYAML, "primary")
		store := NewMixedStore(primary, "/nonexistent/path/xyz", nil)
		cfg, err := store.Load()
		require.NoError(t, err)
		assert.Len(t, cfg.Policies, 1)
	})

	t.Run("skips duplicate policy names from directory", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "dup.yaml"), `
version: "1"
policies:
  - name: primary-policy
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["*"]
        message: "allow all"
`)
		primary := NewMemoryStore(primaryYAML, "primary")
		store := NewMixedStore(primary, dir, nil)
		cfg, err := store.Load()
		require.NoError(t, err)
		// Duplicate should be skipped — only 1 policy.
		assert.Len(t, cfg.Policies, 1)
		assert.Equal(t, "primary-policy", cfg.Policies[0].Name)
	})

	t.Run("empty dir path returns primary only", func(t *testing.T) {
		primary := NewMemoryStore(primaryYAML, "primary")
		store := NewMixedStore(primary, "", nil)
		cfg, err := store.Load()
		require.NoError(t, err)
		assert.Len(t, cfg.Policies, 1)
	})

	t.Run("primary load error propagates", func(t *testing.T) {
		primary := NewMemoryStore([]byte("not: valid: yaml: :::"), "bad")
		store := NewMixedStore(primary, t.TempDir(), nil)
		_, err := store.Load()
		assert.Error(t, err)
	})
}
