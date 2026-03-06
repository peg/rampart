// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package token

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCreateAndLookup(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, tok, err := store.Create("codex", "paranoid", "test token", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if tok.Agent != "codex" {
		t.Errorf("expected agent codex, got %q", tok.Agent)
	}
	if tok.Policy != "paranoid" {
		t.Errorf("expected policy paranoid, got %q", tok.Policy)
	}
	if !tok.HasScope(ScopeEval) {
		t.Error("expected eval scope by default")
	}
	if tok.HasScope(ScopeAdmin) {
		t.Error("should not have admin scope by default")
	}
	if tok.Hash == "" {
		t.Error("hash should be set")
	}
	if tok.Hash == plaintext {
		t.Error("hash should not equal plaintext")
	}

	// Lookup by full plaintext ID.
	result := store.Lookup(plaintext)
	if !result.Found {
		t.Fatal("token not found by lookup")
	}
	if result.Token.Agent != "codex" {
		t.Errorf("lookup returned wrong agent: %q", result.Token.Agent)
	}

	// Lookup with wrong ID.
	result = store.Lookup("rampart_nonexistent")
	if result.Found {
		t.Error("expected no match for nonexistent token")
	}
}

func TestHashedStorage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	store, _ := NewStore(path)

	plaintext, _, err := store.Create("codex", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Read file and verify plaintext is NOT in it.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if contains(content, plaintext) {
		t.Error("plaintext token should not appear in stored file")
	}
	if !contains(content, "hash") {
		t.Error("stored file should contain hash field")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		findSubstring(s, substr))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestCreateRequiresAgent(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	_, _, err := store.Create("", "", "", nil, nil)
	if err == nil {
		t.Error("expected error for empty agent")
	}
}

func TestCreateInvalidAgentName(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	_, _, err := store.Create("bad agent!", "", "", nil, nil)
	if err == nil {
		t.Error("expected error for invalid agent name")
	}

	_, _, err = store.Create("very-long-name-that-exceeds-the-sixty-four-character-limit-for-agent-names", "", "", nil, nil)
	if err == nil {
		t.Error("expected error for too-long agent name")
	}
}

func TestCreateInvalidScope(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	_, _, err := store.Create("codex", "", "", []string{"bogus"}, nil)
	if err == nil {
		t.Error("expected error for invalid scope")
	}
}

func TestRevoke(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	plaintext, tok, _ := store.Create("codex", "", "", nil, nil)

	n, err := store.Revoke(tok.MaskedID())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 revoked, got %d", n)
	}

	// Lookup should return revoked status.
	result := store.Lookup(plaintext)
	if !result.Found {
		t.Error("revoked token should still be found")
	}
	if !result.Revoked {
		t.Error("result should indicate revoked")
	}
}

func TestExpiredToken(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	past := time.Now().Add(-time.Hour)
	plaintext, _, _ := store.Create("codex", "", "", nil, &past)

	result := store.Lookup(plaintext)
	if !result.Found {
		t.Error("expired token should still be found")
	}
	if !result.Expired {
		t.Error("result should indicate expired")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	store1, _ := NewStore(path)
	plaintext, _, _ := store1.Create("codex", "standard", "persist test", nil, nil)

	// Open a new store from the same file.
	store2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	result := store2.Lookup(plaintext)
	if !result.Found {
		t.Fatal("token not found after reload")
	}
	if result.Token.Note != "persist test" {
		t.Errorf("expected note 'persist test', got %q", result.Token.Note)
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not supported on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	store, _ := NewStore(path)
	store.Create("codex", "", "", nil, nil)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected 0600 permissions, got %o", perm)
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	store.Create("codex", "", "", nil, nil)
	store.Create("claude-code", "", "", nil, nil)

	tokens := store.List()
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestCount(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	store.Create("codex", "", "", nil, nil)
	_, tok, _ := store.Create("claude-code", "", "", nil, nil)
	store.Revoke(tok.MaskedID())

	if store.Count() != 1 {
		t.Errorf("expected 1 active, got %d", store.Count())
	}
}

func TestMaskedID(t *testing.T) {
	tok := Token{MaskedPrefix: "abcdef12"}
	masked := tok.MaskedID()
	if masked != "rampart_abcdef12..." {
		t.Errorf("unexpected masked ID: %q", masked)
	}
}

func TestNewStoreNonexistentFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "does-not-exist.json"))
	if err != nil {
		t.Fatal("should not error on nonexistent file")
	}
	if store.Count() != 0 {
		t.Error("new store should be empty")
	}
}

func TestAdminScope(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	_, tok, _ := store.Create("admin-agent", "", "", []string{ScopeEval, ScopeAdmin}, nil)
	if !tok.HasScope(ScopeAdmin) {
		t.Error("expected admin scope")
	}
	if !tok.HasScope(ScopeEval) {
		t.Error("expected eval scope")
	}
}

func TestAutoReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	// Create store1 (simulates the server).
	store1, _ := NewStore(path)
	plaintext, _, _ := store1.Create("codex", "", "", nil, nil)

	// Verify it's found.
	result := store1.Lookup(plaintext)
	if !result.Found {
		t.Fatal("token should be found initially")
	}

	// Small delay to ensure mtime differs (filesystem granularity).
	time.Sleep(50 * time.Millisecond)

	// Create store2 (simulates CLI) and revoke.
	store2, _ := NewStore(path)
	store2.Revoke(Prefix + result.Token.MaskedPrefix)

	// store1 should auto-reload and see the revocation.
	result = store1.Lookup(plaintext)
	if !result.Revoked {
		t.Error("token should be revoked after auto-reload")
	}
}
