// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package token

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAndLookup(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}

	tok, err := store.Create("codex", "paranoid", "test token", nil, time.Time{})
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

	// Lookup by full ID.
	found, ok := store.Lookup(tok.ID)
	if !ok {
		t.Fatal("token not found by lookup")
	}
	if found.Agent != "codex" {
		t.Errorf("lookup returned wrong agent: %q", found.Agent)
	}

	// Lookup with wrong ID.
	_, ok = store.Lookup("rampart_nonexistent")
	if ok {
		t.Error("expected no match for nonexistent token")
	}
}

func TestCreateRequiresAgent(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Create("", "", "", nil, time.Time{})
	if err == nil {
		t.Error("expected error for empty agent")
	}
}

func TestCreateInvalidScope(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Create("codex", "", "", []string{"bogus"}, time.Time{})
	if err == nil {
		t.Error("expected error for invalid scope")
	}
}

func TestRevoke(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}

	tok, _ := store.Create("codex", "", "", nil, time.Time{})

	n, err := store.Revoke(tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 revoked, got %d", n)
	}

	// Lookup should fail for revoked token.
	_, ok := store.Lookup(tok.ID)
	if ok {
		t.Error("revoked token should not be found")
	}

	// Double revoke should error.
	_, err = store.Revoke(tok.ID)
	if err == nil {
		t.Error("expected error revoking already-revoked token")
	}
}

func TestExpiredToken(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}

	tok, _ := store.Create("codex", "", "", nil, time.Now().Add(-time.Hour))

	_, ok := store.Lookup(tok.ID)
	if ok {
		t.Error("expired token should not be found")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	store1, _ := NewStore(path)
	tok, _ := store1.Create("codex", "standard", "persist test", nil, time.Time{})

	// Open a new store from the same file.
	store2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	found, ok := store2.Lookup(tok.ID)
	if !ok {
		t.Fatal("token not found after reload")
	}
	if found.Note != "persist test" {
		t.Errorf("expected note 'persist test', got %q", found.Note)
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	store, _ := NewStore(path)
	store.Create("codex", "", "", nil, time.Time{})

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

	store.Create("codex", "", "", nil, time.Time{})
	store.Create("claude-code", "", "", nil, time.Time{})

	tokens := store.List()
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestCount(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	store.Create("codex", "", "", nil, time.Time{})
	tok, _ := store.Create("claude-code", "", "", nil, time.Time{})
	store.Revoke(tok.ID)

	if store.Count() != 1 {
		t.Errorf("expected 1 active, got %d", store.Count())
	}
}

func TestFindByPrefix(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "tokens.json"))

	tok, _ := store.Create("codex", "", "", nil, time.Time{})

	// Prefix of first 16 chars should match.
	matches := store.FindByPrefix(tok.ID[:16])
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}

	// Nonexistent prefix.
	matches = store.FindByPrefix("rampart_zzzzz")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestMaskedID(t *testing.T) {
	tok := Token{ID: "rampart_abcdef1234567890abcdef1234567890abcdef12345678"}
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

	tok, _ := store.Create("admin-agent", "", "", []string{ScopeEval, ScopeAdmin}, time.Time{})
	if !tok.HasScope(ScopeAdmin) {
		t.Error("expected admin scope")
	}
	if !tok.HasScope(ScopeEval) {
		t.Error("expected eval scope")
	}
}
