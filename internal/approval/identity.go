// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package approval

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/internal/securefile"
)

const privatePendingStatus = "pending-v3"

// initializeIdentityKey shares a durable key across Store instances. The key
// protects credential-bearing fingerprints from offline guessing using only
// a copied journal. It is not encryption or protection from a same-user host.
func (s *Store) initializeIdentityKey() error {
	if s.persistFile == "" {
		_, err := rand.Read(s.identityKey[:])
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.persistFile), 0o700); err != nil {
		return err
	}
	return filetxn.WithLock(s.persistFile, func() error {
		key, err := readIdentityKey(s.persistFile + ".identity-key")
		if err == nil {
			copy(s.identityKey[:], key)
			return s.retireLegacyReplayGrantsLocked()
		}
		if !os.IsNotExist(err) {
			return err
		}
		// Key loss must not silently rotate identity and strand durable grants.
		if err := s.requireLegacyIdentityStateLocked(); err != nil {
			return err
		}
		if _, err := rand.Read(s.identityKey[:]); err != nil {
			return err
		}
		if err := writeExclusiveFile(s.persistFile+".identity-key", s.identityKey[:]); err != nil {
			return err
		}
		return s.retireLegacyReplayGrantsLocked()
	})
}

func readIdentityKey(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("approval: identity key is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := securefile.SingleLink(f); err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) || !os.SameFile(opened, after) || after.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("approval: identity key changed while opening")
	}
	if err := securefile.OwnerOnlyFile(f); err != nil {
		return nil, err
	}
	key, err := io.ReadAll(io.LimitReader(f, sha256.Size+1))
	if err != nil {
		return nil, err
	}
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("approval: identity key must contain 32 bytes")
	}
	after, err = os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("approval: identity key changed while reading")
	}
	if err := securefile.SingleLink(f); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Store) checkIdentityKey() error {
	if s.identityErr != nil {
		return s.identityErr
	}
	if s.persistFile == "" {
		return nil
	}
	key, err := readIdentityKey(s.persistFile + ".identity-key")
	if err != nil {
		return fmt.Errorf("approval: identity key unavailable: %w", err)
	}
	if !hmac.Equal(key, s.identityKey[:]) {
		return fmt.Errorf("approval: identity key changed; refusing authorization")
	}
	return nil
}

func (s *Store) keyedIdentity(key string) string {
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, s.identityKey[:])
	_, _ = mac.Write([]byte("rampart-approval-v3\x00" + key))
	return "v3-" + hex.EncodeToString(mac.Sum(nil))
}

// requireLegacyIdentityStateLocked permits first-time key creation only for
// pre-v3 state. Any v3 journal record or replay artifact makes key recovery an
// explicit operator action. The scan remains bounded, including stale state.
func (s *Store) requireLegacyIdentityStateLocked() error {
	if err := secureExistingApprovalFile(s.persistFile); err == nil {
		f, err := os.Open(s.persistFile)
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), maxApprovalRecordBytes)
		var bytesRead int64
		var records int
		for scanner.Scan() {
			bytesRead += int64(len(scanner.Bytes()) + 1)
			records++
			if bytesRead > maxApprovalJournalBytes || records > maxApprovalJournalRecords {
				return fmt.Errorf("approval: identity migration journal exceeds limit")
			}
			var rec persistRecord
			if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
				return fmt.Errorf("approval: cannot establish legacy identity state")
			}
			if rec.Version >= 3 || rec.Status == privatePendingStatus || strings.HasPrefix(rec.Fingerprint, "v3-") {
				return fmt.Errorf("approval: existing v3 state requires its original identity key")
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	err := walkApprovalStateDir(s.persistFile+".approved-once", maxPersistedReplayStateEntries, func(entry os.DirEntry) error {
		if strings.HasPrefix(entry.Name(), "v3-") {
			return fmt.Errorf("approval: existing v3 replay state requires its original identity key")
		}
		return nil
	})
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// retireLegacyReplayGrantsLocked writes the same durable consumed tombstone
// understood by older binaries before removing old grants. A crash can require
// fresh approval, but cannot resurrect a legacy allowance after a downgrade.
// The journal lock serializes upgrade; mixed-version service writers must be
// stopped before upgrading the shared state.
func (s *Store) retireLegacyReplayGrantsLocked() error {
	dir := s.persistFile + ".approved-once"
	err := walkApprovalStateDir(dir, maxPersistedReplayStateEntries, func(entry os.DirEntry) error {
		name := entry.Name()
		if !strings.HasSuffix(name, ".ready") && !strings.HasSuffix(name, ".json") {
			return nil
		}
		key := strings.TrimSuffix(strings.TrimSuffix(name, ".ready"), ".json")
		digest := strings.TrimPrefix(key, "v2-")
		if len(digest) != sha256.Size*2 {
			return nil
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return nil
		}
		data, ready, consumed := s.replayGrantPaths(key)
		if err := writeExclusiveFile(consumed, []byte("retired during approval identity upgrade\n")); err != nil && !os.IsExist(err) {
			return fmt.Errorf("approval: retire legacy grant: %w", err)
		}
		for _, path := range []string{ready, data} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	})
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return filetxn.SyncDir(dir)
}
