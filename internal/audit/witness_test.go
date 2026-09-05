// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peg/rampart/internal/filetxn"
	"github.com/stretchr/testify/require"
)

func witnessFixture(t *testing.T) (*Witness, *JSONLSink, string) {
	t.Helper()
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir, WithFsync(false), WithRotateSize(900), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })
	w, err := NewWitness(WitnessConfig{Version: 1, ChainID: "test-chain-identity", WitnessID: "independent-test-store", FileDirectory: t.TempDir()})
	require.NoError(t, err)
	return w, sink, dir
}

func writeWitnessEvent(t *testing.T, sink *JSONLSink) {
	t.Helper()
	require.NoError(t, sink.Write(Event{Tool: "exec", Agent: "private-agent-canary",
		Request: map[string]any{"command": "printf private-command-canary", "path": "/private-target-canary"}}))
}

func TestWitnessFilePrefixRestartRotationAndMetadataLoss(t *testing.T) {
	w, sink, dir := witnessFixture(t)
	for i := 0; i < 8; i++ {
		writeWitnessEvent(t, sink)
	}
	result, err := w.Publish(context.Background(), dir)
	require.NoError(t, err)
	require.True(t, result.Verified)
	require.Equal(t, "witnessed_head", result.Status)
	accepted, err := w.retrieveFileHistory(context.Background())
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		writeWitnessEvent(t, sink)
	}
	require.NoError(t, sink.Close())
	for _, name := range []string{sharedStateFilename, anchorFilename, filepath.Base(w.deliveryPath(dir))} {
		err := os.Remove(filepath.Join(dir, name))
		require.True(t, err == nil || os.IsNotExist(err))
	}
	restarted, err := NewWitness(w.config)
	require.NoError(t, err)
	result, err = restarted.Verify(context.Background(), dir)
	require.NoError(t, err)
	require.Equal(t, "witnessed_prefix", result.Status)
	require.EqualValues(t, 3, result.Unwitnessed)
	require.Equal(t, "unknown", result.Delivery)
	require.Equal(t, "separately_administered_storage", result.Authentication)
	files, err := managedAuditFiles(dir)
	require.NoError(t, err)
	require.Greater(t, len(files), 1)
	data, err := os.ReadFile(filepath.Join(w.config.FileDirectory, w.checkpointFilename(8)))
	require.NoError(t, err)
	for _, forbidden := range []string{"private-agent-canary", "private-command-canary", "private-target-canary", dir} {
		require.NotContains(t, string(data), forbidden)
	}
	require.True(t, accepted[0].AcceptedAt.IsZero(), "file publication must not invent an independent acceptance time")
}

func TestWitnessFileDuplicateConflictAndStaleness(t *testing.T) {
	w, sink, dir := witnessFixture(t)
	writeWitnessEvent(t, sink)
	_, err := w.Publish(context.Background(), dir)
	require.NoError(t, err)
	history, err := w.retrieveFileHistory(context.Background())
	require.NoError(t, err)
	first := history[0]
	duplicate := first.Checkpoint
	duplicate.CreatedAt = duplicate.CreatedAt.Add(time.Minute)
	again, err := w.publishFile(duplicate)
	require.NoError(t, err)
	require.Equal(t, first.Checkpoint.CreatedAt, again.Checkpoint.CreatedAt)
	duplicate.Hash = "sha256:" + strings.Repeat("a", 64)
	_, err = w.publishFile(duplicate)
	require.Equal(t, "conflict", WitnessCode(err))
	w.now = func() time.Time { return first.Checkpoint.CreatedAt.Add(25 * time.Hour) }
	result, err := w.Publish(context.Background(), dir)
	require.Equal(t, "stale_checkpoint", WitnessCode(err))
	require.False(t, result.Verified)
	require.Equal(t, "delivered", result.Delivery, "stale evidence is not failed delivery")
	// Ambiguous position spellings cannot hide a conflicting second record.
	require.NoError(t, os.WriteFile(filepath.Join(w.config.FileDirectory, w.config.ChainID+".1.json"), []byte("{}"), 0o600))
	_, err = w.retrieveFileHistory(context.Background())
	require.Equal(t, "conflict", WitnessCode(err))
}

func TestWitnessDetectsRemovedAndRewrittenLocalHistory(t *testing.T) {
	for _, rewrite := range []bool{false, true} {
		t.Run(fmt.Sprint(rewrite), func(t *testing.T) {
			w, sink, dir := witnessFixture(t)
			writeWitnessEvent(t, sink)
			writeWitnessEvent(t, sink)
			_, err := w.Publish(context.Background(), dir)
			require.NoError(t, err)
			require.NoError(t, sink.Close())
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			for _, entry := range entries {
				require.NoError(t, os.Remove(filepath.Join(dir, entry.Name())))
			}
			want := "witness_ahead"
			if rewrite {
				replacement, err := NewJSONLSink(dir, WithFsync(false))
				require.NoError(t, err)
				writeWitnessEvent(t, replacement)
				writeWitnessEvent(t, replacement)
				require.NoError(t, replacement.Close())
				count, err := VerifyManagedChain(dir)
				require.NoError(t, err)
				require.EqualValues(t, 2, count, "rewritten history passes local-only verification")
				want = "hash_mismatch"
			}
			result, err := w.Verify(context.Background(), dir)
			require.Equal(t, want, WitnessCode(err))
			require.False(t, result.Verified)
		})
	}
}

func TestWitnessSnapshotAllowsAppendsAndRejectsReplacement(t *testing.T) {
	_, sink, dir := witnessFixture(t)
	writeWitnessEvent(t, sink)
	snapshot, err := captureWitnessSnapshot(context.Background(), dir)
	require.NoError(t, err)
	checkpoints := map[int64]string{1: sink.lastHash}
	writeWitnessEvent(t, sink)
	state, err := snapshot.recover(context.Background(), checkpoints)
	require.NoError(t, err)
	require.EqualValues(t, 1, state.eventCount)
	require.NotEmpty(t, state.prefixHash)
	require.NoError(t, sink.Close())
	path := filepath.Join(dir, snapshot.files[0])
	require.NoError(t, os.Rename(path, path+".moved"))
	require.NoError(t, os.WriteFile(path, []byte("replacement\n"), 0o600))
	_, err = snapshot.recover(context.Background(), checkpoints)
	require.Error(t, err)
}

func TestWitnessSnapshotDeadlineDoesNotLeaveLockWaiter(t *testing.T) {
	w, sink, dir := witnessFixture(t)
	writeWitnessEvent(t, sink)
	_, err := w.Publish(context.Background(), dir)
	require.NoError(t, err)
	locked, release, released := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		released <- filetxn.WithLock(filepath.Join(dir, sharedStateFilename), func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result, err := w.Verify(ctx, dir)
	close(release)
	require.NoError(t, <-released)
	require.Equal(t, "verification_incomplete", WitnessCode(err))
	require.False(t, result.Verified)
	writeWitnessEvent(t, sink)
	result, err = w.Verify(context.Background(), dir)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.Unwitnessed)
	ctx, cancelFile := context.WithCancel(context.Background())
	cancelFile()
	_, err = w.retrieveFileHistory(ctx)
	require.Equal(t, "verification_incomplete", WitnessCode(err))
}

func TestWitnessConcurrentWriters(t *testing.T) {
	w, first, dir := witnessFixture(t)
	second, err := NewJSONLSink(dir, WithFsync(false), WithRotateSize(900))
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })
	var group sync.WaitGroup
	for _, sink := range []*JSONLSink{first, second} {
		group.Add(1)
		go func(sink *JSONLSink) {
			defer group.Done()
			for i := 0; i < 10; i++ {
				if err := sink.Write(Event{Tool: "read"}); err != nil {
					t.Errorf("write: %v", err)
				}
			}
		}(sink)
	}
	group.Wait()
	result, err := w.Publish(context.Background(), dir)
	require.NoError(t, err)
	require.EqualValues(t, 20, result.WitnessEvents)
}

func signedTestReceipt(t *testing.T) (WitnessReceipt, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	acceptance := WitnessAcceptance{Version: 1, WitnessID: "independent-test-peer", KeyID: "key-1", AcceptedAt: now,
		Checkpoint: WitnessCheckpoint{Version: 1, ChainID: "test-chain-identity", EventCount: 1, Hash: "sha256:" + strings.Repeat("a", 64), CreatedAt: now}}
	return WitnessReceipt{WitnessAcceptance: acceptance, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, acceptance.signingBytes()))}, public, private
}

func signedTestPage(receipts []WitnessReceipt, key ed25519.PrivateKey) WitnessPage {
	view := WitnessPageView{Version: 1, WitnessID: "independent-test-peer", ChainID: "test-chain-identity",
		ViewID: "stable-test-retrieval-view", Total: len(receipts), NextOffset: len(receipts), Complete: true,
		IssuedAt: time.Now().UTC(), KeyID: "key-1", Receipts: receipts}
	return WitnessPage{WitnessPageView: view, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, view.signingBytes()))}
}

func TestWitnessRetainedHistoryRejectsForgedHigherHead(t *testing.T) {
	w, sink, dir := witnessFixture(t)
	writeWitnessEvent(t, sink)
	_, err := w.Publish(context.Background(), dir)
	require.NoError(t, err)
	require.NoError(t, sink.Close())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.NoError(t, os.Remove(filepath.Join(dir, entry.Name())))
	}
	rewritten, err := NewJSONLSink(dir, WithFsync(false))
	require.NoError(t, err)
	writeWitnessEvent(t, rewritten)
	writeWitnessEvent(t, rewritten)
	forged := WitnessCheckpoint{Version: 1, ChainID: w.config.ChainID, EventCount: 2, Hash: rewritten.lastHash, CreatedAt: time.Now().UTC()}
	require.NoError(t, rewritten.Close())
	// The compromised publisher bypasses Publish's consistency guard and writes
	// a higher checkpoint directly. It cannot remove the independently retained N=1.
	data, err := json.Marshal(forged)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(w.config.FileDirectory, w.checkpointFilename(2)), data, 0o600))
	count, err := VerifyManagedChain(dir)
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	result, err := w.Verify(context.Background(), dir)
	require.Equal(t, "hash_mismatch", WitnessCode(err))
	require.False(t, result.Verified)
	// The same attack must fail when an independent HTTPS witness signs the
	// directly appended higher record and retains its earlier receipt.
	history, err := w.retrieveFileHistory(context.Background())
	require.NoError(t, err)
	_, public, private := signedTestReceipt(t)
	for i := range history {
		history[i].WitnessID, history[i].KeyID = "independent-test-peer", "key-1"
		history[i].AcceptedAt = time.Now().UTC()
		history[i].Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, history[i].WitnessAcceptance.signingBytes()))
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(rw).Encode(signedTestPage(history, private))
	}))
	defer server.Close()
	https := testHTTPSWitness(t, server, public)
	result, err = https.Verify(context.Background(), dir)
	require.Equal(t, "hash_mismatch", WitnessCode(err))
	require.False(t, result.Verified)
}

func TestWitnessOutageKeepsLoggingAndDoesNotUseCachedEvidence(t *testing.T) {
	_, sink, dir := witnessFixture(t)
	writeWitnessEvent(t, sink)
	_, public, private := signedTestReceipt(t)
	var mode atomic.Int32
	var mu sync.Mutex
	var history []WitnessReceipt
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
		if mode.Load() == 2 || (mode.Load() == 1 && request.Method == http.MethodPost) {
			rw.WriteHeader(503)
			fmt.Fprint(rw, "private-peer-error-canary")
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if request.Method == http.MethodGet {
			if len(history) == 0 {
				rw.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(rw).Encode(signedTestPage(history, private))
			return
		}
		var checkpoint WitnessCheckpoint
		if err := json.NewDecoder(request.Body).Decode(&checkpoint); err != nil {
			t.Error(err)
		}
		acceptance := WitnessAcceptance{Version: 1, WitnessID: "independent-test-peer", KeyID: "key-1", Checkpoint: checkpoint, AcceptedAt: time.Now().UTC()}
		receipt := WitnessReceipt{WitnessAcceptance: acceptance, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, acceptance.signingBytes()))}
		history = append(history, receipt)
		_ = json.NewEncoder(rw).Encode(receipt)
	}))
	defer server.Close()
	w := testHTTPSWitness(t, server, public)
	_, err := w.Publish(context.Background(), dir)
	require.NoError(t, err)
	writeWitnessEvent(t, sink)
	mode.Store(1)
	result, err := w.Publish(context.Background(), dir)
	require.Equal(t, "unavailable", WitnessCode(err))
	require.NotContains(t, err.Error(), "private-peer-error-canary")
	require.Equal(t, "degraded", result.Delivery)
	writeWitnessEvent(t, sink)
	result, err = w.Verify(context.Background(), dir)
	require.NoError(t, err)
	require.EqualValues(t, 2, result.Unwitnessed)
	require.Equal(t, "degraded", result.Delivery)
	mode.Store(2)
	result, err = w.Verify(context.Background(), dir)
	require.Equal(t, "unavailable", WitnessCode(err))
	require.False(t, result.Verified, "local delivery metadata cannot replace independent retrieval")
}

func TestWitnessLegacyDisconnectedEpochsRemainLocalOnly(t *testing.T) {
	w, sink, dir := witnessFixture(t)
	require.NoError(t, sink.Close())
	for i, name := range []string{"2025-01-01.jsonl", "2025-01-02.jsonl"} {
		event := Event{ID: fmt.Sprint(i + 1), Tool: "read", Timestamp: time.Date(2025, 1, i+1, 0, 0, 0, 0, time.UTC)}
		require.NoError(t, event.ComputeHash())
		data, err := json.Marshal(event)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0o600))
	}
	count, err := VerifyManagedChain(dir)
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	result, err := w.Publish(context.Background(), dir)
	require.Equal(t, "unsupported_legacy_epochs", WitnessCode(err))
	require.False(t, result.Verified)
}

func BenchmarkWitnessSnapshot(b *testing.B) {
	for _, events := range []int{100, 10000} {
		b.Run(fmt.Sprint(events), func(b *testing.B) {
			dir := b.TempDir()
			sink, err := NewJSONLSink(dir, WithFsync(false), WithRotateSize(128<<10), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
			if err != nil {
				b.Fatal(err)
			}
			for i := 0; i < events; i++ {
				if err := sink.Write(Event{Tool: "read", Request: map[string]any{"path": "/harmless-benchmark-marker"}}); err != nil {
					b.Fatal(err)
				}
			}
			if err := sink.Close(); err != nil {
				b.Fatal(err)
			}
			b.Run("capture", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := captureWitnessSnapshot(context.Background(), dir); err != nil {
						b.Fatal(err)
					}
				}
			})
			snapshot, err := captureWitnessSnapshot(context.Background(), dir)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("verify", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := snapshot.recover(context.Background(), nil); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func TestWitnessSignedPaginationBoundaries(t *testing.T) {
	for _, kind := range []string{"valid", "missing-middle", "missing-final", "changed-view", "changed-total", "duplicate", "premature-end", "limit"} {
		t.Run(kind, func(t *testing.T) {
			base, public, private := signedTestReceipt(t)
			receipts := make([]WitnessReceipt, 130)
			for i := range receipts {
				a := base.WitnessAcceptance
				a.Checkpoint.EventCount = int64(i + 1)
				receipts[i] = WitnessReceipt{WitnessAcceptance: a, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, a.signingBytes()))}
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
				offset := 0
				_, _ = fmt.Sscan(request.URL.Query().Get("offset"), &offset)
				if (kind == "missing-middle" && offset == 64) || (kind == "missing-final" && offset == 128) {
					rw.WriteHeader(404)
					return
				}
				if offset != 0 && request.URL.Query().Get("view_id") != "stable-test-retrieval-view" {
					t.Error("continuation did not request the bound view")
				}
				end := min(offset+witnessPageSize, len(receipts))
				page := signedTestPage(receipts[offset:end], private)
				page.Total, page.Offset, page.NextOffset, page.Complete = len(receipts), offset, end, end == len(receipts)
				if kind == "limit" {
					page.Total = maxWitnessReceipts + 1
				}
				if offset > 0 {
					switch kind {
					case "changed-view":
						page.ViewID = "different-retrieval-view"
					case "changed-total":
						page.Total++
					case "duplicate":
						page.Receipts[0] = receipts[0]
					case "premature-end":
						page.Complete = true
					}
				}
				page.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, page.WitnessPageView.signingBytes()))
				_ = json.NewEncoder(rw).Encode(page)
			}))
			defer server.Close()
			w := testHTTPSWitness(t, server, public)
			history, err := w.retrieve(context.Background())
			if kind == "valid" {
				require.NoError(t, err)
				require.Len(t, history, 130)
			} else {
				require.Error(t, err)
				require.Empty(t, history, "partial evidence must never be accepted")
			}
		})
	}
}

func testHTTPSWitness(t *testing.T, server *httptest.Server, public ed25519.PublicKey) *Witness {
	t.Helper()
	token := filepath.Join(t.TempDir(), "credential")
	require.NoError(t, os.WriteFile(token, []byte("synthetic-witness-credential"), 0o600))
	w, err := NewWitness(WitnessConfig{Version: 1, ChainID: "test-chain-identity", WitnessID: "independent-test-peer",
		URL: server.URL, TokenFile: token, Keys: map[string]string{"key-1": base64.StdEncoding.EncodeToString(public)}})
	require.NoError(t, err)
	w.client.Transport = server.Client().Transport
	return w
}

func TestWitnessHTTPSAuthenticationAndMalformedEvidence(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"valid", ""}, {"missing", "no_evidence"}, {"unauthorized", "unauthenticated"}, {"conflict", "conflict"},
		{"bad-signature", "unauthenticated"}, {"unknown-key", "unauthenticated"}, {"wrong-chain", "malformed"},
		{"redirect", "unavailable"}, {"oversized", "malformed"}, {"duplicate-key", "malformed"},
		{"unknown-field", "malformed"}, {"trailing-json", "malformed"}, {"future", "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt, public, private := signedTestReceipt(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Authorization") != "Bearer synthetic-witness-credential" {
					t.Error("retrieval was not authenticated")
				}
				switch tc.name {
				case "missing":
					rw.WriteHeader(404)
					return
				case "unauthorized":
					rw.WriteHeader(401)
					return
				case "conflict":
					rw.WriteHeader(409)
					return
				case "redirect":
					rw.Header().Set("Location", "https://uncontacted.invalid/secret")
					rw.WriteHeader(302)
					return
				case "oversized":
					fmt.Fprint(rw, strings.Repeat("x", witnessPageLimit+1))
					return
				case "bad-signature":
					receipt.Signature = "invalid"
				case "unknown-key":
					receipt.KeyID = "new-unpinned-key"
				case "wrong-chain":
					receipt.Checkpoint.ChainID = "different-chain-id"
				case "future":
					receipt.AcceptedAt = time.Now().Add(time.Hour)
				}
				page := signedTestPage([]WitnessReceipt{receipt}, private)
				data, _ := json.Marshal(page)
				switch tc.name {
				case "duplicate-key":
					data = append([]byte(`{"version":1,`), data[1:]...)
				case "unknown-field":
					data = append([]byte(`{"extra":true,`), data[1:]...)
				case "trailing-json":
					data = append(data, []byte(`{}`)...)
				}
				_, _ = rw.Write(data)
			}))
			defer server.Close()
			w := testHTTPSWitness(t, server, public)
			_, err := w.retrieve(context.Background())
			if tc.want == "" {
				require.NoError(t, err)
			} else {
				require.Equal(t, tc.want, WitnessCode(err))
				require.NotContains(t, err.Error(), "synthetic-witness-credential")
			}
		})
	}
}

func TestWitnessHTTPSPublicationDoesNotHoldWriterLock(t *testing.T) {
	_, sink, dir := witnessFixture(t)
	writeWitnessEvent(t, sink)
	_, public, private := signedTestReceipt(t)
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			rw.WriteHeader(404)
			return
		}
		data, _ := io.ReadAll(request.Body)
		for _, forbidden := range []string{"private-command-canary", "private-target-canary", "private-agent-canary", dir} {
			if strings.Contains(string(data), forbidden) {
				t.Errorf("request data reached witness")
			}
		}
		var checkpoint WitnessCheckpoint
		if err := decodeWitnessJSON(data, &checkpoint); err != nil {
			t.Error(err)
		}
		close(entered)
		<-release
		acceptance := WitnessAcceptance{Version: 1, WitnessID: "independent-test-peer", KeyID: "key-1", Checkpoint: checkpoint, AcceptedAt: time.Now().UTC()}
		_ = json.NewEncoder(rw).Encode(WitnessReceipt{WitnessAcceptance: acceptance, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, acceptance.signingBytes()))})
	}))
	defer server.Close()
	w := testHTTPSWitness(t, server, public)
	done := make(chan error, 1)
	go func() { _, err := w.Publish(context.Background(), dir); done <- err }()
	<-entered
	written := make(chan error, 1)
	go func() { written <- sink.Write(Event{Tool: "read"}) }()
	select {
	case err := <-written:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("network publication held the audit writer lock")
	}
	close(release)
	require.NoError(t, <-done)
}

func TestWitnessReceiptKeyRotationRequiresExplicitPin(t *testing.T) {
	receipt, _, _ := signedTestReceipt(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	receipt.KeyID = "rotated-key"
	receipt.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, receipt.WitnessAcceptance.signingBytes()))
	w := &Witness{config: WitnessConfig{ChainID: receipt.Checkpoint.ChainID, WitnessID: receipt.WitnessID}, keys: map[string]ed25519.PublicKey{}, now: time.Now}
	require.Equal(t, "unauthenticated", WitnessCode(w.validateReceipt(receipt)))
	w.keys["rotated-key"] = public
	require.NoError(t, w.validateReceipt(receipt))
}

func TestWitnessRetainedReceiptsRequireTheirOriginalKeys(t *testing.T) {
	oldReceipt, oldPublic, _ := signedTestReceipt(t)
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	acceptance := oldReceipt.WitnessAcceptance
	acceptance.Checkpoint.EventCount = 2
	acceptance.KeyID = "key-2"
	newReceipt := WitnessReceipt{WitnessAcceptance: acceptance,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(newPrivate, acceptance.signingBytes()))}
	page := signedTestPage([]WitnessReceipt{oldReceipt, newReceipt}, newPrivate)
	page.KeyID = "key-2"
	page.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(newPrivate, page.WitnessPageView.signingBytes()))
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(rw).Encode(page)
	}))
	defer server.Close()
	w := testHTTPSWitness(t, server, oldPublic)
	w.keys["key-2"] = newPublic
	history, err := w.retrieve(context.Background())
	require.NoError(t, err)
	require.Len(t, history, 2)
	delete(w.keys, "key-1")
	history, err = w.retrieve(context.Background())
	require.Equal(t, "unauthenticated", WitnessCode(err))
	require.Empty(t, history)
}
