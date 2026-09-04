// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peg/rampart/internal/filetxn"
)

func (w *Witness) requestBody(ctx context.Context, method, endpoint string, data []byte, limit int64) ([]byte, error) {
	credential, err := readWitnessFile(w.config.TokenFile)
	if err != nil {
		return nil, witnessFailure("unauthenticated")
	}
	token := strings.TrimSpace(string(credential))
	if len(token) < 16 || len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
		return nil, witnessFailure("unauthenticated")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, witnessFailure("unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := w.client.Do(request)
	if err != nil {
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) {
			return nil, witnessFailure("unauthenticated")
		}
		return nil, witnessFailure("unavailable")
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, witnessFailure("unauthenticated")
	case http.StatusNotFound:
		return nil, witnessFailure("no_evidence")
	case http.StatusConflict:
		return nil, witnessFailure("conflict")
	case http.StatusOK, http.StatusCreated:
	default:
		return nil, witnessFailure("unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, witnessFailure("malformed")
	}
	return body, nil
}

func (w *Witness) publishHTTPS(ctx context.Context, data []byte) (WitnessReceipt, error) {
	body, err := w.requestBody(ctx, http.MethodPost, w.config.URL, data, witnessRecordLimit)
	if err != nil {
		return WitnessReceipt{}, err
	}
	var receipt WitnessReceipt
	if err := decodeWitnessJSON(body, &receipt); err != nil {
		return WitnessReceipt{}, err
	}
	if err := w.validateReceipt(receipt); err != nil {
		return WitnessReceipt{}, err
	}
	return receipt, nil
}

const maxFileWitnessEntries = 100000

func (w *Witness) checkpointFilename(count int64) string {
	return fmt.Sprintf("%s.%020d.json", w.config.ChainID, count)
}

func (w *Witness) fileReceipt(name string, count int64) (WitnessReceipt, error) {
	data, err := readWitnessFile(filepath.Join(w.config.FileDirectory, name))
	if err != nil {
		return WitnessReceipt{}, witnessFailure("unavailable")
	}
	var checkpoint WitnessCheckpoint
	if err := decodeWitnessJSON(data, &checkpoint); err != nil {
		return WitnessReceipt{}, err
	}
	if !validWitnessCheckpoint(checkpoint, w.config.ChainID, w.now()) {
		return WitnessReceipt{}, witnessFailure("malformed")
	}
	if checkpoint.EventCount != count {
		return WitnessReceipt{}, witnessFailure("conflict")
	}
	// File evidence has no independently authenticated acceptance timestamp or
	// signature. Its authority depends entirely on separate storage control.
	return WitnessReceipt{WitnessAcceptance: WitnessAcceptance{Version: 1,
		WitnessID: w.config.WitnessID, Checkpoint: checkpoint}}, nil
}

func (w *Witness) retrieveFileHistory() ([]WitnessReceipt, error) {
	if err := validateAuditDirectory(w.config.FileDirectory); err != nil {
		return nil, witnessFailure("unavailable")
	}
	directory, err := os.Open(w.config.FileDirectory)
	if err != nil {
		return nil, witnessFailure("unavailable")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(maxFileWitnessEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, witnessFailure("unavailable")
	}
	if len(entries) > maxFileWitnessEntries {
		return nil, witnessFailure("evidence_limit")
	}
	var positions []int64
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), w.config.ChainID+".") {
			continue
		}
		position := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), w.config.ChainID+"."), ".json")
		count, err := strconv.ParseInt(position, 10, 64)
		if err != nil || count <= 0 || entry.Name() != w.checkpointFilename(count) {
			return nil, witnessFailure("conflict")
		}
		if _, _, err := inspectAuditRegularPath(filepath.Join(w.config.FileDirectory, entry.Name())); err != nil {
			return nil, witnessFailure("malformed")
		}
		positions = append(positions, count)
	}
	if len(positions) == 0 {
		return nil, witnessFailure("no_evidence")
	}
	sort.Slice(positions, func(i, j int) bool { return positions[i] < positions[j] })
	receipts := make([]WitnessReceipt, 0, len(positions))
	for _, count := range positions {
		receipt, err := w.fileReceipt(w.checkpointFilename(count), count)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func (w *Witness) publishFile(checkpoint WitnessCheckpoint) (WitnessReceipt, error) {
	if err := validateAuditDirectory(w.config.FileDirectory); err != nil {
		return WitnessReceipt{}, witnessFailure("unavailable")
	}
	name := w.checkpointFilename(checkpoint.EventCount)
	path := filepath.Join(w.config.FileDirectory, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		previous, err := w.fileReceipt(name, checkpoint.EventCount)
		if err != nil {
			return WitnessReceipt{}, err
		}
		if previous.Checkpoint.Hash != checkpoint.Hash {
			return WitnessReceipt{}, witnessFailure("conflict")
		}
		return previous, nil
	}
	if err != nil {
		return WitnessReceipt{}, witnessFailure("unavailable")
	}
	data, _ := json.Marshal(checkpoint)
	_, writeErr := file.Write(append(data, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		// Never remove or rewrite evidence after a failed publication. A partial
		// record needs operator attention and cannot silently become acceptance.
		return WitnessReceipt{}, witnessFailure("delivery_incomplete")
	}
	if err := filetxn.SyncDir(w.config.FileDirectory); err != nil {
		return WitnessReceipt{}, witnessFailure("delivery_incomplete")
	}
	return w.fileReceipt(name, checkpoint.EventCount)
}

type witnessDelivery struct {
	Version     int       `json:"version"`
	ChainID     string    `json:"chain_id"`
	WitnessID   string    `json:"witness_id"`
	AttemptedAt time.Time `json:"attempted_at"`
	Delivery    string    `json:"delivery"`
	Failure     string    `json:"failure,omitempty"`
}

func (w *Witness) deliveryPath(dir string) string {
	return filepath.Join(dir, ".audit-witness-delivery-"+w.config.ChainID+".json")
}

func (w *Witness) saveDelivery(dir string, result WitnessResult) error {
	state := witnessDelivery{Version: 1, ChainID: w.config.ChainID, WitnessID: w.config.WitnessID,
		AttemptedAt: w.now().UTC(), Delivery: result.Delivery, Failure: result.LastFailure}
	data, _ := json.Marshal(state)
	return replaceAuditMetadata(w.deliveryPath(dir), data, false)
}

func (w *Witness) addDelivery(dir string, result *WitnessResult) {
	result.Delivery = "unknown"
	data, err := readWitnessFile(w.deliveryPath(dir))
	var state witnessDelivery
	if err != nil || decodeWitnessJSON(data, &state) != nil || state.Version != 1 ||
		state.ChainID != w.config.ChainID || state.WitnessID != w.config.WitnessID ||
		state.AttemptedAt.IsZero() || state.AttemptedAt.After(w.now().Add(5*time.Minute)) {
		return
	}
	if state.Delivery == "delivered" && state.Failure == "" {
		result.Delivery = state.Delivery
	} else if state.Delivery == "degraded" && knownWitnessFailure(state.Failure) {
		result.Delivery, result.LastFailure = state.Delivery, state.Failure
	}
}

func knownWitnessFailure(code string) bool {
	switch code {
	case "unauthenticated", "unavailable", "no_evidence", "conflict", "malformed", "evidence_limit", "verification_incomplete", "incomplete_evidence", "stale_view",
		"destination_capacity", "delivery_incomplete", "delivery_state_unavailable",
		"local_invalid", "unsupported_legacy_epochs", "witness_ahead", "hash_mismatch",
		"stale_checkpoint", "empty_chain":
		return true
	}
	return false
}
