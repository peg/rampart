// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	witnessPageLimit = 64 << 10
	witnessPageSize  = 64
)

// WitnessPageView binds a complete immutable retrieval view. Offset is an
// index into retained receipts, not an audit event count. Every page preserves
// ViewID and Total; signed boundaries prevent silently skipping or mixing pages.
type WitnessPageView struct {
	Version    int              `json:"version"`
	WitnessID  string           `json:"witness_id"`
	ChainID    string           `json:"chain_id"`
	ViewID     string           `json:"view_id"`
	Total      int              `json:"total"`
	Offset     int              `json:"offset"`
	NextOffset int              `json:"next_offset"`
	Complete   bool             `json:"complete"`
	IssuedAt   time.Time        `json:"issued_at"`
	KeyID      string           `json:"key_id"`
	Receipts   []WitnessReceipt `json:"receipts"`
}

type WitnessPage struct {
	WitnessPageView
	Signature string `json:"signature"`
}

func (p WitnessPageView) signingBytes() []byte {
	data, _ := json.Marshal(p)
	return append([]byte("rampart.audit.witness.page.v1\n"), data...)
}

func (w *Witness) validatePage(page WitnessPage) error {
	if page.Version != 1 || page.WitnessID != w.config.WitnessID || page.ChainID != w.config.ChainID ||
		!witnessIdentifier.MatchString(page.ViewID) || page.Total < 0 || page.Offset < 0 ||
		len(page.Receipts) > witnessPageSize || page.NextOffset != page.Offset+len(page.Receipts) ||
		page.NextOffset > page.Total || page.Complete != (page.NextOffset == page.Total) ||
		(!page.Complete && len(page.Receipts) == 0) {
		return witnessFailure("incomplete_evidence")
	}
	if page.Total > maxWitnessReceipts {
		return witnessFailure("evidence_limit")
	}
	_, offset := page.IssuedAt.Zone()
	if page.IssuedAt.IsZero() || offset != 0 || page.IssuedAt.After(w.now().Add(5*time.Minute)) || w.now().Sub(page.IssuedAt) > 5*time.Minute {
		return witnessFailure("stale_view")
	}
	key, pinned := w.keys[page.KeyID]
	signature, err := base64.StdEncoding.DecodeString(page.Signature)
	if !pinned || err != nil || !ed25519.Verify(key, page.WitnessPageView.signingBytes(), signature) {
		return witnessFailure("unauthenticated")
	}
	for _, receipt := range page.Receipts {
		if err := w.validateReceipt(receipt); err != nil {
			return err
		}
	}
	return nil
}

func (w *Witness) retrieveHTTPS(ctx context.Context) ([]WitnessReceipt, error) {
	var receipts []WitnessReceipt
	viewID, total, offset := "", 0, 0
	var previousCount int64
	for pages := 0; pages <= maxWitnessReceipts/witnessPageSize+1; pages++ {
		endpoint, _ := url.Parse(w.config.URL) // Validated by NewWitness.
		query := endpoint.Query()
		query.Set("offset", strconv.Itoa(offset))
		query.Set("limit", strconv.Itoa(witnessPageSize))
		if viewID != "" {
			query.Set("view_id", viewID)
		}
		endpoint.RawQuery = query.Encode()
		body, err := w.requestBody(ctx, http.MethodGet, endpoint.String(), nil, witnessPageLimit)
		if err != nil {
			if offset > 0 && WitnessCode(err) == "no_evidence" {
				return nil, witnessFailure("incomplete_evidence")
			}
			return nil, err
		}
		var page WitnessPage
		if err := decodeWitnessJSON(body, &page); err != nil {
			return nil, err
		}
		if err := w.validatePage(page); err != nil {
			return nil, err
		}
		if page.Offset != offset || (viewID != "" && (viewID != page.ViewID || total != page.Total)) {
			return nil, witnessFailure("conflict")
		}
		viewID, total = page.ViewID, page.Total
		for _, receipt := range page.Receipts {
			if receipt.Checkpoint.EventCount <= previousCount {
				return nil, witnessFailure("conflict")
			}
			previousCount = receipt.Checkpoint.EventCount
			receipts = append(receipts, receipt)
		}
		offset = page.NextOffset
		if page.Complete {
			if len(receipts) == 0 {
				return nil, witnessFailure("no_evidence")
			}
			return receipts, nil
		}
	}
	return nil, witnessFailure("evidence_limit")
}
