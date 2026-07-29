// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type linkedAuditEvent struct {
	id        string
	hash      string
	prevHash  string
	file      string
	start     int64
	recordLen int64
}

type linkedContinuation struct {
	file          string
	line          int
	chainContinue string
	prevFile      string
}

// recoverChainStateByLinks validates legacy logs whose events are not in file
// order. It stores only chain metadata, never full requests or responses.
func recoverChainStateByLinks(dir string, files []string) (recoveredChainState, error) {
	eventsByHash := make(map[string]*linkedAuditEvent)
	children := make(map[string][]*linkedAuditEvent)
	firstEventByFile := make(map[string]*linkedAuditEvent)
	continuations := make([]linkedContinuation, 0)
	fileOrder := make(map[string]int, len(files))
	for i, name := range files {
		fileOrder[name] = i
	}
	var state recoveredChainState
	previousFile := ""

	for _, name := range files {
		path := filepath.Join(dir, name)
		file, err := openAuditRegular(path, os.O_RDONLY)
		if err != nil {
			return recoveredChainState{}, fmt.Errorf("open %s: %w", name, err)
		}

		reader := bufio.NewReaderSize(file, auditReaderBufferBytes)
		lineNum := 0
		cursor := int64(0)
		seenRecord := false
		for {
			recordStart := cursor
			record, complete, readErr := readRecord(reader)
			if errors.Is(readErr, io.EOF) {
				break
			}
			lineNum++
			if readErr != nil {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("read %s line %d: %w", name, lineNum, readErr)
			}
			if !complete {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("read %s line %d: unterminated audit record", name, lineNum)
			}
			cursor += int64(len(record) + 1)
			line := bytes.TrimSpace(record)
			if len(line) == 0 {
				continue
			}

			var event Event
			if err := json.Unmarshal(line, &event); err != nil {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("parse %s line %d: %w", name, lineNum, err)
			}
			if event.ID == "" {
				var header struct {
					ChainContinue *string `json:"chain_continue"`
					PrevFile      *string `json:"prev_file"`
				}
				if err := json.Unmarshal(line, &header); err != nil || header.ChainContinue == nil || header.PrevFile == nil {
					_ = file.Close()
					return recoveredChainState{}, fmt.Errorf("parse %s line %d: record has no event id", name, lineNum)
				}
				if seenRecord {
					_ = file.Close()
					return recoveredChainState{}, fmt.Errorf("verify %s line %d: chain continuation must be the first record", name, lineNum)
				}
				if *header.PrevFile != previousFile {
					_ = file.Close()
					return recoveredChainState{}, fmt.Errorf("verify %s line %d: prev_file %q does not match previous audit file %q", name, lineNum, *header.PrevFile, previousFile)
				}
				continuations = append(continuations, linkedContinuation{
					file:          name,
					line:          lineNum,
					chainContinue: *header.ChainContinue,
					prevFile:      *header.PrevFile,
				})
				seenRecord = true
				continue
			}

			ok, verifyErr := event.VerifyHash()
			if verifyErr != nil {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("verify %s line %d event %s: %w", name, lineNum, event.ID, verifyErr)
			}
			if !ok {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("verify %s line %d event %s: hash mismatch", name, lineNum, event.ID)
			}
			if _, duplicate := eventsByHash[event.Hash]; duplicate {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("verify %s line %d event %s: duplicate event hash %q", name, lineNum, event.ID, event.Hash)
			}

			linked := &linkedAuditEvent{
				id:        event.ID,
				hash:      event.Hash,
				prevHash:  event.PrevHash,
				file:      name,
				start:     recordStart,
				recordLen: int64(len(record) + 1),
			}
			eventsByHash[linked.hash] = linked
			children[linked.prevHash] = append(children[linked.prevHash], linked)
			if firstEventByFile[name] == nil {
				firstEventByFile[name] = linked
			}
			state.eventCount++
			seenRecord = true
		}
		if err := file.Close(); err != nil {
			return recoveredChainState{}, fmt.Errorf("close %s: %w", name, err)
		}
		state.lastFile = name
		state.lastFileSize = cursor
		previousFile = name
	}

	if state.eventCount == 0 {
		for _, header := range continuations {
			if header.chainContinue != "" {
				return recoveredChainState{}, fmt.Errorf("verify %s line %d: chain continuation %q has no preceding event", header.file, header.line, header.chainContinue)
			}
		}
		return state, nil
	}

	for _, event := range eventsByHash {
		if event.prevHash != "" {
			if _, ok := eventsByHash[event.prevHash]; !ok {
				return recoveredChainState{}, fmt.Errorf("verify %s event %s: prev_hash %q does not reference an audit event", event.file, event.id, event.prevHash)
			}
		}
		if len(children[event.hash]) > 1 {
			return recoveredChainState{}, fmt.Errorf("verify event %s: hash chain forks into %d events", event.id, len(children[event.hash]))
		}
	}
	roots := children[""]
	if len(roots) != 1 {
		return recoveredChainState{}, fmt.Errorf("verify audit chain: expected one root event, found %d", len(roots))
	}

	visited := 0
	tail := roots[0]
	for {
		visited++
		next := children[tail.hash]
		if len(next) == 0 {
			break
		}
		tail = next[0]
		if visited > len(eventsByHash) {
			return recoveredChainState{}, fmt.Errorf("verify audit chain: cycle detected")
		}
	}
	if visited != len(eventsByHash) {
		return recoveredChainState{}, fmt.Errorf("verify audit chain: %d events are disconnected", len(eventsByHash)-visited)
	}

	for _, header := range continuations {
		if header.prevFile == "" && header.chainContinue != "" {
			return recoveredChainState{}, fmt.Errorf("verify %s line %d: first audit file cannot continue hash %q", header.file, header.line, header.chainContinue)
		}
		if header.chainContinue == "" {
			if header.prevFile != "" {
				return recoveredChainState{}, fmt.Errorf("verify %s line %d: empty chain continuation references prev_file %q", header.file, header.line, header.prevFile)
			}
		} else {
			previous, ok := eventsByHash[header.chainContinue]
			if !ok {
				return recoveredChainState{}, fmt.Errorf("verify %s line %d: chain continuation %q does not reference an audit event", header.file, header.line, header.chainContinue)
			}
			if fileOrder[previous.file] > fileOrder[header.prevFile] {
				return recoveredChainState{}, fmt.Errorf("verify %s line %d: chain continuation event in %q comes after prev_file %q", header.file, header.line, previous.file, header.prevFile)
			}
		}
		if first := firstEventByFile[header.file]; first != nil && first.prevHash != header.chainContinue {
			return recoveredChainState{}, fmt.Errorf("verify %s line %d: first event prev_hash %q does not match chain continuation %q", header.file, header.line, first.prevHash, header.chainContinue)
		}
	}

	state.lastHash = tail.hash
	state.lastEventFile = tail.file
	state.lastEventStart = tail.start
	state.lastEventSize = tail.recordLen
	return state, nil
}
