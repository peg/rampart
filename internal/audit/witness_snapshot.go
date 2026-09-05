// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxWitnessSnapshotFiles = 10000

// witnessSnapshot captures file identities and committed lengths under the
// existing writer lock. Hash verification then reads only those lengths outside
// the lock, so transport and full-history scanning cannot stall audit writers.
type witnessSnapshot struct {
	dir   string
	files []string
	info  map[string]os.FileInfo
}

func captureWitnessSnapshot(ctx context.Context, dir string) (witnessSnapshot, error) {
	snapshot := witnessSnapshot{dir: dir, info: make(map[string]os.FileInfo)}
	sink := &JSONLSink{dir: dir}
	err := sink.withDirectoryLockContext(ctx, func() error {
		directory, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer directory.Close()
		entries, err := directory.ReadDir(maxWitnessSnapshotFiles + 1)
		if err != nil && err != io.EOF {
			return err
		}
		if len(entries) > maxWitnessSnapshotFiles {
			return fmt.Errorf("audit: witness snapshot exceeds %d directory entries", maxWitnessSnapshotFiles)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !strings.HasSuffix(entry.Name(), ".jsonl") {
				continue
			}
			info, _, err := inspectAuditRegularPath(filepath.Join(dir, entry.Name()))
			if err != nil {
				return err
			}
			if info == nil {
				return fmt.Errorf("audit: snapshot file disappeared")
			}
			if IsManagedChainFile(entry.Name()) {
				snapshot.files = append(snapshot.files, entry.Name())
				snapshot.info[entry.Name()] = info
			}
		}
		return nil
	})
	SortAuditFiles(snapshot.files)
	return snapshot, err
}

type witnessSnapshotReader struct {
	ctx  context.Context
	file *os.File
	read *io.SectionReader
	path string
	info os.FileInfo
}

func (r *witnessSnapshotReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.read.Read(p)
}

func (r *witnessSnapshotReader) Close() error {
	defer r.file.Close()
	info, exists, err := inspectAuditRegularPath(r.path)
	if err != nil || !exists || !os.SameFile(info, r.info) || info.Size() < r.info.Size() {
		return fmt.Errorf("audit: witness snapshot file changed")
	}
	return nil
}

func (s witnessSnapshot) recover(ctx context.Context, checkpoints map[int64]string) (recoveredChainState, error) {
	return recoverChainState(s.dir, s.files, func(name string) (io.ReadCloser, error) {
		path := filepath.Join(s.dir, name)
		file, err := openAuditRegular(path, os.O_RDONLY)
		if err != nil {
			return nil, err
		}
		info, err := file.Stat()
		expected := s.info[name]
		if err != nil || !os.SameFile(info, expected) || info.Size() < expected.Size() {
			_ = file.Close()
			return nil, fmt.Errorf("audit: witness snapshot file changed")
		}
		return &witnessSnapshotReader{ctx: ctx, file: file,
			read: io.NewSectionReader(file, 0, expected.Size()), path: path, info: expected}, nil
	}, checkpoints, nil)
}
