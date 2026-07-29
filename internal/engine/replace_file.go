// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package engine

import "github.com/peg/rampart/internal/filetxn"

func replaceFileAtomic(sourcePath, destinationPath string) error {
	return filetxn.Replace(sourcePath, destinationPath)
}

func syncPolicyDir(path string) error {
	return filetxn.SyncDir(path)
}
