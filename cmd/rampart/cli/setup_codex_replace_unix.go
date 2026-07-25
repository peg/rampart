// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

package cli

import "os"

func replaceCodexHooksFile(source, destination string) error {
	return os.Rename(source, destination)
}
