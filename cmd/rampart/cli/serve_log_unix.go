// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build !windows

package cli

import "os"

func openServeLogAppend(path string, create bool) (*os.File, error) {
	flags := os.O_APPEND | os.O_WRONLY
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	return os.OpenFile(path, flags, 0o600)
}
