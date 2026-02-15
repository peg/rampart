// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package engine

import "testing"

func FuzzNormalizeCommand(f *testing.F) {
	f.Add("rm -rf /")
	f.Add("'rm' -rf /")
	f.Add(`"rm" -rf /`)
	f.Add(`r\m -rf /`)
	f.Add("FOO=bar rm -rf /")
	f.Add("a && b || c ; d | e")
	f.Add(`echo "hello 'world'"`)
	f.Add("")
	f.Add("''''")
	f.Add(`\\\\`)

	f.Fuzz(func(t *testing.T, cmd string) {
		// Must not panic.
		_ = NormalizeCommand(cmd)
		_ = SplitCompoundCommand(cmd)
	})
}
