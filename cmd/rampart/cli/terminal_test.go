// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package cli

import (
	"os"
	"testing"
)

func TestPipeIsNotTerminal(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()

	if isTerminal(reader) {
		t.Fatal("pipe reported as a terminal")
	}
}
