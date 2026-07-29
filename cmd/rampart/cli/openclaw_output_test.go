// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import "testing"

func TestDecodeOpenClawConfigJSONAcceptsScalarAfterNotice(t *testing.T) {
	var value any
	output := []byte("[state-migrations] retained legacy state\n\"off\"\n")
	if err := decodeOpenClawConfigJSON(output, &value); err != nil {
		t.Fatal(err)
	}
	if value != "off" {
		t.Fatalf("value = %#v, want off", value)
	}
}

func TestDecodeOpenClawConfigJSONRejectsTrailingGarbage(t *testing.T) {
	var value any
	if err := decodeOpenClawConfigJSON([]byte("\"off\" ignored\n"), &value); err == nil {
		t.Fatal("accepted a JSON scalar with trailing non-JSON output")
	}
}
