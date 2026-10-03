// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package opencode

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestRenderBindsExactExecutableAsJSON(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "Rampart space ' \" $ ` <&.exe")
	data, err := Render(binary)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !Managed(data) || !bytes.Contains(data, encoded) || bytes.Contains(data, []byte("__RAMPART_BINARY_JSON__")) {
		t.Fatal("rendered plugin must preserve its ownership header and exact JSON-encoded executable")
	}
	if _, err := Render("rampart"); err == nil {
		t.Fatal("relative executable would allow PATH shadowing")
	}
}

func TestManagedRequiresCompleteLeadingHeader(t *testing.T) {
	for _, data := range []string{
		"// Rampart OpenCode policy gate\nexport default () => {};\n",
		"// A plugin that mentions Rampart OpenCode policy gate\n" + ownershipHeader,
		"// Rampart OpenCode policy gate\n// Managed by another installer; template v1.\n",
	} {
		if Managed([]byte(data)) {
			t.Fatalf("unowned plugin accepted: %q", data)
		}
	}
}
