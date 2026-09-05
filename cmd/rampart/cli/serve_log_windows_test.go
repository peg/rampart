// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeLogNativePath(t *testing.T) {
	long := strings.Repeat(`segment\`, 40) + "serve.log"
	for _, tc := range []struct{ path, want string }{
		{`C:\logs\serve.log`, `C:\logs\serve.log`},
		{`\\server\share\serve.log`, `\\server\share\serve.log`},
		{`C:\` + long, `\\?\C:\` + long},
		{`\\server\share\` + long, `\\?\UNC\server\share\` + long},
		{`\\?\C:\` + long, `\\?\C:\` + long},
		{`\\?\UNC\server\share\` + long, `\\?\UNC\server\share\` + long},
		{`\\.\C:\` + long, `\\.\C:\` + long},
	} {
		if got := serveLogNativePath(tc.path); got != tc.want {
			t.Errorf("native path %q: got %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestServeLogLongPathRotation(t *testing.T) {
	dir := t.TempDir()
	for len(dir) < 320 {
		dir = filepath.Join(dir, strings.Repeat("long", 8))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "serve.log")
	w, err := openServeLog(path, 128, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 40; i++ {
		if _, err := fmt.Fprintf(w, "long path record %02d\n", i); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "long path record 39") {
		t.Fatalf("latest long-path record missing: %q (%v)", data, err)
	}
	for _, suffix := range []string{"", ".1", ".2"} {
		info, err := os.Stat(path + suffix)
		if err != nil || info.Size() > 128 {
			t.Fatalf("invalid retained log %q: %v (%v)", suffix, info, err)
		}
	}
}
