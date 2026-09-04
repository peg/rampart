// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServeLogRotationWithInheritedOutput(t *testing.T) {
	const childEnv = "RAMPART_TEST_SERVE_LOG_CHILD"
	if path := os.Getenv(childEnv); path != "" {
		fail := func(err error) {
			// The inherited output may refer to a backup already removed by
			// rotation. Preserve a failing child's diagnostic for its parent.
			_ = os.WriteFile(path+".child-error", []byte(err.Error()), 0o600)
			t.Fatal(err)
		}
		// Keep the actual inherited stdout and stderr handles open throughout
		// rotation, as the background serve child does.
		fmt.Fprintln(os.Stdout, "inherited stdout")
		fmt.Fprintln(os.Stderr, "inherited stderr")
		w, err := openServeLog(path, 128, 3)
		if err != nil {
			fail(err)
		}
		for i := 0; i < 40; i++ {
			if _, err := fmt.Fprintf(w, "managed record %02d\n", i); err != nil {
				fail(err)
			}
		}
		if err := w.Close(); err != nil {
			fail(err)
		}
		return
	}

	path := filepath.Join(t.TempDir(), "serve.log")
	startup, err := openServeLog(path, 128, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer startup.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServeLogRotationWithInheritedOutput$")
	child.Env = append(os.Environ(), childEnv+"="+path)
	child.Stdout, child.Stderr = startup.file, startup.file
	if err := child.Run(); err != nil {
		detail, _ := os.ReadFile(path + ".child-error")
		t.Fatalf("child with inherited log handles: %v (%s)", err, detail)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "managed record 39") {
		t.Fatalf("latest record missing after child rotation: %q (%v)", data, err)
	}
	files, err := filepath.Glob(path + "*")
	if err != nil || len(files) != 4 {
		t.Fatalf("retained files=%v, error=%v; want active and three backups", files, err)
	}
	for _, name := range files {
		info, err := os.Stat(name)
		if err != nil || info.Size() > 128 {
			t.Fatalf("invalid retained log %s: %v (%v)", name, info, err)
		}
	}
}

func TestServeLogRotationAndRedaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.log")
	w, err := openServeLog(path, 180, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		record := fmt.Sprintf("event=%02d Authorization: Bearer synthetic-secret-credential\n", i)
		if n, err := w.Write([]byte(record)); err != nil || n != len(record) {
			t.Fatalf("write=(%d,%v)", n, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("retained %d files, want active plus two backups", len(files))
	}
	for _, name := range files {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 180 {
			t.Fatalf("%s exceeds size limit: %d", name, info.Size())
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("mode=%o", info.Mode().Perm())
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "synthetic-secret-credential") {
			t.Fatal("credential reached retained log")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "event=29") {
		t.Fatal("latest event not in active log")
	}
}

func TestServeLogOversizedRecordIsOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.log")
	w, err := openServeLog(path, 256, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	record := []byte(strings.Repeat("private-material", serveLogMaxRecord))
	if n, err := w.Write(record); err != nil || n != len(record) {
		t.Fatalf("write=(%d,%v)", n, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-material") || !strings.Contains(string(data), "omitted") {
		t.Fatalf("unexpected record: %q", data)
	}
}

func TestServeLogRejectsLinkedActiveFile(t *testing.T) {
	for _, kind := range []string{"hard", "symbolic"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target, path := filepath.Join(dir, "unrelated"), filepath.Join(dir, "serve.log")
			if err := os.WriteFile(target, []byte("unchanged"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o644); err != nil {
				t.Fatal(err)
			}
			link := os.Link
			if kind == "symbolic" {
				link = os.Symlink
			}
			if err := link(target, path); err != nil {
				t.Skipf("links unavailable: %v", err)
			}
			w, err := openServeLog(path, 180, 2)
			if err == nil {
				_ = w.Close()
				t.Fatal("accepted linked active file")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "unchanged" {
				t.Fatalf("target changed: %q %v", data, err)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
				t.Fatal("changed unrelated file permissions")
			}
		})
	}
}

func TestServeLogRejectsReplacedActiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.log")
	w, err := openServeLog(path, 180, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Skipf("cannot rename open file: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("must not append\n")); err == nil {
		t.Fatal("accepted replaced active file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatal("replacement was modified")
	}
}

func TestServeLogInvalidBackupStopsRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.log")
	w, err := openServeLog(path, 50, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	before := strings.Repeat("a", 40)
	if _, err := w.Write([]byte(before)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".2", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(strings.Repeat("b", 30))); err == nil {
		t.Fatal("accepted invalid backup")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != before {
		t.Fatal("rotation changed active log before rejecting backup")
	}
}

func TestServeLogConcurrentRecordsAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.log")
	w, err := openServeLog(path, 4096, 2)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 40; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			if _, err := fmt.Fprintf(w, "record-%02d\n", i); err != nil {
				t.Errorf("write: %v", err)
			}
		}(i)
	}
	group.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = openServeLog(path, 4096, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(w, "after-restart"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 41 || lines[40] != "after-restart" {
		t.Fatalf("lost or torn records: %q", data)
	}
}

func BenchmarkServeDiagnosticLog(b *testing.B) {
	w, err := openServeLog(filepath.Join(b.TempDir(), "serve.log"), serveLogMaxBytes, serveLogBackups)
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	record := []byte("time=2026-09-04T00:00:00Z level=INFO msg=decision action=deny\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(record); err != nil {
			b.Fatal(err)
		}
	}
}

func TestServeLogFlagRoutesApplicationDiagnostics(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	config := filepath.Join(home, "rampart.yaml")
	if err := os.WriteFile(config, []byte("version: \"1\"\ndefault_action: deny\npolicies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := &serveDeps{notifyContext: func(parent context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, cancel
	}}
	cmd := newServeCmd(&rootOptions{configPath: config}, deps)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	path := filepath.Join(home, "serve.log")
	cmd.SetArgs([]string{"--port", "0", "--log-file", path, "--audit-dir", filepath.Join(home, "audit")})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("no application diagnostics written")
	}
	if output.Len() != 0 {
		t.Fatalf("diagnostics escaped selected log: %s", output.String())
	}
	if cmd.OutOrStdout() != &output || cmd.ErrOrStderr() != &output {
		t.Fatal("command writers were not restored")
	}
}
