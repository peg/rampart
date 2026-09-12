// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/proxy"
)

func customServeLaunch(t *testing.T) serveLaunchSettings {
	t.Helper()
	return serveLaunchSettings{WorkingDir: t.TempDir(), ConfigPath: "policy files/custom.yaml", ConfigDir: "additional policies", AuditDir: "audit logs", Mode: "monitor", Port: 19099, Addr: "127.0.0.1", Syslog: "127.0.0.1:514", CEF: true, ResolveBaseURL: "https://approvals.example.invalid", SigningKey: "keys/signing.key", Metrics: true, LogFile: "logs/service.log", ReloadInterval: 3 * time.Second, ApprovalTimeout: 4 * time.Minute, TLSCert: "certs/service.pem", TLSKey: "certs/service.key", NoOpenClawBridge: true, Verbose: true}
}

func TestServeLaunchPreservesTypedOptionsAndWorkingDirectory(t *testing.T) {
	settings := customServeLaunch(t)
	if err := settings.validate(); err != nil {
		t.Fatal(err)
	}
	root := NewRootCmd(context.Background(), io.Discard, io.Discard)
	command, arguments, err := root.Find(settings.arguments())
	if err != nil || command.Name() != "serve" {
		t.Fatalf("find serve command: %v", err)
	}
	if err := command.ParseFlags(arguments); err != nil {
		t.Fatal(err)
	}
	flags := command.Flags()
	for flag, want := range map[string]string{"config": settings.ConfigPath, "config-dir": settings.ConfigDir, "audit-dir": settings.AuditDir, "mode": settings.Mode, "addr": settings.Addr, "syslog": settings.Syslog, "resolve-base-url": settings.ResolveBaseURL, "signing-key": settings.SigningKey, "log-file": settings.LogFile, "tls-cert": settings.TLSCert, "tls-key": settings.TLSKey} {
		got, err := flags.GetString(flag)
		if err != nil || got != want {
			t.Errorf("%s=%q, want%q: %v", flag, got, want, err)
		}
	}
	for flag, want := range map[string]bool{"background": true, "cef": true, "metrics": true, "verbose": true, "tls-auto": false, "no-openclaw-bridge": true} {
		got, err := flags.GetBool(flag)
		if err != nil || got != want {
			t.Errorf("%s=%t, want%t: %v", flag, got, want, err)
		}
	}
	if got, _ := flags.GetInt("port"); got != settings.Port {
		t.Fatalf("port=%d", got)
	}
	for flag, want := range map[string]time.Duration{"reload-interval": settings.ReloadInterval, "approval-timeout": settings.ApprovalTimeout} {
		if got, _ := flags.GetDuration(flag); got != want {
			t.Errorf("%s=%s, want%s", flag, got, want)
		}
	}
	t.Setenv("RAMPART_LAUNCH_TEST_HELPER", "1")
	t.Setenv("RAMPART_TOKEN", "synthetic-upgrader-override-must-not-replace-service-token")
	var args []string
	var output bytes.Buffer
	err = settings.restart(func(binary string, arguments ...string) *exec.Cmd {
		if binary != "rampart-candidate" {
			t.Errorf("binary=%q", binary)
		}
		args = append([]string(nil), arguments...)
		return exec.Command(os.Args[0], "-test.run=^TestServeLaunchRestartHelper$")
	}, "rampart-candidate", &output, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var observed struct {
		CWD          string
		TokenPresent bool
	}
	if err := json.Unmarshal(output.Bytes(), &observed); err != nil {
		t.Fatal(err)
	}
	wantDir, wantErr := os.Stat(settings.WorkingDir)
	gotDir, gotErr := os.Stat(observed.CWD)
	if wantErr != nil || gotErr != nil || !os.SameFile(wantDir, gotDir) || observed.TokenPresent || !reflect.DeepEqual(args, settings.arguments()) {
		t.Fatalf("restart did not preserve launch semantics: %#v", observed)
	}
}

func TestServeLaunchRestartHelper(t *testing.T) {
	if os.Getenv("RAMPART_LAUNCH_TEST_HELPER") != "1" {
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		os.Exit(2)
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		CWD          string
		TokenPresent bool
	}{cwd, os.Getenv("RAMPART_TOKEN") != ""})
	os.Exit(0)
}

func TestServeStateKeepsRestartSettingsPrivateAndRejectsCredentialURLs(t *testing.T) {
	dir := t.TempDir()
	settings := customServeLaunch(t)
	identity := proxy.RuntimeIdentity{InstanceID: "state-instance-0001", Version: "test", Commit: "test-commit", Mode: settings.Mode}
	if err := writeServeState(dir, settings.Port, 4242, true, identity, &settings); err != nil {
		t.Fatal(err)
	}
	state, err := readPrivateServeState(dir)
	if err != nil || state.Launch == nil || *state.Launch != settings || state.RuntimeIdentity != identity {
		t.Fatalf("private state round trip: %#v %v", state, err)
	}
	before, err := os.ReadFile(filepath.Join(dir, serveStateFile))
	if err != nil {
		t.Fatal(err)
	}
	settings.ResolveBaseURL = "https://operator:synthetic-secret@example.invalid/?token=synthetic-secret"
	if err := writeServeState(dir, settings.Port, 4242, true, identity, &settings); err == nil {
		t.Fatal("credential-bearing restart URL was persisted")
	}
	after, err := os.ReadFile(filepath.Join(dir, serveStateFile))
	if err != nil || !bytes.Equal(before, after) || bytes.Contains(after, []byte("synthetic-secret")) {
		t.Fatal("invalid launch altered private state")
	}
}

func TestRestartRefusesUnknownLaunchFieldsWithoutBreakingDiscovery(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".rampart")
	settings := customServeLaunch(t)
	identity := proxy.RuntimeIdentity{InstanceID: "state-instance-0001", Version: "test", Commit: "test-commit", Mode: settings.Mode}
	if err := writeServeState(dir, settings.Port, 4242, true, identity, &settings); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, serveStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"launch":{`), []byte(`"launch":{"future_option":true,`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := readPrivateServeState(dir)
	if err != nil || state.Port != settings.Port {
		t.Fatalf("lightweight discovery rejected future state: %v", err)
	}
	if _, err := preparePIDServeRestart(func() (string, error) { return home, nil }, "unused-candidate", 4242); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown launch setting not refused at preparation: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("refusal changed runtime state")
	}
}

func TestServeCertificatePreservesRelativeSymlinkTraversal(t *testing.T) {
	home := t.TempDir()
	settings := customServeLaunch(t)
	actual := filepath.Join(settings.WorkingDir, "actual", "nested")
	if err := os.MkdirAll(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, filepath.Join(settings.WorkingDir, "alias")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(settings.WorkingDir, "actual", "cert.pem"), certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep both native destinations valid but distinct. Unix traversal through
	// the symlink and Windows lexical path handling need not select the same file.
	lexicalCertificate := append([]byte("\n"), certificate...)
	if err := os.WriteFile(filepath.Join(settings.WorkingDir, "cert.pem"), lexicalCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	settings.TLSCert = "alias/../cert.pem"
	t.Chdir(settings.WorkingDir)
	// The actual TLS loader opens the original relative argument from this CWD.
	expected, err := os.ReadFile(settings.TLSCert)
	if err != nil {
		t.Fatal(err)
	}
	state := serveState{Launch: &settings}
	got, err := serveLaunchCertificate(state, home, os.ReadFile)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("relative TLS traversal lost: %v", err)
	}
	settings.TLSCert = "missing.pem"
	if _, err := serveLaunchCertificate(state, home, os.ReadFile); err == nil || !strings.Contains(err.Error(), "manual restart") {
		t.Fatalf("missing cert: %v", err)
	}
}

func TestUpgradePinsOwnedCustomTLSBeforeStopping(t *testing.T) {
	home := t.TempDir()
	settings := customServeLaunch(t)
	settings.Mode = "enforce"
	server := newUpgradeHealthServer(t, true, "v1.9.1")
	defer server.Close()
	u, _ := url.Parse(server.URL)
	settings.Port, _ = strconv.Atoi(u.Port())
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	settings.TLSCert = "custom-cert.pem"
	if err := os.WriteFile(filepath.Join(settings.WorkingDir, settings.TLSCert), certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	state := serveState{URL: server.URL, Port: settings.Port, PID: 4242, Started: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), Launch: &settings}
	writeUpgradeServeState(t, home, state)
	deps := testServeRestartVerifierDeps(func(int) (bool, string, error) { return true, "rampart serve", nil })
	verifier, err := prepareServeRestartVerifierWithDeps(func() (string, error) { return home, nil }, os.ReadFile, deps)
	if err != nil {
		t.Fatal(err)
	}
	state.Started = time.Now().UTC().Format(time.RFC3339Nano)
	writeUpgradeServeState(t, home, state)
	if err := verifier(context.Background(), "v1.9.1", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("owned custom TLS activation: %v", err)
	}
	if err := os.Remove(filepath.Join(settings.WorkingDir, settings.TLSCert)); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareServeRestartVerifierWithDeps(func() (string, error) { return home, nil }, os.ReadFile, deps); err == nil || !strings.Contains(err.Error(), "before restart") {
		t.Fatalf("missing TLS reference was not refused before stop: %v", err)
	}
}

func TestUpgradeCurrentCLIDoesNotImplyCurrentService(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	server := newUpgradeHealthServer(t, false, "v1.9.1")
	defer server.Close()
	t.Setenv("RAMPART_URL", server.URL)
	var output bytes.Buffer
	cmd := newUpgradeCmdWithDeps(&rootOptions{}, &upgradeDeps{
		goos:           "linux", // Exercise the self-upgrade branch; Windows installer refusal has separate coverage.
		currentVersion: func(context.Context, commandRunner, func() (string, error)) (string, error) { return "v2.0.0", nil },
		inspectServePID: func(func() (string, error), func(string) ([]byte, error)) (int, bool, error) {
			t.Fatal("current CLI must not stop or claim ownership of the observed service")
			return 0, false, nil
		},
	})
	cmd.SetOut(&output)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"v2.0.0", "--yes", "--no-policy-update"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Already on latest CLI (v2.0.0)") || !strings.Contains(output.String(), "Observed service: v1.9.1") || !strings.Contains(output.String(), "did not restart") {
		t.Fatalf("runtime version distinction: %s", output.String())
	}
}
