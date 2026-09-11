// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// serveLaunchSettings is private, typed restart state for the options serve
// actually consumed. It deliberately has no argv, environment, or token field.
// Relative paths retain their meaning through the original working directory.
type serveLaunchSettings struct {
	WorkingDir       string        `json:"working_dir"`
	ConfigPath       string        `json:"config_path"`
	ConfigDir        string        `json:"config_dir,omitempty"`
	AuditDir         string        `json:"audit_dir"`
	Mode             string        `json:"mode"`
	Port             int           `json:"port"`
	Addr             string        `json:"addr"`
	Syslog           string        `json:"syslog,omitempty"`
	CEF              bool          `json:"cef"`
	ResolveBaseURL   string        `json:"resolve_base_url,omitempty"`
	SigningKey       string        `json:"signing_key,omitempty"`
	Metrics          bool          `json:"metrics"`
	LogFile          string        `json:"log_file,omitempty"`
	ReloadInterval   time.Duration `json:"reload_interval"`
	ApprovalTimeout  time.Duration `json:"approval_timeout"`
	TLSCert          string        `json:"tls_cert,omitempty"`
	TLSKey           string        `json:"tls_key,omitempty"`
	TLSAuto          bool          `json:"tls_auto"`
	NoOpenClawBridge bool          `json:"no_openclaw_bridge"`
	Verbose          bool          `json:"verbose"`
}

func (settings serveLaunchSettings) validate() error {
	if !filepath.IsAbs(settings.WorkingDir) || settings.ConfigPath == "" || settings.AuditDir == "" || settings.Port < 1 || settings.Port > 65535 || net.ParseIP(settings.Addr) == nil {
		return fmt.Errorf("restart settings have incomplete paths or listener configuration")
	}
	if settings.Mode != "enforce" && settings.Mode != "monitor" && settings.Mode != "disabled" {
		return fmt.Errorf("restart settings have an invalid mode")
	}
	if (settings.TLSCert == "") != (settings.TLSKey == "") || (settings.TLSAuto && settings.TLSCert != "") {
		return fmt.Errorf("restart settings have conflicting TLS configuration")
	}
	for _, value := range []string{settings.WorkingDir, settings.ConfigPath, settings.ConfigDir, settings.AuditDir, settings.Syslog, settings.ResolveBaseURL, settings.SigningKey, settings.LogFile, settings.TLSCert, settings.TLSKey} {
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("restart settings contain an unsupported path or address")
		}
	}
	if settings.ResolveBaseURL != "" {
		u, err := url.Parse(settings.ResolveBaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("approval URL cannot be retained without copying possible credentials")
		}
	}
	if settings.Syslog != "" {
		if _, _, err := net.SplitHostPort(settings.Syslog); err != nil || strings.ContainsAny(settings.Syslog, "@/?#") {
			return fmt.Errorf("syslog address cannot be retained safely")
		}
	}
	return nil
}

func (settings serveLaunchSettings) arguments() []string {
	args := []string{"serve", "--background", "--config", settings.ConfigPath,
		"--audit-dir", settings.AuditDir, "--mode", settings.Mode, "--port", strconv.Itoa(settings.Port), "--addr", settings.Addr,
		"--cef=" + strconv.FormatBool(settings.CEF), "--metrics=" + strconv.FormatBool(settings.Metrics), "--verbose=" + strconv.FormatBool(settings.Verbose),
		"--reload-interval", settings.ReloadInterval.String(), "--approval-timeout", settings.ApprovalTimeout.String(),
		"--tls-auto=" + strconv.FormatBool(settings.TLSAuto), "--no-openclaw-bridge=" + strconv.FormatBool(settings.NoOpenClawBridge)}
	for _, option := range []struct{ name, value string }{
		{"config-dir", settings.ConfigDir}, {"syslog", settings.Syslog}, {"resolve-base-url", settings.ResolveBaseURL},
		{"signing-key", settings.SigningKey}, {"log-file", settings.LogFile}, {"tls-cert", settings.TLSCert}, {"tls-key", settings.TLSKey},
	} {
		if option.value != "" {
			args = append(args, "--"+option.name, option.value)
		}
	}
	return args
}

type serveRestarter func(commandRunner, string, io.Writer, io.Writer) error

func preparePIDServeRestart(userHomeDir func() (string, error), binary string, pid int) (serveRestarter, error) {
	home, err := userHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".rampart")
	state, err := readPrivateServeStateForRestart(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot preserve this background service: %w", err)
	}
	if state.PID != pid || !samePath(state.Executable, binary) {
		return nil, fmt.Errorf("cannot preserve this background service: private state does not match the running PID and upgraded executable; restart it manually with its original settings")
	}
	owned, _, err := isRampartServeProcess(pid)
	if err != nil || !owned {
		return nil, fmt.Errorf("cannot preserve background service: process ownership is unproven")
	}
	stateURL, err := validateLocalServeStateURL(state)
	if err != nil {
		return nil, err
	}
	observed, err := observeServiceRuntime(context.Background(), stateURL.String(), time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot preserve background service: its configured endpoint is not healthy")
	}
	if state.InstanceID != "" && (!runtimeIdentified(state.RuntimeIdentity) || observed.RuntimeIdentity != state.RuntimeIdentity) {
		return nil, fmt.Errorf("cannot preserve background service: health and private process state identify different runtimes")
	}
	settings := state.Launch
	if settings == nil {
		if state.InstanceID != "" {
			return nil, fmt.Errorf("this service could not save safe restart settings; restart it manually with its original settings before upgrading")
		}
		if cmp, ok := compareReleaseVersions(observed.Version, "v1.9.1"); !ok || cmp > 0 {
			return nil, legacyLaunchError()
		}
		legacy, err := legacyDefaultServeLaunch(pid, home, binary)
		if err != nil {
			return nil, err
		}
		settings = &legacy
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	if settings.Port != state.Port || settings.Mode != observed.Mode || (settings.TLSAuto || settings.TLSCert != "") != (stateURL.Scheme == "https") {
		return nil, fmt.Errorf("saved launch settings do not match the running service")
	}
	if info, err := os.Stat(settings.WorkingDir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("the original service working directory is unavailable; restore it before upgrading")
	}
	// The running service already persisted its token. Refuse before stop if
	// restarting would generate a replacement token or inherit an override.
	if token, err := readPersistedToken(); err != nil || token == "" {
		return nil, fmt.Errorf("the running service's private token is unavailable; restore it before upgrading")
	}
	captured := *settings
	return captured.restart, nil
}

func (settings serveLaunchSettings) restart(runner commandRunner, executable string, stdout, stderr io.Writer) error {
	cmd := runner(executable, settings.arguments()...)
	cmd.Dir = settings.WorkingDir
	cmd.Env = setEnvValue(os.Environ(), "RAMPART_TOKEN", "")
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("upgrade: restart with preserved service settings: %w", err)
	}
	return nil
}

// Released v1.9.1 did not retain launch settings. Recover only the positively
// identified ordinary background launch, never interpret general ps output as
// shell syntax or guess custom flags. Service-manager definitions are handled
// separately by upgrade and remain authoritative for their own launches.
func legacyDefaultServeLaunch(pid int, home, executable string) (serveLaunchSettings, error) {
	var settings serveLaunchSettings
	logPath := filepath.Join(home, ".rampart", "serve.log")
	var cwd string
	var args []string
	switch runtime.GOOS {
	case "linux":
		procDir := filepath.Join("/proc", strconv.Itoa(pid))
		before, err := os.ReadFile(filepath.Join(procDir, "stat"))
		if err != nil {
			return settings, legacyLaunchError()
		}
		commandFile, err := os.Open(filepath.Join(procDir, "cmdline"))
		if err != nil {
			return settings, legacyLaunchError()
		}
		command, readErr := io.ReadAll(io.LimitReader(commandFile, 65537))
		closeErr := commandFile.Close()
		if readErr != nil || closeErr != nil || len(command) > 65536 {
			return settings, legacyLaunchError()
		}
		cwd, err = os.Readlink(filepath.Join(procDir, "cwd"))
		if err != nil {
			return settings, legacyLaunchError()
		}
		after, err := os.ReadFile(filepath.Join(procDir, "stat"))
		if err != nil || linuxProcessStart(before) == "" || linuxProcessStart(before) != linuxProcessStart(after) {
			return settings, legacyLaunchError()
		}
		args = strings.Split(strings.TrimSuffix(string(command), "\x00"), "\x00")
	case "darwin":
		// A default launch with whitespace-bearing paths cannot be recovered
		// unambiguously from ps. Preserve it through a manual migration instead.
		if strings.ContainsAny(executable+logPath, " \t\r\n\"'") {
			return settings, legacyLaunchError()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		pidText := strconv.Itoa(pid)
		before, err := exec.CommandContext(ctx, "ps", "-p", pidText, "-o", "lstart=").Output()
		if err != nil {
			return settings, legacyLaunchError()
		}
		command, err := exec.CommandContext(ctx, "ps", "-ww", "-p", pidText, "-o", "args=").Output()
		if err != nil || len(command) > 65536 {
			return settings, legacyLaunchError()
		}
		directory, err := exec.CommandContext(ctx, "lsof", "-a", "-p", pidText, "-d", "cwd", "-Fn").Output()
		if err != nil || len(directory) > 8192 {
			return settings, legacyLaunchError()
		}
		for _, line := range strings.Split(string(directory), "\n") {
			if strings.HasPrefix(line, "n/") {
				if cwd != "" {
					return settings, legacyLaunchError()
				}
				cwd = line[1:]
			}
		}
		after, err := exec.CommandContext(ctx, "ps", "-p", pidText, "-o", "lstart=").Output()
		if err != nil || len(bytes.TrimSpace(before)) == 0 || !bytes.Equal(before, after) {
			return settings, legacyLaunchError()
		}
		args = strings.Fields(string(command))
	default:
		return settings, legacyLaunchError()
	}
	if len(args) != 4 || !samePath(args[0], executable) || args[1] != "serve" || args[2] != "--log-file" || !samePath(args[3], logPath) || !filepath.IsAbs(cwd) {
		return settings, legacyLaunchError()
	}
	owned, _, err := isRampartServeProcess(pid)
	if err != nil || !owned {
		return settings, legacyLaunchError()
	}
	return serveLaunchSettings{WorkingDir: cwd, ConfigPath: "rampart.yaml", AuditDir: filepath.Join(home, ".rampart", "audit"), Mode: "enforce", Port: 9090, Addr: "127.0.0.1", LogFile: logPath}, nil
}

func linuxProcessStart(stat []byte) string {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return ""
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}

func serveLaunchCertificate(state serveState, home string, readFile func(string) ([]byte, error)) ([]byte, error) {
	certPath := filepath.Join(home, ".rampart", "tls", "cert.pem")
	if state.Launch != nil && state.Launch.TLSCert != "" {
		if err := state.Launch.validate(); err != nil {
			return nil, err
		}
		certPath = state.Launch.TLSCert
		if !filepath.IsAbs(certPath) {
			// Preserve kernel traversal through symlinks followed by '..', just
			// as the original relative path was opened from the service CWD.
			certPath = state.Launch.WorkingDir + string(os.PathSeparator) + certPath
		}
	}
	info, err := os.Stat(certPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, fmt.Errorf("previous service certificate is unavailable or not a bounded regular file; preserve the certificate reference for a manual restart")
	}
	data, err := readFile(certPath)
	if err != nil || len(data) > 1<<20 {
		return nil, fmt.Errorf("read previous service certificate")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("previous service certificate is not valid PEM")
	}
	return append([]byte(nil), data...), nil
}

func legacyLaunchError() error {
	return fmt.Errorf("legacy background launch settings or working directory cannot be reconstructed safely; stop and restart the service manually with its original flags using this CLI, then retry upgrade (the service has not been stopped)")
}
