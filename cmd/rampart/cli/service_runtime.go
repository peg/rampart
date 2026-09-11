// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peg/rampart/internal/proxy"
)

// serviceRuntimeObservation records what the selected endpoint actually served.
// It contains no credentials, PID, executable path, or process arguments.
type serviceRuntimeObservation struct {
	proxy.RuntimeIdentity
	Endpoint string `json:"endpoint"`
}

func runtimeIdentified(identity proxy.RuntimeIdentity) bool {
	if len(identity.InstanceID) < 16 || len(identity.InstanceID) > 128 || strings.TrimSpace(identity.Commit) == "" {
		return false
	}
	for _, c := range identity.InstanceID {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return strings.TrimSpace(identity.Version) != "" && (identity.Mode == "enforce" || identity.Mode == "monitor" || identity.Mode == "disabled")
}

func serviceEndpoint(raw string) (string, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", fmt.Errorf("service endpoint must be an absolute HTTP(S) origin without credentials, paths, queries, or fragments")
	}
	return endpoint, nil
}

func observeServiceRuntime(ctx context.Context, endpoint string, timeout time.Duration) (serviceRuntimeObservation, error) {
	var observed serviceRuntimeObservation
	endpoint, err := serviceEndpoint(endpoint)
	if err != nil {
		return observed, err
	}
	observed.Endpoint = endpoint
	client, closeClient, err := serviceRuntimeClient(endpoint, timeout)
	if err != nil {
		return observed, err
	}
	defer closeClient()
	health, err := fetchRampartHealth(ctx, client, endpoint+"/healthz")
	if err != nil {
		return observed, err
	}
	observed.RuntimeIdentity = health.RuntimeIdentity
	return observed, nil
}

// serviceRuntimeClient is shared by health and preflight so both requests use
// the same endpoint trust. No redirected request receives control credentials.
func serviceRuntimeClient(endpoint string, timeout time.Duration) (*http.Client, func(), error) {
	client := *rampartHTTPClient
	client.Timeout = timeout
	client.CheckRedirect = newRampartHTTPClient(timeout).CheckRedirect
	if strings.HasPrefix(endpoint, "https://") && isLoopbackURL(endpoint) {
		if home, err := os.UserHomeDir(); err == nil {
			if state, err := readPrivateServeState(filepath.Join(home, ".rampart")); err == nil && state.Launch != nil && state.Launch.TLSCert != "" {
				stateURL, stateErr := validateLocalServeStateURL(state)
				u, _ := url.Parse(endpoint)
				if stateErr == nil && stateURL.Scheme == u.Scheme && stateURL.Port() == u.Port() {
					owned, _, identityErr := isRampartServeProcess(state.PID)
					if identityErr == nil && owned {
						certificate, certErr := serveLaunchCertificate(state, home, os.ReadFile)
						if certErr != nil {
							return nil, func() {}, certErr
						}
						return localServeHealthClient(u, home, os.ReadFile, timeout, certificate)
					}
				}
			}
			if _, certErr := os.Stat(filepath.Join(home, ".rampart", "tls", "cert.pem")); !os.IsNotExist(certErr) {
				u, _ := url.Parse(endpoint)
				return localServeHealthClient(u, home, os.ReadFile, timeout)
			}
		}
	}
	return &client, func() {}, nil
}

// integrationServiceEndpoint follows the endpoint consumed by that integration,
// not an unrelated healthy default service. Local hooks do not require HTTP.
func integrationServiceEndpoint(driver integrationDriver) (string, error) {
	if !driver.ServiceRequired {
		return "", nil
	}
	if driver.OpenClaw {
		config, err := openClawAssuranceConfiguration()
		if err != nil {
			return "", err
		}
		return serviceEndpoint(config.Plugin.ServeURL)
	}
	endpoint, err := resolveServeURLStrict("", fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return "", err
	}
	return serviceEndpoint(endpoint)
}

func readPrivateServeState(dir string) (serveState, error) {
	var state serveState
	data, err := readPrivateServeStateData(dir)
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(data, &state)
	return state, err
}

// Restart preparation is stricter than health/URL discovery. An older CLI
// must refuse newer launch options rather than discard them during a restart.
func readPrivateServeStateForRestart(dir string) (serveState, error) {
	var state serveState
	data, err := readPrivateServeStateData(dir)
	if err != nil {
		return state, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, fmt.Errorf("saved runtime state has unsupported or invalid fields; restart manually with the original options before upgrading")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return state, fmt.Errorf("saved runtime state contains trailing data")
	}
	return state, nil
}

func readPrivateServeStateData(dir string) ([]byte, error) {
	path := filepath.Join(dir, serveStateFile)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxServeStateFileBytes || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("serve.state is not a bounded private regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxServeStateFileBytes {
		return nil, fmt.Errorf("serve.state exceeds size limit")
	}
	return data, nil
}

func ownedServiceRuntime(observed serviceRuntimeObservation) bool {
	if !runtimeIdentified(observed.RuntimeIdentity) || !isLoopbackURL(observed.Endpoint) {
		return false
	}
	dir, err := rampartDir()
	if err != nil {
		return false
	}
	state, err := readPrivateServeState(dir)
	if err != nil || state.PID <= 0 || state.RuntimeIdentity != observed.RuntimeIdentity {
		return false
	}
	stateURL, err := validateLocalServeStateURL(state)
	if err != nil {
		return false
	}
	endpoint, _ := url.Parse(observed.Endpoint)
	if stateURL.Scheme != endpoint.Scheme || stateURL.Port() != endpoint.Port() {
		return false
	}
	owned, _, err := isRampartServeProcess(state.PID)
	return err == nil && owned
}
