// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License").

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// rampartHTTPClient is used for all outgoing HTTP requests from CLI commands
// (hook, approve, etc). The timeout prevents hangs when the Rampart server
// is unresponsive — without it, a stuck proxy blocks Claude indefinitely.
var rampartHTTPClient = newRampartHTTPClient(10 * time.Second)

// newRampartHTTPClient refuses redirects. Go's default client forwards bearer
// credentials to same-host redirects, and callers should never have to reason
// about whether a Rampart control request can leave its configured endpoint.
func newRampartHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// resolveTokenForEndpoint resolves an explicit, environment, or persisted
// token and binds it to a safe Rampart endpoint. Persisted tokens are local
// machine credentials and are never auto-attached to remote URLs. Remote
// administration remains available with an explicit token over HTTPS.
func resolveTokenForEndpoint(rawURL, explicitToken string) (string, string, error) {
	token := strings.TrimSpace(explicitToken)
	source := "flag"
	if token == "" {
		token, source = resolveTokenValue()
	}
	if token == "" {
		return "", source, nil
	}
	if err := validateCredentialEndpoint(rawURL, source); err != nil {
		return "", source, err
	}
	return token, source, nil
}

func validateCredentialEndpoint(rawURL, tokenSource string) error {
	trimmed := strings.TrimSpace(rawURL)
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("invalid Rampart endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsafe Rampart endpoint %q: scheme must be http or https", trimmed)
	}
	if u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return fmt.Errorf("invalid Rampart endpoint %q: absolute URL with a host is required", trimmed)
	}
	if u.User != nil {
		return fmt.Errorf("unsafe Rampart endpoint %q: embedded credentials are not allowed", trimmed)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("unsafe Rampart endpoint %q: query strings and fragments are not allowed", trimmed)
	}

	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if loopback {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("unsafe Rampart endpoint %q: bearer tokens require HTTPS for non-loopback hosts", trimmed)
	}
	if tokenSource == "file" {
		return fmt.Errorf("refusing to send the auto-discovered token to remote endpoint %q; set RAMPART_TOKEN explicitly for a trusted HTTPS endpoint", trimmed)
	}
	return nil
}

const maxRampartHealthResponseBytes = 4 << 10

type rampartHealthResponse struct {
	Service       string `json:"service"`
	Status        string `json:"status"`
	Mode          string `json:"mode"`
	UptimeSeconds *int   `json:"uptime_seconds"`
	Version       string `json:"version"`
}

// fetchRampartHealth verifies that healthURL belongs to a Rampart server, not
// merely that an unrelated process happens to return HTTP 200 on the same port.
// Service is optional so a newly upgraded CLI can still recognize an older
// Rampart daemon whose health payload predates the explicit identity marker.
func fetchRampartHealth(ctx context.Context, client *http.Client, healthURL string) (rampartHealthResponse, error) {
	var health rampartHealthResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return health, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return health, err
	}
	defer resp.Body.Close()

	if resp.Request == nil || resp.Request.URL.Scheme != req.URL.Scheme ||
		resp.Request.URL.Host != req.URL.Host || resp.Request.URL.Path != req.URL.Path {
		return health, fmt.Errorf("health check redirected away from %s", healthURL)
	}
	if resp.StatusCode != http.StatusOK {
		return health, fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRampartHealthResponseBytes+1))
	if err != nil {
		return health, fmt.Errorf("read health response: %w", err)
	}
	if len(body) > maxRampartHealthResponseBytes {
		return health, fmt.Errorf("health response exceeds %d bytes", maxRampartHealthResponseBytes)
	}
	if err := json.Unmarshal(body, &health); err != nil {
		return health, fmt.Errorf("decode health response: %w", err)
	}
	if health.Service != "" && health.Service != "rampart" {
		return health, fmt.Errorf("unexpected health service %q", health.Service)
	}
	if health.Status != "ok" {
		return health, fmt.Errorf("unexpected health status %q", health.Status)
	}
	switch health.Mode {
	case "enforce", "monitor", "disabled":
	default:
		return health, fmt.Errorf("unexpected health mode %q", health.Mode)
	}
	if health.UptimeSeconds == nil || *health.UptimeSeconds < 0 {
		return health, fmt.Errorf("invalid health uptime")
	}
	if strings.TrimSpace(health.Version) == "" {
		return health, fmt.Errorf("health response is missing a version")
	}
	return health, nil
}

func isRampartHealthReady(ctx context.Context, client *http.Client, healthURL string) bool {
	_, err := fetchRampartHealth(ctx, client, healthURL)
	return err == nil
}
