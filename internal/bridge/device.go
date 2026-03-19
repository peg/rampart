// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bridge

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// deviceIdentity holds the Ed25519 keypair used to authenticate the bridge
// with the OpenClaw gateway. Without device identity, the gateway silently
// strips the bridge's operator.approvals scope, preventing it from receiving
// exec.approval.requested events.
type deviceIdentity struct {
	DeviceID   string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// deviceIdentityFile is the on-disk format used by OpenClaw.
type deviceIdentityFile struct {
	Version       int    `json:"version"`
	DeviceID      string `json:"deviceId"`
	PublicKeyPem  string `json:"publicKeyPem"`
	PrivateKeyPem string `json:"privateKeyPem"`
}

// loadOpenClawDeviceIdentity reads the device identity that OpenClaw already
// created at ~/.openclaw/identity/device.json. Reusing this identity avoids
// the first-time pairing step since it's already approved by the gateway.
func loadOpenClawDeviceIdentity() (*deviceIdentity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("device identity: resolve home: %w", err)
	}
	path := filepath.Join(home, ".openclaw", "identity", "device.json")
	return loadDeviceIdentityFromFile(path)
}

func loadDeviceIdentityFromFile(path string) (*deviceIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("device identity: read %s: %w", path, err)
	}

	var f deviceIdentityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("device identity: parse: %w", err)
	}

	pub, err := parseEd25519PublicKey(f.PublicKeyPem)
	if err != nil {
		return nil, fmt.Errorf("device identity: public key: %w", err)
	}

	priv, err := parseEd25519PrivateKey(f.PrivateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("device identity: private key: %w", err)
	}

	return &deviceIdentity{
		DeviceID:   f.DeviceID,
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// buildDeviceAuthPayload builds the connect payload and signs it with the
// device private key, matching the buildDeviceAuthPayloadV3 format used by
// the OpenClaw JS GatewayClient.
//
// The payload is a pipe-delimited string (NOT JSON) signed with Ed25519:
//
//	"v3|{deviceId}|{clientId}|{clientMode}|{role}|{scopes}|{signedAtMs}|{token}|{nonce}|{platform}|{deviceFamily}"
//
// The signature and public key are base64url-encoded (no padding).
func (d *deviceIdentity) buildDeviceAuthPayload(nonce, token string, scopes []string) (map[string]any, error) {
	signedAtMs := time.Now().UnixMilli()

	// normalizeDeviceMetadataForAuth: trim and lowercase, empty string if blank.
	platform := strings.ToLower(strings.TrimSpace(runtime.GOOS))
	deviceFamily := "" // not set for desktop/server clients

	// Build V3 pipe-delimited payload — must match buildDeviceAuthPayloadV3 exactly.
	scopesStr := strings.Join(scopes, ",")
	parts := []string{
		"v3",
		d.DeviceID,
		"gateway-client",
		"backend",
		"operator",
		scopesStr,
		fmt.Sprintf("%d", signedAtMs),
		token,
		nonce,
		platform,
		deviceFamily,
	}
	payloadStr := strings.Join(parts, "|")

	sig := ed25519.Sign(d.privateKey, []byte(payloadStr))

	return map[string]any{
		"id":        d.DeviceID,
		"publicKey": base64.RawURLEncoding.EncodeToString(d.publicKey),
		"signature": base64.RawURLEncoding.EncodeToString(sig),
		"signedAt":  signedAtMs,
		"nonce":     nonce,
	}, nil
}

func parseEd25519PublicKey(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 public key")
	}
	return pub, nil
}

func parseEd25519PrivateKey(pemStr string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 private key")
	}
	return priv, nil
}
