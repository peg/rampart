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

package signing

import (
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestSignAndValidateRoundtrip(t *testing.T) {
	signer := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	expiresAt := time.Now().Add(5 * time.Minute)

	raw := signer.SignURL("http://localhost:9090", "approval-1", expiresAt)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse signed URL: %v", err)
	}
	q := u.Query()
	sig := q.Get("sig")
	exp, err := parseExp(q.Get("exp"))
	if err != nil {
		t.Fatalf("parse exp: %v", err)
	}

	if !signer.ValidateSignature("approval-1", sig, exp) {
		t.Fatal("expected signature validation to succeed")
	}
}

func TestExpiredSignatureRejected(t *testing.T) {
	signer := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	exp := time.Now().Add(-time.Minute).Unix()
	sig := signer.signature("approval-1", exp)

	if signer.ValidateSignature("approval-1", sig, exp) {
		t.Fatal("expected expired signature to be rejected")
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	signer := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	exp := time.Now().Add(5 * time.Minute).Unix()
	sig := signer.signature("approval-1", exp) + "tampered"

	if signer.ValidateSignature("approval-1", sig, exp) {
		t.Fatal("expected tampered signature to be rejected")
	}
}

func TestWrongApprovalIDRejected(t *testing.T) {
	signer := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	exp := time.Now().Add(5 * time.Minute).Unix()
	sig := signer.signature("approval-1", exp)

	if signer.ValidateSignature("approval-2", sig, exp) {
		t.Fatal("expected signature for wrong approval ID to be rejected")
	}
}

func parseExp(v string) (int64, error) {
	return strconv.ParseInt(v, 10, 64)
}
