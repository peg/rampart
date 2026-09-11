// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthIdentifiesOnlyTheServerStart(t *testing.T) {
	first := New(nil, nil, WithToken("synthetic-private-token"), WithMode("monitor"))
	second := New(nil, nil, WithToken("synthetic-private-token"))
	t.Cleanup(func() { _ = first.Shutdown(context.Background()) })
	t.Cleanup(func() { _ = second.Shutdown(context.Background()) })
	if first.RuntimeIdentity().InstanceID == "" || first.RuntimeIdentity().InstanceID == second.RuntimeIdentity().InstanceID {
		t.Fatal("server starts must have distinct opaque identities")
	}
	response := httptest.NewRecorder()
	first.handler().ServeHTTP(response, httptest.NewRequest("GET", "/healthz", nil))
	var health HealthResponse
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health.RuntimeIdentity != first.RuntimeIdentity() || health.Mode != "monitor" {
		t.Fatalf("health identity = %#v", health)
	}
	for _, private := range []string{"synthetic-private-token", `"pid":`, `"executable":`, `"arguments":`} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatalf("health exposed private field %s", private)
		}
	}
}
