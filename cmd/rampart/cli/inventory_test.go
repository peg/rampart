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

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
)

func TestInventoryJSONKeyFields(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	configPath := filepath.Join(home, "rampart.yaml")
	writeTestPolicyFile(t, configPath)

	auditDir := filepath.Join(home, ".rampart", "audit")
	writeTestAuditEvents(t, auditDir, []audit.Event{
		{ID: "evt-1", Timestamp: time.Now().UTC(), Tool: "exec", Decision: audit.EventDecision{Action: "allow"}},
		{ID: "evt-2", Timestamp: time.Now().UTC(), Tool: "exec", Decision: audit.EventDecision{Action: "deny"}},
		{ID: "evt-3", Timestamp: time.Now().UTC(), Tool: "exec", Decision: audit.EventDecision{Action: "watch"}},
		{ID: "evt-4", Timestamp: time.Now().UTC(), Tool: "exec", Decision: audit.EventDecision{Action: "ask"}},
	})

	stdout, _, err := runCLI(t, "--config", configPath, "inventory", "--json")
	if err != nil {
		t.Fatalf("inventory --json failed: %v", err)
	}

	var got inventorySnapshot
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("inventory --json output is not valid JSON: %v\nOutput:\n%s", err, stdout)
	}

	if got.SchemaVersion != inventorySchemaVersion {
		t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, inventorySchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339, got.GeneratedAt); err != nil {
		t.Fatalf("generated_at is not RFC3339: %q (%v)", got.GeneratedAt, err)
	}
	if strings.TrimSpace(got.BuildVersion) == "" {
		t.Fatal("build_version is empty")
	}

	if len(got.PolicyInventory.Files) == 0 {
		t.Fatal("expected at least one policy inventory entry")
	}
	policyEntry, found := findPolicyEntry(got.PolicyInventory.Files, filepath.Base(configPath))
	if !found {
		t.Fatalf("missing policy inventory entry for %s", filepath.Base(configPath))
	}
	if !policyEntry.Valid || policyEntry.LoadStatus != "loaded" {
		t.Fatalf("expected loaded policy entry, got valid=%v status=%q", policyEntry.Valid, policyEntry.LoadStatus)
	}
	if policyEntry.DefaultAction != "deny" {
		t.Fatalf("default_action = %q, want %q", policyEntry.DefaultAction, "deny")
	}
	if policyEntry.PolicyCount != 1 {
		t.Fatalf("policy_count = %d, want 1", policyEntry.PolicyCount)
	}
	if strings.Contains(policyEntry.Path, home) {
		t.Fatalf("policy path leaked full home path: %q", policyEntry.Path)
	}

	if !got.AuditInventory.DirectoryAvailable {
		t.Fatal("expected audit directory to be available")
	}
	if got.AuditInventory.TodayEvents.Allow != 1 || got.AuditInventory.TodayEvents.Deny != 1 || got.AuditInventory.TodayEvents.Watch != 1 || got.AuditInventory.TodayEvents.Pending != 1 {
		t.Fatalf("unexpected today event counts: %+v", got.AuditInventory.TodayEvents)
	}
	if got.AuditInventory.TodayEvents.Total != 4 {
		t.Fatalf("today total = %d, want 4", got.AuditInventory.TodayEvents.Total)
	}
}

func TestInventoryJSONPolicyInvalidHandling(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	configPath := filepath.Join(home, "rampart.yaml")
	writeTestPolicyFile(t, configPath)

	policyDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir policy dir: %v", err)
	}
	invalidPath := filepath.Join(policyDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte("version: \"1\"\npolicies:\n  - name: broken\n    rules: [\n"), 0o644); err != nil {
		t.Fatalf("write invalid policy: %v", err)
	}

	stdout, _, err := runCLI(t, "--config", configPath, "inventory", "--json")
	if err != nil {
		t.Fatalf("inventory --json failed: %v", err)
	}

	var got inventorySnapshot
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("inventory --json output is not valid JSON: %v\nOutput:\n%s", err, stdout)
	}

	invalidEntry, found := findPolicyEntry(got.PolicyInventory.Files, "invalid.yaml")
	if !found {
		t.Fatalf("missing inventory entry for invalid policy file: %+v", got.PolicyInventory.Files)
	}
	if invalidEntry.Valid {
		t.Fatalf("invalid policy unexpectedly marked valid: %+v", invalidEntry)
	}
	if invalidEntry.LoadStatus != "invalid" {
		t.Fatalf("load_status = %q, want %q", invalidEntry.LoadStatus, "invalid")
	}
	if strings.TrimSpace(invalidEntry.Error) == "" {
		t.Fatal("expected invalid policy error message")
	}
	if invalidEntry.PolicyCount != 0 {
		t.Fatalf("invalid policy_count = %d, want 0", invalidEntry.PolicyCount)
	}
	if strings.Contains(invalidEntry.Path, home) {
		t.Fatalf("invalid policy path leaked full home path: %q", invalidEntry.Path)
	}
	if got.PolicyInventory.InvalidCount < 1 {
		t.Fatalf("invalid_count = %d, want at least 1", got.PolicyInventory.InvalidCount)
	}
}

func writeTestPolicyFile(t *testing.T, path string) {
	t.Helper()
	content := `version: "1"
default_action: deny
policies:
  - name: test-allow
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["echo *"]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
}

func writeTestAuditEvents(t *testing.T, auditDir string, events []audit.Event) {
	t.Helper()
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}

	path := filepath.Join(auditDir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create audit file: %v", err)
	}
	defer file.Close()

	for i, event := range events {
		if event.ID == "" {
			event.ID = fmt.Sprintf("evt-%d", i+1)
		}
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now().UTC()
		}
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal audit event: %v", err)
		}
		if _, err := file.Write(append(data, '\n')); err != nil {
			t.Fatalf("write audit event: %v", err)
		}
	}
}

func findPolicyEntry(entries []inventoryPolicyFile, fileName string) (inventoryPolicyFile, bool) {
	for _, entry := range entries {
		if entry.FileName == fileName {
			return entry, true
		}
	}
	return inventoryPolicyFile{}, false
}
