package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestAuditFile(t *testing.T, dir string, events []audit.Event) string {
	t.Helper()
	path := filepath.Join(dir, "audit.jsonl")
	var buf bytes.Buffer
	for _, e := range chainTestEvents(t, "", events) {
		data, err := json.Marshal(e)
		require.NoError(t, err)
		buf.Write(data)
		buf.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
	return path
}

var testAuditEventSeq atomic.Int64

// chainTestEvents gives events unique IDs and a valid hash chain that
// continues from prevHash, as the audit writer would.
func chainTestEvents(t *testing.T, prevHash string, events []audit.Event) []audit.Event {
	t.Helper()
	chained := make([]audit.Event, len(events))
	for i, e := range events {
		e.ID = fmt.Sprintf("%s-%d", e.ID, testAuditEventSeq.Add(1))
		e.PrevHash = prevHash
		require.NoError(t, e.ComputeHash())
		prevHash = e.Hash
		chained[i] = e
	}
	return chained
}

func makeTestEvent(tool, command, path, action string, ts time.Time) audit.Event {
	params := map[string]any{}
	if command != "" {
		params["command"] = command
	}
	if path != "" {
		params["path"] = path
	}
	return audit.Event{
		ID:        "test-" + tool,
		Timestamp: ts,
		Agent:     "test-agent",
		Session:   "test-session",
		Tool:      tool,
		Request:   params,
		Decision:  audit.EventDecision{Action: action},
	}
}

func TestInitFromAudit_BasicGeneration(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	events := []audit.Event{
		makeTestEvent("exec", "npm install express", "", "allow", now),
		makeTestEvent("exec", "npm install lodash", "", "allow", now),
		makeTestEvent("exec", "git push origin main", "", "allow", now),
		makeTestEvent("read", "", "/home/user/project/src/main.go", "allow", now),
		makeTestEvent("write", "", "/home/user/project/src/util.go", "allow", now),
	}
	auditPath := writeTestAuditFile(t, dir, events)
	outputPath := filepath.Join(dir, "generated.yaml")

	var buf bytes.Buffer
	err := runInitFromAudit(&buf, fromAuditOptions{
		auditPath: auditPath,
		output:    outputPath,
	})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Analyzed 5 tool calls")
	assert.Contains(t, output, "Generated")
	assert.Contains(t, output, "Written to:")

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "npm install*")
	assert.Contains(t, content, "git push*")
}

func TestInitFromAudit_DeniedEventsSkipped(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	events := []audit.Event{
		makeTestEvent("exec", "npm install express", "", "allow", now),
		makeTestEvent("exec", "rm -rf /", "", "deny", now),
	}
	auditPath := writeTestAuditFile(t, dir, events)
	outputPath := filepath.Join(dir, "generated.yaml")

	var buf bytes.Buffer
	err := runInitFromAudit(&buf, fromAuditOptions{
		auditPath: auditPath,
		output:    outputPath,
	})
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "npm install")
	assert.NotContains(t, content, "rm -rf")
}

func TestInitFromAudit_Deduplication(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	events := []audit.Event{
		makeTestEvent("exec", "npm install express", "", "allow", now),
		makeTestEvent("exec", "npm install lodash", "", "allow", now),
		makeTestEvent("exec", "npm install react", "", "allow", now),
	}
	auditPath := writeTestAuditFile(t, dir, events)
	outputPath := filepath.Join(dir, "generated.yaml")

	var buf bytes.Buffer
	err := runInitFromAudit(&buf, fromAuditOptions{
		auditPath: auditPath,
		output:    outputPath,
	})
	require.NoError(t, err)

	output := buf.String()
	// All three should deduplicate to "npm install*"
	assert.Contains(t, output, "1 patterns")
}

func TestInitFromAudit_DryRun(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	events := []audit.Event{
		makeTestEvent("exec", "npm install express", "", "allow", now),
	}
	auditPath := writeTestAuditFile(t, dir, events)
	outputPath := filepath.Join(dir, "should-not-exist.yaml")

	var buf bytes.Buffer
	err := runInitFromAudit(&buf, fromAuditOptions{
		auditPath: auditPath,
		output:    outputPath,
		dryRun:    true,
	})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Dry run")
	assert.Contains(t, output, "npm install")

	_, err = os.Stat(outputPath)
	assert.True(t, os.IsNotExist(err), "dry run should not write file")
}

func TestInitFromAudit_SinceFilter(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().UTC().Add(-48 * time.Hour)
	recent := time.Now().UTC().Add(-30 * time.Minute)
	events := []audit.Event{
		makeTestEvent("exec", "old-command", "", "allow", old),
		makeTestEvent("exec", "recent-command", "", "allow", recent),
	}
	auditPath := writeTestAuditFile(t, dir, events)
	outputPath := filepath.Join(dir, "generated.yaml")

	var buf bytes.Buffer
	err := runInitFromAudit(&buf, fromAuditOptions{
		auditPath: auditPath,
		output:    outputPath,
		since:     "1h",
	})
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "recent-command")
	assert.NotContains(t, content, "old-command")
}

func TestInitFromAudit_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "empty.jsonl")
	require.NoError(t, os.WriteFile(auditPath, []byte(""), 0o644))

	var buf bytes.Buffer
	err := runInitFromAudit(&buf, fromAuditOptions{
		auditPath: auditPath,
	})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No audit events found")
}

func TestInitFromAudit_AllDenied(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	events := []audit.Event{
		makeTestEvent("exec", "rm -rf /", "", "deny", now),
	}
	auditPath := writeTestAuditFile(t, dir, events)

	var buf bytes.Buffer
	err := runInitFromAudit(&buf, fromAuditOptions{
		auditPath: auditPath,
	})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "none were allowed")
}

func TestInitFromAudit_Directory(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	// Write two separate JSONL files.
	e1 := chainTestEvents(t, "", []audit.Event{makeTestEvent("exec", "git status", "", "allow", now)})[0]
	d1, _ := json.Marshal(e1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit1.jsonl"), append(d1, '\n'), 0o644))

	e2 := chainTestEvents(t, e1.Hash, []audit.Event{makeTestEvent("exec", "go test ./...", "", "allow", now)})[0]
	d2, _ := json.Marshal(e2)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit2.jsonl"), append(d2, '\n'), 0o644))

	outputPath := filepath.Join(dir, "out", "generated.yaml")

	var buf bytes.Buffer
	err := runInitFromAudit(&buf, fromAuditOptions{
		auditPath: dir,
		output:    outputPath,
	})
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "git status")
	assert.Contains(t, content, "go test*")
}

// History that fails verification must never become allow rules unless the
// operator opts in, and then the policy says so.
func TestInitFromAudit_RejectsUnverifiedHistory(t *testing.T) {
	now := time.Now().UTC()
	valid := chainTestEvents(t, "", []audit.Event{
		makeTestEvent("exec", "git status", "", "allow", now),
		makeTestEvent("exec", "go test ./...", "", "allow", now),
	})
	encode := func(events ...audit.Event) string {
		var lines []string
		for _, e := range events {
			data, err := json.Marshal(e)
			require.NoError(t, err)
			lines = append(lines, string(data))
		}
		return strings.Join(lines, "\n") + "\n"
	}
	forged := valid[1]
	forged.Request = map[string]any{"command": "rampart setup claude-code --remove"}
	clean := encode(valid...)

	for name, content := range map[string]string{
		"forged record":    encode(valid[0], forged),
		"unhashed record":  encode(makeTestEvent("exec", "git status", "", "allow", now)),
		"malformed record": clean + "{\"id\":\"broken\",\n",
		"unknown field":    strings.Replace(clean, `"tool":"exec"`, `"tool":"exec","note":"x"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			for _, asDir := range []bool{false, true} {
				dir := t.TempDir()
				path := filepath.Join(dir, "audit.jsonl")
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
				source := path
				if asDir {
					source = dir
				}
				output := filepath.Join(t.TempDir(), "generated.yaml")
				var buf bytes.Buffer
				err := runInitFromAudit(&buf, fromAuditOptions{auditPath: source, output: output})
				require.Error(t, err, "dir=%v", asDir)
				assert.Contains(t, err.Error(), "--allow-unverified")
				assert.NoFileExists(t, output)
			}
		})
	}

	t.Run("broken linkage across files", func(t *testing.T) {
		dir := t.TempDir()
		first := chainTestEvents(t, "", []audit.Event{makeTestEvent("exec", "git status", "", "allow", now)})
		second := chainTestEvents(t, "", []audit.Event{makeTestEvent("exec", "go test ./...", "", "allow", now)})
		require.NoError(t, os.WriteFile(filepath.Join(dir, "audit1.jsonl"), []byte(encode(first...)), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "audit2.jsonl"), []byte(encode(second...)), 0o600))
		var buf bytes.Buffer
		err := runInitFromAudit(&buf, fromAuditOptions{auditPath: dir, dryRun: true})
		require.Error(t, err)
		assert.NotContains(t, buf.String(), "go test")
	})

	t.Run("allow-unverified opts in and marks the policy", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.jsonl")
		require.NoError(t, os.WriteFile(path, []byte(encode(valid[0], forged)), 0o600))
		var buf bytes.Buffer
		require.NoError(t, runInitFromAudit(&buf, fromAuditOptions{auditPath: path, dryRun: true, allowUnverified: true}))
		assert.Contains(t, buf.String(), "WARNING: generated from audit history that was not verified")
	})
}
