package engine

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhookActionParsing(t *testing.T) {
	yaml := `
version: "1"
default_action: deny
policies:
  - name: webhook-check
    match:
      tool: exec
    rules:
      - action: webhook
        when:
          command_matches: ["*rm -rf*"]
        webhook:
          url: "http://localhost:8090/verify"
          timeout: 3s
          fail_open: false
`
	eng := setupEngine(t, yaml)
	require.Equal(t, 1, eng.PolicyCount())

	call := execCall("test-agent", "rm -rf /tmp/foo")
	decision := eng.Evaluate(call)

	assert.Equal(t, ActionWebhook, decision.Action)
	require.NotNil(t, decision.WebhookConfig)
	assert.Equal(t, "http://localhost:8090/verify", decision.WebhookConfig.URL)
	assert.Equal(t, 3*1e9, float64(decision.WebhookConfig.EffectiveTimeout()))
	assert.False(t, decision.WebhookConfig.EffectiveFailOpen())
}

func TestWebhookActionDefaultTimeout(t *testing.T) {
	yaml := `
version: "1"
default_action: deny
policies:
  - name: webhook-defaults
    match:
      tool: exec
    rules:
      - action: webhook
        when:
          command_matches: ["*deploy*"]
        webhook:
          url: "http://localhost:9090/check"
`
	eng := setupEngine(t, yaml)
	call := execCall("agent", "deploy prod")
	decision := eng.Evaluate(call)

	assert.Equal(t, ActionWebhook, decision.Action)
	require.NotNil(t, decision.WebhookConfig)
	assert.Equal(t, 5*1e9, float64(decision.WebhookConfig.EffectiveTimeout()))
	assert.False(t, decision.WebhookConfig.EffectiveFailOpen())
}

func TestWebhookValidationRequiresURL(t *testing.T) {
	yaml := `
version: "1"
default_action: deny
policies:
  - name: bad-webhook
    match:
      tool: exec
    rules:
      - action: webhook
        when:
          command_matches: ["*"]
`
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	require.NoError(t, writeFile(path, yaml))

	store := NewFileStore(path)
	_, err := New(store, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook action requires webhook.url")
}

func TestWebhookValidationRequiresURLNotEmpty(t *testing.T) {
	yaml := `
version: "1"
default_action: deny
policies:
  - name: bad-webhook
    match:
      tool: exec
    rules:
      - action: webhook
        when:
          command_matches: ["*"]
        webhook:
          url: ""
`
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	require.NoError(t, writeFile(path, yaml))

	store := NewFileStore(path)
	_, err := New(store, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook action requires webhook.url")
}

func TestWebhookNoMatchFallsToDefault(t *testing.T) {
	yaml := `
version: "1"
default_action: allow
policies:
  - name: webhook-check
    match:
      tool: exec
    rules:
      - action: webhook
        when:
          command_matches: ["*rm -rf*"]
        webhook:
          url: "http://localhost:8090/verify"
`
	eng := setupEngine(t, yaml)
	call := execCall("agent", "ls -la")
	decision := eng.Evaluate(call)

	// No rule matched, falls to default
	assert.Equal(t, ActionAllow, decision.Action)
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
