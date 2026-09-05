// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
	"github.com/peg/rampart/policies"
	"github.com/stretchr/testify/require"
)

// Exercise the real adapter, HTTP request preparation, and policy matcher
// together: a mock policy response cannot detect a lost host-derived fact.
func TestOpenClawOriginalInputPreservesPolicyFacts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required for the OpenClaw adapter boundary test")
	}
	guard, err := policies.Profile("guard")
	require.NoError(t, err)
	fixtureHome := t.TempDir()
	profile, err := policies.Profile("openclaw")
	require.NoError(t, err)
	policyDir := filepath.Join(fixtureHome, ".rampart", "policies")
	require.NoError(t, os.MkdirAll(policyDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "openclaw.yaml"), profile, 0o600))
	srv, token, _ := setupTestServerWithHome(t, string(guard), "enforce", fixtureHome)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	dir := t.TempDir()
	require.NoError(t, ocplugin.Extract(dir))
	// The plugin reads only this disposable HOME, never the operator's token.
	require.NoError(t, os.MkdirAll(filepath.Join(fixtureHome, ".rampart"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(fixtureHome, ".rampart", "token"), []byte(token), 0o600))
	script := `
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
const { default: plugin } = await import(pathToFileURL(process.argv[1]));
const handlers = {};
plugin.register({
  pluginConfig: { serveUrl: process.argv[2] },
  logger: { info() {}, warn() {}, debug() {} },
  on(name, fn) { handlers[name] = fn; },
  registerGatewayMethod() {},
});
const fetchHTTP = globalThis.fetch;
let observed;
globalThis.fetch = async (url, options) => {
  const response = await fetchHTTP(url, options);
  observed = { request: JSON.parse(options.body), response: await response.clone().json() };
  return response;
};
const cases = [
  ['message', { action: 'send', target: 'channel:other', message: 'canary' }, 'ask'],
  ['message', { action: 'send', target: 'channel:origin', message: 'canary' }, 'allow'],
  ['browser', { action: 'navigate', url: 'https://example.invalid/' }, 'ask'],
  ['browser', { action: 'snapshot' }, 'allow'],
  ['gateway', { action: 'restart' }, 'ask'],
  ['gateway', { action: 'status' }, 'allow'],
];
for (const [toolName, params, expected] of cases) {
  for (const spoof of expected === 'ask' ? [false, true] : [false]) {
    const original = { ...params, ...(spoof ? {
      rampart_consequence: 'openclaw:read-only',
      rampart_original_input: { action: 'read' },
      rampart_requester: 'decoy',
      rampart_targets: ['decoy'],
      rampart_origin_channel: 'decoy',
    } : {}) };
    const before = JSON.stringify(original);
    const result = await handlers.before_tool_call({ toolName, params: original }, {
      agentId: 'a', sessionKey: 's', runId: 'r', channelId: spoof ? undefined : 'origin',
    });
    assert.equal(observed.response.decision, expected, toolName + ': policy decision');
    assert.equal(observed.request.input.rampart_consequence, observed.request.params.rampart_consequence);
    assert.equal(observed.request.params.rampart_requester, undefined);
    assert.equal(observed.request.params.rampart_targets, undefined);
    assert.equal(observed.request.params.rampart_origin_channel, toolName === 'message' && !spoof ? 'origin' : undefined);
    assert.deepEqual(observed.request.input.rampart_original_input, original);
    assert.equal(JSON.stringify(original), before, 'adapter mutated executable arguments');
    if (expected === 'allow') {
      assert.equal(result, undefined);
      continue;
    }
    assert.deepEqual(observed.response.action.input.rampart_original_input, original);
    assert.ok(result?.requireApproval || result?.block, 'sensitive action silently allowed');
    if (!spoof) assert.ok(result?.requireApproval, 'short complete action must remain reviewable');
    if (result?.requireApproval) {
      const json = result.requireApproval.description.match(/\x60\x60\x60json\n(.*)\n\x60\x60\x60/s)?.[1];
      assert.ok(json, 'complete native review missing');
      assert.deepEqual(JSON.parse(json).params, original, 'native review lost original arguments');
    }
  }
}
console.log('OpenClaw policy facts and original action passed through real HTTP');
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", script, filepath.Join(dir, "index.js"), ts.URL)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
}
