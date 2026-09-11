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
const fetchHTTP = globalThis.fetch;
// Initialize Node's real HTTP client before measuring a policy exchange. This
// test covers policy facts, not cold client startup; the Go context bounds the
// readiness request and the complete script without retrying either request.
const readinessStarted = performance.now();
const readiness = await fetchHTTP(new URL('/healthz', process.argv[2]));
assert.equal(readiness.status, 200, 'policy fixture readiness failed');
await readiness.arrayBuffer();
const readinessMs = Math.round(performance.now() - readinessStarted);
console.log('OpenClaw policy HTTP fixture ready in ' + readinessMs + 'ms');
const handlers = {};
const warnings = [];
plugin.register({
  pluginConfig: { serveUrl: process.argv[2] },
  logger: { info() {}, warn(message) { warnings.push(message); }, debug() {} },
  on(name, fn) { handlers[name] = fn; },
  registerGatewayMethod() {},
});
let observed;
let requestCount = 0;
globalThis.fetch = async (url, options) => {
  const started = performance.now();
  const attempt = { request: JSON.parse(options.body) };
  observed = attempt;
  requestCount++;
  try {
    const response = await fetchHTTP(url, options);
    attempt.status = response.status;
    attempt.response = await response.clone().json();
    return response;
  } catch (error) {
    attempt.error = { name: error?.name, code: error?.code ?? error?.cause?.code };
    throw error;
  } finally {
    attempt.elapsedMs = Math.round(performance.now() - started);
    attempt.aborted = options.signal?.aborted === true;
  }
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
    observed = undefined;
    requestCount = 0;
    warnings.length = 0;
    const result = await handlers.before_tool_call({ toolName, params: original }, {
      agentId: 'a', sessionKey: 's', runId: 'r', channelId: spoof ? undefined : 'origin',
    });
    const exchange = observed && {
      status: observed.status, error: observed.error,
      elapsedMs: observed.elapsedMs, aborted: observed.aborted,
    };
    assert.ok(observed?.response, toolName + ': HTTP policy exchange did not complete: ' +
      JSON.stringify({ spoof, readinessMs, requestCount, exchange, result, warnings }));
    assert.equal(requestCount, 1, toolName + ': expected one fresh HTTP policy exchange');
    assert.equal(observed.status, 200, toolName + ': HTTP policy exchange status');
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
