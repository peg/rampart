import plugin from './index.js';

const ctx = {
  agentId: 'main',
  sessionKey: 'agent:main:provider-surface',
  runId: 'provider-surface-run',
};

function createApi(pluginConfig = {}) {
  const handlers = {};
  const gatewayMethods = {};
  const logs = [];
  return {
    handlers,
    gatewayMethods,
    logs,
    api: {
      pluginConfig,
      logger: {
        info: (...a) => logs.push(['info', a.join(' ')]),
        warn: (...a) => logs.push(['warn', a.join(' ')]),
        debug: (...a) => logs.push(['debug', a.join(' ')]),
      },
      on: (name, fn) => { handlers[name] = fn; },
      registerGatewayMethod: (name, fn) => { gatewayMethods[name] = fn; },
    },
  };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function parseBody(call) {
  return JSON.parse(call.opts.body);
}

function fetchJson(result) {
  return { ok: true, status: 200, json: async () => result, text: async () => JSON.stringify(result) };
}

async function withPlugin({ name, fetchImpl, pluginConfig = {}, invoke }) {
  const { api, handlers, gatewayMethods, logs } = createApi(pluginConfig);
  const originalFetch = global.fetch;
  global.fetch = fetchImpl;
  try {
    plugin.register(api);
    return await invoke({ handlers, gatewayMethods, logs });
  } catch (err) {
    err.message = `${name}: ${err.message}`;
    throw err;
  } finally {
    global.fetch = originalFetch;
  }
}

async function runPolicyScenario({ name, event, expectedTool, expectedCommand, response = { decision: 'allow', allowed: true }, assertResult, context = ctx }) {
  const calls = [];
  const result = await withPlugin({
    name,
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      assert(String(url).includes(`/v1/tool/${encodeURIComponent(expectedTool)}`), `expected /v1/tool/${expectedTool}, got ${url}`);
      return fetchJson(response);
    },
    invoke: async ({ handlers }) => {
      const before = handlers.before_tool_call;
      assert(typeof before === 'function', 'before_tool_call handler missing');
      return await before(event, context);
    },
  });

  assert(calls.length === 1, `expected one policy call, got ${calls.length}`);
  const body = parseBody(calls[0]);
  assert(body.openclaw_hosted === true, 'expected openclaw_hosted=true');
  assert(body.skip_pending_approval === true, 'expected skip_pending_approval=true');
  assert(body.agent === 'main', `expected the original OpenClaw identity, got ${body.agent}`);
  assert(body.params.rampart_integration === 'openclaw', 'expected OpenClaw integration marker');
  if (expectedCommand !== undefined) {
    assert(body.params.command === expectedCommand, `expected command ${expectedCommand}, got ${JSON.stringify(body.params)}`);
  }
  if (assertResult) assertResult(result, body);
  return { result, body };
}

const scenarios = [];

await runPolicyScenario({
  name: 'canonical-exec-flat-command',
  event: { toolName: 'exec', params: { command: 'echo flat-provider' } },
  expectedTool: 'exec',
  expectedCommand: 'echo flat-provider',
});
scenarios.push('canonical-exec-flat-command');

await runPolicyScenario({
  name: 'canonical-exec-nested-input-command',
  event: { toolName: 'exec', params: { input: { command: 'echo nested-provider' } } },
  expectedTool: 'exec',
  expectedCommand: 'echo nested-provider',
});
scenarios.push('canonical-exec-nested-input-command');

await runPolicyScenario({
  name: 'policy-response-cannot-rewrite-tool-params',
  event: { toolName: 'exec', params: { command: 'echo original' } },
  expectedTool: 'exec',
  expectedCommand: 'echo original',
  response: {
    decision: 'allow',
    allowed: true,
    params: { command: 'echo injected' },
  },
  assertResult: (result) => {
    assert(result === undefined, 'policy response unexpectedly rewrote executable params');
  },
});
scenarios.push('policy-response-cannot-rewrite-tool-params');

for (const [name, toolName, params, expectedCommand] of [
  ['bash-cmd-alias', 'bash', { cmd: 'echo bash-provider' }, 'echo bash-provider'],
  ['shell-script-alias', 'shell', { script: 'echo shell-provider' }, 'echo shell-provider'],
  ['terminal-args-command-alias', 'terminal', { args: { command: 'echo terminal-provider' } }, 'echo terminal-provider'],
]) {
  await runPolicyScenario({
    name,
    event: { toolName, params },
    expectedTool: 'exec',
    expectedCommand,
  });
  scenarios.push(name);
}

await runPolicyScenario({
  name: 'read-tool-policy-surface',
  event: { toolName: 'read', params: { path: '/tmp/provider-fixture.txt' } },
  expectedTool: 'read',
});
scenarios.push('read-tool-policy-surface');

let unknownToolPolicyCalls = 0;
const unknownTool = await withPlugin({
  name: 'unknown-tool-fails-closed',
  fetchImpl: async () => {
    unknownToolPolicyCalls += 1;
    return fetchJson({ decision: 'allow', allowed: true, policy: 'allow-unmatched' });
  },
  invoke: async ({ handlers }) => handlers.before_tool_call(
    { toolName: 'future_mutating_tool', params: { target: '/tmp/unsafe' } },
    ctx,
  ),
});
assert(unknownTool?.block === true, 'an unclassified future tool must be blocked locally');
assert(unknownToolPolicyCalls === 0, 'an unclassified tool must not reach the permissive service fallback');
scenarios.push('unknown-tool-fails-closed');

const adapterFault = await withPlugin({
  name: 'adapter-exception-fails-closed',
  fetchImpl: async () => fetchJson({ decision: 'allow', allowed: true }),
  invoke: async ({ handlers }) => handlers.before_tool_call(
    {
      toolName: 'write',
      params: new Proxy({}, {
        ownKeys: () => { throw new TypeError('malformed host params'); },
      }),
    },
    ctx,
  ),
});
assert(adapterFault?.block === true, 'an internal adapter exception must become an explicit block');
assert(adapterFault.blockReason.includes('policy adapter error'), `unexpected adapter block: ${adapterFault.blockReason}`);
scenarios.push('adapter-exception-fails-closed');

const patchCalls = [];
const patchResult = await withPlugin({
  name: 'apply-patch-evaluates-every-path',
  fetchImpl: async (url, opts = {}) => {
    const body = parseBody({ opts });
    patchCalls.push({ url: String(url), body });
    const denied = body.params.path === 'secrets/.env';
    return fetchJson({
      decision: denied ? 'deny' : 'allow',
      allowed: !denied,
      policy: denied ? 'protected-environment' : 'workspace-write',
      message: denied ? 'protected environment file' : 'workspace write allowed',
    });
  },
  invoke: async ({ handlers }) => handlers.before_tool_call(
    {
      toolName: 'apply_patch',
      params: {
        input: [
          '*** Begin Patch',
          '*** Add File: safe.txt',
          '+safe',
          '*** Update File: secrets/.env',
          '@@',
          '-old',
          '+new',
          '*** End Patch',
        ].join('\n'),
      },
      derivedPaths: ['safe.txt', 'secrets/.env'],
    },
    ctx,
  ),
});
assert(patchResult?.block === true, 'one denied apply_patch target must block the whole patch');
assert(patchCalls.length === 2, `expected both patch paths to be evaluated, got ${patchCalls.length}`);
assert(patchCalls.every((call) => call.url.includes('/v1/tool/edit')), 'apply_patch must map to edit policy');
assert(
  patchCalls.map((call) => call.body.params.path).join(',') === 'safe.txt,secrets/.env',
  `unexpected patch paths: ${JSON.stringify(patchCalls)}`,
);
scenarios.push('apply-patch-evaluates-every-path');

const patchAskCalls = [];
const patchAsk = await withPlugin({
  name: 'apply-patch-approval-describes-winning-path',
  fetchImpl: async (url, opts = {}) => {
    const body = parseBody({ opts });
    patchAskCalls.push({ url: String(url), body });
    return fetchJson(body.params.path === 'production/config.yaml'
      ? { decision: 'ask', allowed: false, policy: 'production-write', message: 'production change' }
      : { decision: 'allow', allowed: true, policy: 'workspace-write' });
  },
  invoke: async ({ handlers }) => handlers.before_tool_call(
    {
      toolName: 'apply_patch',
      params: {
        input: [
          '*** Begin Patch',
          '*** Update File: safe.txt',
          '@@',
          '-old',
          '+new',
          '*** Update File: production/config.yaml',
          '@@',
          '-old',
          '+new',
          '*** End Patch',
        ].join('\n'),
      },
    },
    ctx,
  ),
});
assert(patchAsk?.requireApproval, 'expected approval for the restrictive patch target');
assert(
  patchAsk.requireApproval.description.includes('production/config.yaml'),
  `approval must identify the path that triggered ask: ${patchAsk.requireApproval.description}`,
);
assert(patchAskCalls.length === 2, `expected two policy checks, got ${patchAskCalls.length}`);
scenarios.push('apply-patch-approval-describes-winning-path');

for (const [name, params, context, expectedConsequence] of [
  [
    'message-reply-to-originating-channel',
    { action: 'send', target: 'channel:12345', message: 'Routine reply' },
    { ...ctx, channelId: '12345', messageProvider: 'discord' },
    'openclaw:routine-reply',
  ],
  [
    'message-send-to-other-channel',
    { action: 'send', target: 'channel:99999', message: 'Cross-channel send' },
    { ...ctx, channelId: '12345', messageProvider: 'discord' },
    'openclaw:external-message',
  ],
  [
    'message-suffix-collision-is-external',
    { action: 'send', target: 'channel:external:12345', message: 'Cross-channel suffix collision' },
    { ...ctx, channelId: '12345', messageProvider: 'discord' },
    'openclaw:external-message',
  ],
  [
    'message-provider-collision-is-external',
    { action: 'send', target: 'telegram:channel:12345', message: 'Cross-provider send' },
    { ...ctx, channelId: '12345', messageProvider: 'discord' },
    'openclaw:external-message',
  ],
  [
    'message-read-is-read-only',
    { action: 'read', target: 'channel:12345' },
    { ...ctx, channelId: '12345', messageProvider: 'discord' },
    'openclaw:read-only',
  ],
  [
    'message-delete-is-mutation',
    { action: 'delete', target: 'channel:12345', messageId: 'abc' },
    { ...ctx, channelId: '12345', messageProvider: 'discord' },
    'openclaw:mutation',
  ],
]) {
  await runPolicyScenario({
    name,
    event: { toolName: 'message', params },
    expectedTool: 'message',
    context,
    assertResult: (_result, body) => {
      assert(
        body.params.rampart_consequence === expectedConsequence,
        `expected ${expectedConsequence}, got ${JSON.stringify(body.params)}`,
      );
      assert(
        !Object.prototype.hasOwnProperty.call(params, 'rampart_consequence'),
        'host-derived policy fields must not mutate executable tool params',
      );
    },
  });
  scenarios.push(name);
}

for (const [name, params, expectedConsequence, expectedDomain] of [
  [
    'browser-status-is-read-only',
    { action: 'status' },
    'openclaw:browser-read-only',
    undefined,
  ],
  [
    'browser-open-target-url-is-navigation',
    { action: 'open', targetUrl: 'https://github.com/peg/rampart' },
    'openclaw:browser-navigation',
    'github.com',
  ],
  [
    'browser-click-is-mutation-even-on-safe-domain',
    { action: 'act', request: { kind: 'click', ref: 'button-1' }, targetUrl: 'https://github.com/peg/rampart' },
    'openclaw:browser-mutation',
    'github.com',
  ],
]) {
  await runPolicyScenario({
    name,
    event: { toolName: 'browser', params },
    expectedTool: 'browser',
    assertResult: (_result, body) => {
      assert(
        body.params.rampart_consequence === expectedConsequence,
        `expected ${expectedConsequence}, got ${JSON.stringify(body.params)}`,
      );
      if (expectedDomain !== undefined) {
        assert(body.params.domain === expectedDomain, `expected domain ${expectedDomain}, got ${JSON.stringify(body.params)}`);
      }
      assert(
        !Object.prototype.hasOwnProperty.call(params, 'rampart_consequence'),
        'host-derived policy fields must not mutate executable browser params',
      );
    },
  });
  scenarios.push(name);
}

for (const [name, toolName, params, expectedTool, expectedConsequence] of [
  ["grep-is-a-file-read", "grep", { path: "/tmp", pattern: "needle" }, "read", undefined],
  ["process-poll-is-read-only", "process", { action: "poll", sessionId: "job-1" }, "process", "openclaw:control-read-only"],
  ["gateway-config-change-is-mutation", "gateway", { action: "config.patch" }, "gateway", "openclaw:control-mutation"],
  ["session-history-is-sensitive", "sessions_history", { sessionKey: "agent:main:main" }, "sessions_history", "openclaw:control-sensitive-read-or-mutation"],
  ["session-status-model-change-is-mutation", "session_status", { model: "provider/model" }, "session_status", "openclaw:control-mutation"],
]) {
  await runPolicyScenario({
    name,
    event: { toolName, params },
    expectedTool,
    assertResult: (_result, body) => {
      if (expectedConsequence !== undefined) {
        assert(
          body.params.rampart_consequence === expectedConsequence,
          `expected ${expectedConsequence}, got ${JSON.stringify(body.params)}`,
        );
      }
    },
  });
  scenarios.push(name);
}

await runPolicyScenario({
  name: "sessions-send-uses-message-approval-surface",
  event: { toolName: "sessions_send", params: { sessionKey: "agent:other:main", message: "hello" } },
  expectedTool: "message",
  assertResult: (_result, body) => {
    assert(body.params.action === "send", `expected send action, got ${JSON.stringify(body.params)}`);
    assert(body.params.target === "agent:other:main", `expected session target, got ${JSON.stringify(body.params)}`);
    assert(body.params.rampart_consequence === "openclaw:external-message", `unexpected consequence: ${JSON.stringify(body.params)}`);
  },
});
scenarios.push("sessions-send-uses-message-approval-surface");

const ask = await runPolicyScenario({
  name: 'write-tool-hosted-approval',
  event: { toolName: 'write', params: { path: '/tmp/provider-fixture.txt', content: 'fixture' } },
  expectedTool: 'write',
  response: { decision: 'ask', allowed: false, policy: 'provider-fixture', message: 'write requires approval', severity: 'warning' },
  assertResult: (result) => {
    assert(result?.requireApproval, 'expected requireApproval for ask decision');
    assert(result.requireApproval.title.includes('write approval required'), `unexpected approval title: ${result.requireApproval.title}`);
    assert(result.requireApproval.description.includes('/tmp/provider-fixture.txt'), 'approval description should include path');
  },
});
assert(ask.result.requireApproval.timeoutBehavior === 'deny', 'approval should deny on timeout');
scenarios.push('write-tool-hosted-approval');

const authError = await withPlugin({
  name: 'auth-error-fail-closed',
  fetchImpl: async () => ({ ok: false, status: 401, text: async () => '{"error":"invalid token"}' }),
  invoke: async ({ handlers }) => {
    const before = handlers.before_tool_call;
    assert(typeof before === 'function', 'before_tool_call handler missing');
    return await before({ toolName: 'exec', params: { command: 'sudo id' } }, ctx);
  },
});
assert(authError?.block === true, '401 auth error should block sensitive tool calls');
assert(authError.blockReason.includes('HTTP 401'), `auth block reason should mention HTTP 401: ${authError.blockReason}`);
scenarios.push('auth-error-fail-closed');

const liveVerification = await withPlugin({
  name: 'live-behavioral-verification',
  fetchImpl: async (url, opts = {}) => {
    assert(String(url).includes('/v1/preflight/'), `unexpected verification URL: ${url}`);
    const body = parseBody({ opts });
    const tool = decodeURIComponent(String(url).split('/v1/preflight/')[1]);
    let decision = 'allow';
    if (tool === 'exec' && body.params.command === 'rm -rf /') decision = 'deny';
    if (tool === 'exec' && body.params.command?.startsWith('git push ')) decision = 'ask';
    if (tool === 'message' && body.params.rampart_consequence === 'openclaw:external-message') decision = 'ask';
    if (tool === 'exec' && body.params.command?.startsWith('cat ~/.ssh/id_')) decision = 'deny';
    if (tool === 'exec' && body.params.command?.startsWith('python3 -c ')) decision = 'ask';
    assert(body.verification === true, 'verification calls must request side-effect-free preflight mode');
    return fetchJson({ decision, allowed: decision === 'allow' });
  },
  invoke: async ({ gatewayMethods }) => {
    const verify = gatewayMethods['rampart.verify'];
    assert(typeof verify === 'function', 'rampart.verify gateway method missing');
    let response;
    await verify({ respond: (ok, payload) => { response = { ok, payload }; } });
    return response;
  },
});
assert(liveVerification?.ok === true, 'gateway verification RPC should respond successfully');
assert(liveVerification.payload?.schema === 'rampart.plugin.verify.v1', 'verification schema missing');
assert(liveVerification.payload?.safeCanaries === true, 'verification must identify safe canaries');
assert(liveVerification.payload?.ok === true, `verification failed: ${JSON.stringify(liveVerification.payload)}`);
assert(liveVerification.payload?.checks?.length === 6, 'expected six plugin policy canaries');
scenarios.push('live-behavioral-verification');

const degraded = await withPlugin({
  name: 'degraded-sensitive-exec-blocks',
  fetchImpl: async () => { throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } }); },
  invoke: async ({ handlers }) => handlers.before_tool_call(
    { toolName: 'exec', params: { command: 'sudo true' } },
    ctx,
  ),
});
assert(degraded?.block === true, 'degraded exec should fail closed');
assert(degraded.blockReason.includes('policy service down'), `unexpected degraded block reason: ${degraded.blockReason}`);
scenarios.push('degraded-sensitive-exec-blocks');

console.log(JSON.stringify({ ok: true, scenarios }, null, 2));
