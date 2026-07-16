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

async function waitFor(predicate, message, { timeoutMs = 250, intervalMs = 5 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(message);
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

async function runPolicyScenario({ name, event, expectedTool, expectedCommand, response = { decision: 'allow' }, assertResult, context = ctx }) {
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

const ask = await runPolicyScenario({
  name: 'write-tool-hosted-approval',
  event: { toolName: 'write', params: { path: '/tmp/provider-fixture.txt', content: 'fixture' } },
  expectedTool: 'write',
  response: { decision: 'ask', policy: 'provider-fixture', message: 'write requires approval', severity: 'warning' },
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

const auditCalls = [];
await withPlugin({
  name: 'after-tool-audit-canonical-exec',
  fetchImpl: async (url, opts = {}) => {
    auditCalls.push({ url: String(url), opts });
    return fetchJson({ ok: true });
  },
  invoke: async ({ handlers }) => {
    const after = handlers.after_tool_call;
    assert(typeof after === 'function', 'after_tool_call handler missing');
    await after({ toolName: 'terminal', params: { args: { command: 'echo audited-provider' } }, durationMs: 5 }, ctx);
    await waitFor(
      () => auditCalls.some((call) => call.url.includes('/v1/audit')),
      'audit endpoint not called',
    );
  },
});
const auditCall = auditCalls.find((call) => call.url.includes('/v1/audit'));
assert(auditCall, 'audit endpoint not called');
const auditBody = parseBody(auditCall);
assert(auditBody.tool === 'exec', `expected canonical audit tool exec, got ${auditBody.tool}`);
assert(auditBody.params.command === 'echo audited-provider', `expected normalized audit command, got ${JSON.stringify(auditBody.params)}`);
scenarios.push('after-tool-audit-canonical-exec');

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
