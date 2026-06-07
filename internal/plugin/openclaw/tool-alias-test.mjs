import plugin from './index.js';

function createApi(pluginConfig = {}) {
  const handlers = {};
  const logs = [];
  return {
    handlers,
    logs,
    api: {
      pluginConfig,
      logger: {
        info: (...a) => logs.push(['info', a.join(' ')]),
        warn: (...a) => logs.push(['warn', a.join(' ')]),
        debug: (...a) => logs.push(['debug', a.join(' ')]),
      },
      on: (name, fn) => { handlers[name] = fn; },
      registerGatewayMethod: () => {},
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

async function runWithFetch({ name, fetchImpl, pluginConfig = {}, invoke }) {
  const { api, handlers, logs } = createApi(pluginConfig);
  const originalFetch = global.fetch;
  global.fetch = fetchImpl;
  try {
    plugin.register(api);
    return await invoke({ handlers, logs });
  } catch (err) {
    err.message = `${name}: ${err.message}`;
    throw err;
  } finally {
    global.fetch = originalFetch;
  }
}

const calls = [];
const allowResult = await runWithFetch({
  name: 'bash-allow-maps-to-exec',
  fetchImpl: async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    assert(String(url).includes('/v1/tool/exec'), `expected exec endpoint, got ${url}`);
    return { ok: true, json: async () => ({ decision: 'allow' }) };
  },
  invoke: async ({ handlers, logs }) => {
    const before = handlers.before_tool_call;
    assert(typeof before === 'function', 'before_tool_call handler missing');
    const result = await before({ toolName: 'bash', params: { cmd: 'echo hi' } }, {
      agentId: 'main',
      sessionKey: 'agent:main:test',
      runId: 'bash-allow-run',
    });
    assert(logs.some((entry) => entry.join(' ').includes('mapped OpenClaw tool bash to Rampart exec')), 'mapping log missing');
    return result;
  },
});
assert(allowResult === undefined, 'allow decision should pass through');
assert(calls.length === 1, `expected one policy call, got ${calls.length}`);
const allowBody = parseBody(calls[0]);
assert(allowBody.params.command === 'echo hi', `expected cmd promoted to command, got ${JSON.stringify(allowBody.params)}`);
assert(allowBody.openclaw_hosted === true, 'expected openclaw_hosted=true');
assert(allowBody.skip_pending_approval === true, 'expected skip_pending_approval=true');

const learnCalls = [];
const askResult = await runWithFetch({
  name: 'bash-ask-learns-canonical-exec',
  fetchImpl: async (url, opts = {}) => {
    learnCalls.push({ url: String(url), opts });
    if (String(url).includes('/v1/tool/exec')) {
      return { ok: true, json: async () => ({ decision: 'ask', policy: 'test-policy', message: 'needs approval' }) };
    }
    if (String(url).includes('/v1/rules/learn')) {
      return { ok: true, status: 200, text: async () => '{"ok":true}' };
    }
    throw new Error(`unexpected fetch ${url}`);
  },
  invoke: async ({ handlers }) => {
    const before = handlers.before_tool_call;
    const result = await before({ toolName: 'bash', params: { script: 'sudo true' } }, {
      agentId: 'main',
      sessionKey: 'agent:main:test',
      runId: 'bash-ask-run',
    });
    assert(result?.requireApproval, 'expected requireApproval for ask');
    assert(result.requireApproval.title.includes('bash→exec approval required'), `unexpected title: ${result.requireApproval.title}`);
    await result.requireApproval.onResolution('allow-always');
    return result;
  },
});
assert(askResult.requireApproval.description.includes('sudo true'), 'approval description should include normalized command');
const learnCall = learnCalls.find((call) => call.url.includes('/v1/rules/learn'));
assert(learnCall, 'learn endpoint not called');
const learnBody = parseBody(learnCall);
assert(learnBody.tool === 'exec', `learn tool = ${learnBody.tool}, want exec`);
assert(learnBody.args === 'sudo true', `learn args = ${learnBody.args}, want sudo true`);

const unreachableResult = await runWithFetch({
  name: 'bash-unreachable-blocks-as-exec',
  fetchImpl: async () => { throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } }); },
  invoke: async ({ handlers }) => handlers.before_tool_call(
    { toolName: 'bash', params: { command: 'echo hi' } },
    { agentId: 'main', sessionKey: 'agent:main:test', runId: 'bash-unreachable-run' },
  ),
});
assert(unreachableResult?.block === true, 'bash/exec alias should fail closed when Rampart is unreachable');
assert(unreachableResult.blockReason.includes('bash→exec'), `block reason should show alias mapping: ${unreachableResult.blockReason}`);

const auditCalls = [];
await runWithFetch({
  name: 'bash-after-audit-canonical-exec',
  fetchImpl: async (url, opts = {}) => {
    auditCalls.push({ url: String(url), opts });
    return { ok: true, status: 200, json: async () => ({ ok: true }) };
  },
  invoke: async ({ handlers }) => {
    const after = handlers.after_tool_call;
    assert(typeof after === 'function', 'after_tool_call handler missing');
    await after({ toolName: 'bash', params: { command: 'echo hi' }, durationMs: 7 }, {
      agentId: 'main',
      sessionKey: 'agent:main:test',
      runId: 'bash-after-run',
    });
    await waitFor(
      () => auditCalls.some((call) => call.url.includes('/v1/audit')),
      'audit endpoint not called',
    );
  },
});
const auditCall = auditCalls.find((call) => call.url.includes('/v1/audit'));
assert(auditCall, 'audit endpoint not called');
const auditBody = parseBody(auditCall);
assert(auditBody.tool === 'exec', `audit tool = ${auditBody.tool}, want exec`);
assert(auditBody.params.command === 'echo hi', `audit command missing: ${JSON.stringify(auditBody.params)}`);

console.log(JSON.stringify({
  ok: true,
  scenarios: [
    'bash-allow-maps-to-exec',
    'bash-ask-learns-canonical-exec',
    'bash-unreachable-blocks-as-exec',
    'bash-after-audit-canonical-exec',
  ],
}, null, 2));
