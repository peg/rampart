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

async function runScenario({ name, toolName, fetchImpl, pluginConfig }) {
  const { api, handlers, logs } = createApi(pluginConfig);
  const originalFetch = global.fetch;
  global.fetch = fetchImpl;
  try {
    plugin.register(api);
    const before = handlers['before_tool_call'];
    assert(typeof before === 'function', `${name}: before_tool_call handler missing`);
    const result = await before({ toolName, params: { command: 'echo hi' } }, {
      agentId: 'main',
      sessionKey: 'agent:main:test',
      runId: `${name}-run`,
    });
    return { result, logs };
  } finally {
    global.fetch = originalFetch;
  }
}

const unreachableExec = await runScenario({
  name: 'unreachable-exec',
  toolName: 'exec',
  fetchImpl: async () => { throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } }); },
});
assert(unreachableExec.result?.block === true, 'unreachable exec must block');
assert(unreachableExec.result.blockReason.includes('policy service down'), 'unreachable exec reason should mention service down');

const unreachableRead = await runScenario({
  name: 'unreachable-read-explicit-fail-open',
  toolName: 'read',
  pluginConfig: { failOpenTools: ['read'] },
  fetchImpl: async () => { throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } }); },
});
assert(unreachableRead.result === undefined, 'unreachable read should use an explicit fail-open override');

const unreachableReadDefault = await runScenario({
  name: 'unreachable-read-default-closed',
  toolName: 'read',
  fetchImpl: async () => { throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } }); },
});
assert(unreachableReadDefault.result?.block === true, 'unreachable read must fail closed by default');

const serverErrorWrite = await runScenario({
  name: 'server-error-write',
  toolName: 'write',
  fetchImpl: async () => ({ ok: false, status: 503, text: async () => 'unavailable' }),
});
assert(serverErrorWrite.result?.block === true, 'write on serve 5xx must block');
assert(serverErrorWrite.result.blockReason.includes('service error 503'), 'write 5xx reason should include status');

const timeoutEdit = await runScenario({
  name: 'timeout-edit',
  toolName: 'edit',
  fetchImpl: async () => {
    const err = new Error('aborted');
    err.name = 'AbortError';
    throw err;
  },
});
assert(timeoutEdit.result?.block === true, 'edit on timeout must block');
assert(timeoutEdit.result.blockReason.includes('timed out'), 'edit timeout reason should mention timeout');

const serverErrorReadWithStrictConfig = await runScenario({
  name: 'server-error-read-strict',
  toolName: 'read',
  pluginConfig: { failOpenTools: [] },
  fetchImpl: async () => ({ ok: false, status: 503, text: async () => 'unavailable' }),
});
assert(serverErrorReadWithStrictConfig.result?.block === true, 'read should block when failOpenTools is empty');

const clientErrorRead = await runScenario({
  name: 'client-error-read-explicit-fail-open',
  toolName: 'read',
  pluginConfig: { failOpenTools: ['read'] },
  fetchImpl: async () => ({ ok: false, status: 400 }),
});
assert(clientErrorRead.result?.block === true, 'client errors must never become configured fail-open');

const manualRedirectRead = await runScenario({
  name: 'manual-redirect-read-explicit-fail-open',
  toolName: 'read',
  pluginConfig: { failOpenTools: ['read'] },
  fetchImpl: async () => ({ ok: false, status: 307 }),
});
assert(manualRedirectRead.result?.block === true, 'redirect responses must never become configured fail-open');

for (const [name, payload] of [
  ['empty-object-response', {}],
  ['array-response', []],
  ['missing-allowed-response', { decision: 'allow' }],
  ['contradictory-allow-response', { decision: 'allow', allowed: false }],
  ['contradictory-deny-response', { decision: 'deny', allowed: true }],
  ['unknown-decision', { decision: 'maybe', allowed: true }],
]) {
  const scenario = await runScenario({
    name,
    toolName: 'exec',
    pluginConfig: { failOpen: false },
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => payload }),
  });
  assert(scenario.result?.block === true, `${name} must fail closed`);
}

const redirectRead = await runScenario({
  name: 'redirect-read-explicit-fail-open',
  toolName: 'read',
  pluginConfig: { failOpenTools: ['read'] },
  fetchImpl: async () => {
    throw new TypeError('fetch failed', { cause: new Error('unexpected redirect') });
  },
});
assert(redirectRead.result?.block === true, 'redirect refusal must not become configured fail-open');

const oversizedResponse = await runScenario({
  name: 'oversized-response',
  toolName: 'read',
  pluginConfig: { failOpenTools: ['read'] },
  fetchImpl: async () => new Response('x'.repeat(1024 * 1024 + 1), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  }),
});
assert(oversizedResponse.result?.block === true, 'oversized response must fail closed');

const slowBody = await runScenario({
  name: 'slow-response-body',
  toolName: 'exec',
  pluginConfig: { timeoutMs: 5 },
  fetchImpl: async (_url, opts) => new Response(new ReadableStream({
    start(controller) {
      const delayed = setTimeout(() => {
        controller.enqueue(new TextEncoder().encode('{"decision":"allow","allowed":true}'));
        controller.close();
      }, 50);
      opts.signal.addEventListener('abort', () => {
        clearTimeout(delayed);
        const error = new Error('response body aborted');
        error.name = 'AbortError';
        controller.error(error);
      }, { once: true });
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
});
assert(slowBody.result?.block === true, 'timeout must cover the complete response body');

const untrustedServeUrl = await runScenario({
  name: 'untrusted-serve-url',
  toolName: 'exec',
  pluginConfig: { serveUrl: 'https://example.invalid', failOpen: false },
  fetchImpl: async () => { throw new Error('untrusted URL must not be fetched'); },
});
assert(untrustedServeUrl.result?.block === true, 'untrusted serveUrl must fail closed');

for (const serveUrl of [
  'http://user:password@localhost:9090',
  'http://localhost:9090?redirect=https://example.invalid',
  'http://localhost:9090/control',
]) {
  const scenario = await runScenario({
    name: `unsafe-local-url-${serveUrl}`,
    toolName: 'exec',
    pluginConfig: { serveUrl, failOpen: false },
    fetchImpl: async () => { throw new Error('unsafe URL must not be fetched'); },
  });
  assert(scenario.result?.block === true, `${serveUrl} must fail closed`);
  assert(!JSON.stringify(scenario.logs).includes('password'), 'unsafe serveUrl credentials must not reach logs');
}

console.log(JSON.stringify({ ok: true, scenarios: ['unreachable-exec', 'unreachable-read-explicit-fail-open', 'unreachable-read-default-closed', 'server-error-write', 'timeout-edit', 'server-error-read-strict', 'client-error-read-explicit-fail-open', 'manual-redirect-read-explicit-fail-open', 'empty-object-response', 'array-response', 'missing-allowed-response', 'contradictory-allow-response', 'contradictory-deny-response', 'unknown-decision', 'redirect-read-explicit-fail-open', 'oversized-response', 'slow-response-body', 'untrusted-serve-url'] }, null, 2));
