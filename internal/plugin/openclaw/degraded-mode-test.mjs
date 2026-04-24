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
  name: 'unreachable-read',
  toolName: 'read',
  fetchImpl: async () => { throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } }); },
});
assert(unreachableRead.result === undefined, 'unreachable read should use configured fail-open default');

const serverErrorWrite = await runScenario({
  name: 'server-error-write',
  toolName: 'write',
  fetchImpl: async () => ({ ok: false, status: 503, text: async () => 'unavailable' }),
});
assert(serverErrorWrite.result?.block === true, 'write on serve 5xx must block');
assert(serverErrorWrite.result.blockReason.includes('service error 503'), 'write 5xx reason should include status');

const serverErrorReadWithStrictConfig = await runScenario({
  name: 'server-error-read-strict',
  toolName: 'read',
  pluginConfig: { failOpenTools: [] },
  fetchImpl: async () => ({ ok: false, status: 503, text: async () => 'unavailable' }),
});
assert(serverErrorReadWithStrictConfig.result?.block === true, 'read should block when failOpenTools is empty');

console.log(JSON.stringify({ ok: true, scenarios: ['unreachable-exec', 'unreachable-read', 'server-error-write', 'server-error-read-strict'] }, null, 2));
